//! Tauri side of RemoteControl. The contract with the web UI is `app/src/ipc.ts`.

mod logging;
mod secrets;
mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use rc_types::{
    session_channels, CursorShape, ErrorKind, SessionError, SessionEvent, SessionHandle, SessionInput, SessionIo,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{Manager as _, State};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::store::{Connection, Protocol, Store};

/// Stop adding frames to one window message beyond this many bytes.
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

struct AppState {
    store: Mutex<Store>,
    sessions: Mutex<HashMap<String, mpsc::UnboundedSender<SessionInput>>>,
    log_path: PathBuf,
}

/// Error shape the UI expects: `{ kind, detail }`.
#[derive(Debug, Clone, Serialize)]
struct UiError {
    kind: &'static str,
    detail: String,
}

impl UiError {
    fn other(detail: impl Into<String>) -> Self {
        Self {
            kind: "other",
            detail: detail.into(),
        }
    }
}

fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Unreachable => "unreachable",
        ErrorKind::AuthFailed => "auth_failed",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Security => "security",
        ErrorKind::Protocol => "protocol",
        ErrorKind::Disconnected => "disconnected",
        ErrorKind::Other => "other",
    }
}

impl From<&SessionError> for UiError {
    fn from(error: &SessionError) -> Self {
        Self {
            kind: kind_name(error.kind),
            detail: error.detail.clone(),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── Connections ──────────────────────────────────────────────────────────────

#[tauri::command]
fn list_connections(state: State<'_, AppState>) -> Vec<Connection> {
    lock(&state.store).list()
}

#[tauri::command]
fn save_connection(state: State<'_, AppState>, mut connection: Connection) -> Result<Connection, UiError> {
    connection.name = connection.name.trim().to_owned();
    connection.host = connection.host.trim().to_owned();
    connection.username = connection.username.trim().to_owned();
    connection.domain = connection.domain.trim().to_owned();
    if connection.host.is_empty() {
        return Err(UiError::other("A host name or IP address is required."));
    }
    if connection.name.is_empty() {
        connection.name = connection.host.clone();
    }
    let mut store = lock(&state.store);
    if connection.id.is_empty() {
        connection.id = uuid::Uuid::new_v4().to_string();
        connection.pinned_identity = None;
    } else if let Some(existing) = store.get(&connection.id) {
        // The pin belongs to a machine: keep it only while the address is unchanged.
        let same_machine = existing.host.eq_ignore_ascii_case(&connection.host)
            && existing.protocol == connection.protocol
            && existing.ssh_tunnel == connection.ssh_tunnel;
        connection.pinned_identity = if same_machine { existing.pinned_identity } else { None };
    }
    store.upsert(connection.clone()).map_err(UiError::other)?;
    Ok(connection)
}

#[tauri::command]
fn delete_connection(state: State<'_, AppState>, id: String) -> Result<(), UiError> {
    secrets::delete(&id);
    lock(&state.store).remove(&id).map_err(UiError::other)
}

#[tauri::command]
fn has_saved_password(id: String) -> bool {
    secrets::get(&id).is_some()
}

#[tauri::command]
fn forget_password(id: String) {
    secrets::delete(&id);
}

// ── Sessions ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ConnectArgs {
    id: String,
    password: Option<String>,
    save_password: bool,
    width: u16,
    height: u16,
    scale_factor: u32,
    trust_new_identity: bool,
}

#[tauri::command]
fn connect(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    args: ConnectArgs,
    events: Channel<InvokeResponseBody>,
) -> Result<String, UiError> {
    let connection = lock(&state.store)
        .get(&args.id)
        .ok_or_else(|| UiError::other("This connection no longer exists."))?;

    let typed_password = args.password.filter(|p| !p.is_empty());
    let password = match typed_password.clone().or_else(|| secrets::get(&connection.id)) {
        Some(password) => password,
        None => {
            return Err(UiError {
                kind: "password_required",
                detail: "No password is saved for this connection.".to_owned(),
            })
        }
    };
    let pinned = if args.trust_new_identity {
        None
    } else {
        connection.pinned_identity.clone()
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    info!(
        session = %session_id,
        name = %connection.name,
        protocol = ?connection.protocol,
        host = %connection.host,
        port = connection.port,
        tunnel = connection.ssh_tunnel,
        pinned = pinned.is_some(),
        "connect requested"
    );

    let (io, handle) = session_channels();
    lock(&state.sessions).insert(session_id.clone(), handle.input.clone());

    match connection.protocol {
        Protocol::Rdp => {
            let config = rc_rdp::RdpConfig {
                host: connection.host.clone(),
                port: connection.port,
                username: connection.username.clone(),
                password: password.clone(),
                domain: Some(connection.domain.clone()).filter(|d| !d.is_empty()),
                width: args.width.clamp(640, 8192),
                height: args.height.clamp(480, 8192),
                scale_factor: args.scale_factor.clamp(100, 500),
                pinned_cert_sha256: pinned,
                nla: connection.nla,
                clipboard: true,
            };
            if let Err(e) = rc_rdp::spawn(config, io) {
                lock(&state.sessions).remove(&session_id);
                return Err(UiError::other(format!("cannot start the session thread: {e}")));
            }
        }
        Protocol::Vnc => {
            tauri::async_runtime::spawn(run_vnc(connection.clone(), password.clone(), pinned, io));
        }
    }

    let pump = Pump {
        app,
        session_id: session_id.clone(),
        connection_id: connection.id.clone(),
        // Only a password the user just typed needs saving, and only once it has worked.
        password_to_save: typed_password.filter(|_| args.save_password),
        channel: events,
    };
    tauri::async_runtime::spawn(pump.run(handle));

    Ok(session_id)
}

/// VNC, through an SSH tunnel to the Mac unless the connection opts out.
async fn run_vnc(connection: Connection, password: String, pinned: Option<String>, io: SessionIo) {
    let config = rc_vnc::VncConfig {
        username: Some(connection.username.clone()).filter(|u| !u.is_empty()),
        password: Some(password.clone()),
        shared: true,
        view_only: false,
    };
    if !connection.ssh_tunnel {
        warn!("VNC without an SSH tunnel: the session is not encrypted");
        rc_vnc::connect_and_run(&connection.host, connection.port, config, io).await;
        return;
    }

    let _ = io
        .events
        .send(SessionEvent::Status(format!(
            "Opening a secure tunnel to {}",
            connection.host
        )))
        .await;
    let tunnel = rc_tunnel::open(rc_tunnel::TunnelConfig {
        ssh_host: connection.host.clone(),
        ssh_port: connection.ssh_port,
        username: connection.username.clone(),
        password,
        target_host: "127.0.0.1".to_owned(),
        target_port: connection.port,
        pinned_host_key_sha256: pinned,
    })
    .await;
    match tunnel {
        Ok(tunnel) => {
            let _ = io
                .events
                .send(SessionEvent::ServerIdentity {
                    sha256: tunnel.host_key_sha256.clone(),
                })
                .await;
            let guard = tunnel.guard;
            rc_vnc::run(tunnel.stream, config, io).await;
            guard.close().await;
        }
        Err(error) => {
            warn!(kind = ?error.kind, detail = %error.detail, "SSH tunnel failed");
            let _ = io.events.send(SessionEvent::Closed { error: Some(error) }).await;
        }
    }
}

/// Forwards one session's events to its window channel.
struct Pump {
    app: tauri::AppHandle,
    session_id: String,
    connection_id: String,
    password_to_save: Option<String>,
    channel: Channel<InvokeResponseBody>,
}

impl Pump {
    async fn run(mut self, mut handle: SessionHandle) {
        let mut pending: Option<SessionEvent> = None;
        loop {
            let event = match pending.take() {
                Some(event) => event,
                None => match handle.events.recv().await {
                    Some(event) => event,
                    None => SessionEvent::Closed {
                        error: Some(SessionError::new(ErrorKind::Other, "the session ended unexpectedly")),
                    },
                },
            };

            let sent = match event {
                SessionEvent::Frame { x, y, w, h, rgba } => {
                    // Pack every frame that is already waiting into one message: a burst of small
                    // rectangles costs one trip to the window instead of dozens.
                    let mut batch = Vec::with_capacity(8 + rgba.len());
                    push_frame(&mut batch, x, y, w, h, &rgba);
                    while batch.len() < MAX_BATCH_BYTES {
                        match handle.events.try_recv() {
                            Ok(SessionEvent::Frame { x, y, w, h, rgba }) => push_frame(&mut batch, x, y, w, h, &rgba),
                            Ok(other) => {
                                pending = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    self.channel.send(InvokeResponseBody::Raw(batch)).is_ok()
                }
                SessionEvent::Closed { error } => {
                    info!(session = %self.session_id, error = ?error, "session closed");
                    let error = error.as_ref().map(UiError::from);
                    let _ = self.send_json(serde_json::json!({ "type": "closed", "error": error }));
                    break;
                }
                other => {
                    self.side_effects(&other);
                    match to_json(other) {
                        Some(json) => self.send_json(json),
                        None => true,
                    }
                }
            };

            if !sent {
                // The window or tab went away: end the remote session too.
                info!(session = %self.session_id, "window channel closed; ending session");
                let _ = handle.input.send(SessionInput::Close);
                break;
            }
        }
        let state = self.app.state::<AppState>();
        lock(&state.sessions).remove(&self.session_id);
    }

    fn send_json(&self, value: serde_json::Value) -> bool {
        self.channel.send(InvokeResponseBody::Json(value.to_string())).is_ok()
    }

    /// Things the app itself does on an event, besides forwarding it.
    fn side_effects(&mut self, event: &SessionEvent) {
        match event {
            SessionEvent::ServerIdentity { sha256 } => {
                // Trust on first use: remember who answered so a different machine is noticed later.
                let state = self.app.state::<AppState>();
                let saved = lock(&state.store).set_pin(&self.connection_id, Some(sha256.clone()));
                if let Err(e) = saved {
                    error!(error = %e, "cannot save the server identity");
                }
            }
            SessionEvent::Connected { .. } => {
                if let Some(password) = self.password_to_save.take() {
                    if let Err(e) = secrets::set(&self.connection_id, &password) {
                        warn!(error = %e, "password not saved");
                    }
                }
            }
            _ => {}
        }
    }
}

fn push_frame(batch: &mut Vec<u8>, x: u16, y: u16, w: u16, h: u16, rgba: &[u8]) {
    batch.extend_from_slice(&x.to_le_bytes());
    batch.extend_from_slice(&y.to_le_bytes());
    batch.extend_from_slice(&w.to_le_bytes());
    batch.extend_from_slice(&h.to_le_bytes());
    batch.extend_from_slice(rgba);
}

fn to_json(event: SessionEvent) -> Option<serde_json::Value> {
    use serde_json::json;
    Some(match event {
        SessionEvent::Status(text) => json!({ "type": "status", "text": text }),
        SessionEvent::ServerIdentity { sha256 } => json!({ "type": "identity", "sha256": sha256 }),
        SessionEvent::Connected { width, height, name } => {
            json!({ "type": "connected", "width": width, "height": height, "name": name })
        }
        SessionEvent::Resized { width, height } => json!({ "type": "resized", "width": width, "height": height }),
        SessionEvent::Cursor(CursorShape::Default) => json!({ "type": "cursor", "kind": "default" }),
        SessionEvent::Cursor(CursorShape::Hidden) => json!({ "type": "cursor", "kind": "hidden" }),
        SessionEvent::Cursor(CursorShape::Bitmap {
            width,
            height,
            hot_x,
            hot_y,
            rgba,
        }) => json!({
            "type": "cursor", "kind": "bitmap", "width": width, "height": height,
            "hot_x": hot_x, "hot_y": hot_y,
            "rgba_base64": base64::engine::general_purpose::STANDARD.encode(rgba),
        }),
        SessionEvent::Clipboard(text) => json!({ "type": "clipboard", "text": text }),
        SessionEvent::Bell => json!({ "type": "bell" }),
        SessionEvent::Frame { .. } | SessionEvent::Closed { .. } => return None,
    })
}

#[tauri::command]
fn send_input(state: State<'_, AppState>, session_id: String, input: SessionInput) {
    if let Some(sender) = lock(&state.sessions).get(&session_id) {
        let _ = sender.send(input);
    }
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>, session_id: String) {
    if let Some(sender) = lock(&state.sessions).get(&session_id) {
        let _ = sender.send(SessionInput::Close);
    }
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AppInfo {
    version: String,
    os: &'static str,
    arch: &'static str,
    log_path: String,
}

#[tauri::command]
fn app_info(app: tauri::AppHandle, state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: app.package_info().version.to_string(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        log_path: state.log_path.display().to_string(),
    }
}

#[tauri::command]
fn log_text(state: State<'_, AppState>) -> String {
    logging::tail(&state.log_path)
}

#[tauri::command]
fn reveal_log(state: State<'_, AppState>) -> Result<(), UiError> {
    tauri_plugin_opener::reveal_item_in_dir(&state.log_path).map_err(|e| UiError::other(e.to_string()))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let log_dir = app.path().app_log_dir()?;
            let log_path = logging::init(&log_dir);
            info!(
                version = %app.package_info().version,
                os = std::env::consts::OS,
                arch = std::env::consts::ARCH,
                "RemoteControl starting"
            );
            let config_dir = app.path().app_config_dir()?;
            app.manage(AppState {
                store: Mutex::new(Store::load(config_dir.join("connections.json"))),
                sessions: Mutex::new(HashMap::new()),
                log_path,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_connections,
            save_connection,
            delete_connection,
            has_saved_password,
            forget_password,
            connect,
            send_input,
            disconnect,
            app_info,
            log_text,
            reveal_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running RemoteControl");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_packed_as_the_ui_expects() {
        let mut batch = Vec::new();
        push_frame(&mut batch, 1, 2, 2, 1, &[10, 20, 30, 255, 40, 50, 60, 255]);
        push_frame(&mut batch, 300, 0, 1, 1, &[1, 2, 3, 255]);
        // Header: x, y, w, h as little-endian u16, then RGBA; frames back to back.
        assert_eq!(&batch[..8], &[1, 0, 2, 0, 2, 0, 1, 0]);
        assert_eq!(&batch[8..16], &[10, 20, 30, 255, 40, 50, 60, 255]);
        assert_eq!(&batch[16..24], &[44, 1, 0, 0, 1, 0, 1, 0]);
        assert_eq!(batch.len(), 28);
    }

    #[test]
    fn events_use_the_ui_field_names() {
        let json = to_json(SessionEvent::Connected { width: 800, height: 600, name: "pc".into() }).unwrap();
        assert_eq!(json, serde_json::json!({ "type": "connected", "width": 800, "height": 600, "name": "pc" }));
        let json = to_json(SessionEvent::Cursor(CursorShape::Bitmap {
            width: 1, height: 1, hot_x: 0, hot_y: 0, rgba: vec![255, 0, 0, 255],
        }))
        .unwrap();
        assert_eq!(json["kind"], "bitmap");
        assert_eq!(json["rgba_base64"], "/wAA/w==");
        assert!(to_json(SessionEvent::Bell).is_some());
    }

    #[test]
    fn input_from_the_ui_deserializes() {
        let input: SessionInput =
            serde_json::from_str(r#"{"type":"pointer_button","button":"left","down":true,"x":5,"y":6}"#).unwrap();
        assert!(matches!(input, SessionInput::PointerButton { down: true, x: 5, y: 6, .. }));
        let input: SessionInput = serde_json::from_str(r#"{"type":"key","code":"KeyA","key":"a","down":false}"#).unwrap();
        assert!(matches!(input, SessionInput::Key { down: false, .. }));
        for unit in ["release_all", "refresh", "close"] {
            serde_json::from_str::<SessionInput>(&format!(r#"{{"type":"{unit}"}}"#)).unwrap();
        }
        serde_json::from_str::<SessionInput>(r#"{"type":"wheel","dx":0,"dy":-1.5,"x":1,"y":2}"#).unwrap();
        serde_json::from_str::<SessionInput>(r#"{"type":"resize","width":1280,"height":800}"#).unwrap();
        serde_json::from_str::<SessionInput>(r#"{"type":"clipboard","text":"hi"}"#).unwrap();
    }
}
