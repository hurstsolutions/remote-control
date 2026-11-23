//! Tauri side of RemoteControl. The contract with the web UI is `app/src/ipc.ts`.

mod discover;
mod logging;
mod private_fs;
mod secrets;
mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use rc_types::{
    session_channels, CursorShape, ErrorKind, IdentityMismatch, SessionError, SessionEvent, SessionHandle,
    SessionInput, SessionIo, MAX_CLIPBOARD_BYTES,
};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{Manager as _, State};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::store::{Connection, Protocol, Store};

/// Stop adding frames to one window message beyond this many bytes.
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

struct AppState {
    store: Mutex<Store>,
    sessions: Mutex<HashMap<String, LiveSession>>,
    subnets: Mutex<discover::SubnetStore>,
    scan: Mutex<Option<discover::RunningScan>>,
    log_path: PathBuf,
}

struct LiveSession {
    input: mpsc::UnboundedSender<SessionInput>,
    /// The connection's clipboard setting when the session started.
    share_clipboard: bool,
}

/// Error shape the UI expects: `{ kind, detail }`, plus `identity` for kind `identity_changed`.
#[derive(Debug, Clone, Serialize)]
struct UiError {
    kind: &'static str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityMismatch>,
}

impl UiError {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            identity: None,
        }
    }

    fn other(detail: impl Into<String>) -> Self {
        Self::new("other", detail)
    }
}

fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Unreachable => "unreachable",
        ErrorKind::TunnelUnavailable => "tunnel_unavailable",
        ErrorKind::AuthFailed => "auth_failed",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::Security => "security",
        ErrorKind::IdentityChanged => "identity_changed",
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
            identity: error.identity.clone(),
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

/// What `save_connection` hands back.
#[derive(Debug, Serialize)]
struct SavedConnection {
    connection: Connection,
    /// The saved password was removed because the address or the account changed.
    password_cleared: bool,
}

/// How saving `incoming` over `existing` (the stored connection with the same id, if any) treats
/// what belongs to the old target.
#[derive(Debug, PartialEq, Eq)]
struct SaveDecision {
    pinned_identity: Option<String>,
    /// Delete any keychain entry under this id before saving.
    clear_password: bool,
}

fn decide_save(existing: Option<&Connection>, incoming: &Connection) -> SaveDecision {
    match existing {
        // The pin belongs to a machine, the password to an account on it: neither follows the
        // connection somewhere else. The pin is never taken from the caller.
        Some(existing) => {
            let same_target = existing.same_target(incoming);
            SaveDecision {
                pinned_identity: if same_target { existing.pinned_identity.clone() } else { None },
                clear_password: !same_target || !existing.same_account(incoming),
            }
        }
        // A new id, or one we do not know: start clean, and make sure no stale password from an
        // earlier connection with that id is picked up.
        None => SaveDecision {
            pinned_identity: None,
            clear_password: !incoming.id.is_empty(),
        },
    }
}

#[tauri::command]
fn save_connection(state: State<'_, AppState>, mut connection: Connection) -> Result<SavedConnection, UiError> {
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
    let existing = store.get(&connection.id).filter(|_| !connection.id.is_empty());
    let decision = decide_save(existing.as_ref(), &connection);
    if connection.id.is_empty() {
        connection.id = uuid::Uuid::new_v4().to_string();
    }
    connection.pinned_identity = decision.pinned_identity;
    // Delete before saving, and refuse to save the new target while the old password is still
    // there: `connect` would otherwise send it to the new address.
    let deleted = decision.clear_password && secrets::delete(&connection.id);
    if decision.clear_password && secrets::get(&connection.id).is_some() {
        return Err(UiError::other(
            "The address or username changed, but the saved password could not be removed from the keychain. \
             Remove it with \"Forget saved password\" and try again.",
        ));
    }
    let password_cleared = deleted && existing.is_some();
    if password_cleared {
        info!(id = %connection.id, "saved password removed: the connection now points at another address or account");
    }
    store.upsert(connection.clone()).map_err(UiError::other)?;
    Ok(SavedConnection {
        connection,
        password_cleared,
    })
}

#[tauri::command]
fn delete_connection(state: State<'_, AppState>, id: String) -> Result<(), UiError> {
    let _ = secrets::delete(&id);
    lock(&state.store).remove(&id).map_err(UiError::other)
}

#[tauri::command]
fn has_saved_password(id: String) -> bool {
    secrets::get(&id).is_some()
}

#[tauri::command]
fn forget_password(id: String) {
    let _ = secrets::delete(&id);
}

// ── Sessions ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ConnectArgs {
    id: String,
    password: Option<String>,
    save_password: bool,
    width: u16,
    height: u16,
    scale_factor: u32,
    trust_new_identity: bool,
    /// With `trust_new_identity`: the fingerprint the user reviewed. Only that identity is
    /// accepted; `None` accepts whatever the server presents.
    #[serde(default)]
    new_identity: Option<String>,
}

impl std::fmt::Debug for ConnectArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectArgs")
            .field("id", &self.id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("save_password", &self.save_password)
            .field("size", &(self.width, self.height))
            .field("scale_factor", &self.scale_factor)
            .field("trust_new_identity", &self.trust_new_identity)
            .field("new_identity", &self.new_identity)
            .finish()
    }
}

/// The password to sign in with. Trusting a new identity always needs a typed password: the saved
/// one is never sent to a machine whose identity has just changed.
fn choose_password(
    typed: Option<String>,
    trust_new_identity: bool,
    saved: impl FnOnce() -> Option<String>,
) -> Result<String, UiError> {
    if let Some(password) = typed.filter(|p| !p.is_empty()) {
        return Ok(password);
    }
    if trust_new_identity {
        return Err(UiError::new(
            "password_required",
            "Enter the password to connect to a computer with a new identity. The saved password is not used.",
        ));
    }
    saved().ok_or_else(|| UiError::new("password_required", "No password is saved for this connection."))
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

    let typed_password = args.password.clone().filter(|p| !p.is_empty());
    let password = choose_password(typed_password.clone(), args.trust_new_identity, || {
        secrets::get(&connection.id)
    })?;
    let pinned = if args.trust_new_identity {
        args.new_identity.clone().map(|f| f.to_ascii_lowercase())
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
        trust_new_identity = args.trust_new_identity,
        clipboard = connection.share_clipboard,
        "connect requested"
    );

    let (io, handle) = session_channels();
    lock(&state.sessions).insert(
        session_id.clone(),
        LiveSession {
            input: handle.input.clone(),
            share_clipboard: connection.share_clipboard,
        },
    );

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
                clipboard: connection.share_clipboard,
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
        share_clipboard: connection.share_clipboard,
        trust_new_identity: args.trust_new_identity,
        target: connection,
        seen_identity: None,
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
    /// The connection as it was when the session started. Nothing learned in this session (the
    /// server identity, the password) is saved if the stored connection has since been pointed
    /// somewhere else.
    target: Connection,
    share_clipboard: bool,
    trust_new_identity: bool,
    /// The identity the server proved, kept until the sign-in succeeds.
    seen_identity: Option<String>,
    password_to_save: Option<String>,
    channel: Channel<InvokeResponseBody>,
}

/// The pin to store once the sign-in succeeded, if any. `current` is the stored connection now.
fn pin_after_sign_in(
    current: Option<&Connection>,
    target: &Connection,
    seen: Option<&str>,
    trust_new_identity: bool,
) -> Option<String> {
    let current = current?;
    let seen = seen?;
    if !current.same_target(target) {
        // Edited while signing in: this identity belongs to the old address.
        return None;
    }
    match current.pinned_identity.as_deref() {
        None => Some(seen.to_owned()),
        Some(pinned) if pinned.eq_ignore_ascii_case(seen) => None,
        // Only an explicit "trust new identity" replaces a pin.
        Some(_) if trust_new_identity => Some(seen.to_owned()),
        Some(_) => None,
    }
}

/// Whether a password typed for `target` may be saved under the stored connection `current`.
fn may_save_password(current: Option<&Connection>, target: &Connection) -> bool {
    current.is_some_and(|c| c.same_target(target) && c.same_account(target))
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
                SessionEvent::Clipboard(text) if !self.share_clipboard => {
                    debug!(bytes = text.len(), "clipboard sharing is off; remote clipboard ignored");
                    true
                }
                SessionEvent::Clipboard(text) if text.len() > MAX_CLIPBOARD_BYTES => {
                    warn!(bytes = text.len(), limit = MAX_CLIPBOARD_BYTES, "remote clipboard text too large; ignored");
                    true
                }
                other => {
                    let notice = self.side_effects(&other);
                    let forwarded = match to_json(other) {
                        Some(json) => self.send_json(json),
                        None => true,
                    };
                    match notice {
                        Some(text) => forwarded && self.send_json(serde_json::json!({ "type": "notice", "text": text })),
                        None => forwarded,
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

    /// Things the app itself does on an event, besides forwarding it. Returns a notice for the
    /// user, if there is something they should know.
    fn side_effects(&mut self, event: &SessionEvent) -> Option<String> {
        match event {
            SessionEvent::ServerIdentity { sha256 } => {
                // Remembered only once the sign-in works: a machine that cannot sign us in must
                // not become the trusted one.
                self.seen_identity = Some(sha256.clone());
                None
            }
            SessionEvent::Connected { .. } => self.signed_in(),
            _ => None,
        }
    }

    fn signed_in(&mut self) -> Option<String> {
        let state = self.app.state::<AppState>();
        let id = self.target.id.clone();
        let save_password = {
            let mut store = lock(&state.store);
            let current = store.get(&id);
            let pin = pin_after_sign_in(
                current.as_ref(),
                &self.target,
                self.seen_identity.as_deref(),
                self.trust_new_identity,
            );
            if let Some(pin) = pin {
                info!(session = %self.session_id, fingerprint = %pin, "server identity saved");
                if let Err(e) = store.set_pin(&id, Some(pin)) {
                    error!(error = %e, "cannot save the server identity");
                }
            } else if self.seen_identity.is_some() && !current.as_ref().is_some_and(|c| c.same_target(&self.target)) {
                warn!(session = %self.session_id, "connection was changed while signing in; server identity not saved");
            }
            may_save_password(current.as_ref(), &self.target)
        };
        let password = self.password_to_save.take()?;
        if !save_password {
            warn!(session = %self.session_id, "connection was changed while signing in; password not saved");
            return None;
        }
        match secrets::set(&id, &password) {
            Ok(()) => None,
            Err(e) => {
                warn!(error = %e, "password not saved");
                Some(format!(
                    "Signed in, but the password could not be saved in the keychain, so you will be asked for it next time. ({e})"
                ))
            }
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
    let sessions = lock(&state.sessions);
    let Some(session) = sessions.get(&session_id) else {
        return;
    };
    if let SessionInput::Clipboard { text } = &input {
        if !session.share_clipboard {
            debug!(bytes = text.len(), "clipboard sharing is off; local clipboard not sent");
            return;
        }
        if text.len() > MAX_CLIPBOARD_BYTES {
            warn!(bytes = text.len(), limit = MAX_CLIPBOARD_BYTES, "local clipboard text too large; not sent");
            return;
        }
    }
    let _ = session.input.send(input);
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>, session_id: String) {
    if let Some(session) = lock(&state.sessions).get(&session_id) {
        let _ = session.input.send(SessionInput::Close);
    }
}

// ── Find computers ───────────────────────────────────────────────────────────

#[tauri::command]
fn list_subnets(state: State<'_, AppState>) -> Vec<discover::Subnet> {
    lock(&state.subnets).list()
}

#[tauri::command]
fn save_subnets(state: State<'_, AppState>, subnets: Vec<discover::Subnet>) -> Result<Vec<discover::Subnet>, UiError> {
    lock(&state.subnets).replace(subnets).map_err(UiError::other)
}

#[derive(Debug, Deserialize)]
struct ScanArgs {
    /// Ids of saved subnets. Raw ranges are never taken from the UI.
    subnet_ids: Vec<String>,
}

/// Start scanning the chosen saved subnets. Resolves with a scan id; progress, found machines and
/// a final "finished" event arrive on the channel.
#[tauri::command]
fn start_scan(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    args: ScanArgs,
    events: Channel<InvokeResponseBody>,
) -> Result<String, UiError> {
    if args.subnet_ids.len() > discover::MAX_SUBNETS {
        return Err(UiError::other("Too many subnets chosen."));
    }
    let saved = lock(&state.subnets).list();
    let plan = discover::scan_plan(&saved, &args.subnet_ids).map_err(UiError::other)?;
    let targets = rc_discover::targets(&plan).map_err(UiError::other)?;
    let mut running = lock(&state.scan);
    if running.is_some() {
        return Err(UiError::other("A scan is already running. Cancel it or wait for it to finish."));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let cancel = rc_discover::CancelToken::default();
    *running = Some(discover::RunningScan { id: id.clone(), cancel: cancel.clone() });
    drop(running);
    let subnets: Vec<String> = plan.iter().map(ToString::to_string).collect();
    info!(scan = %id, ?subnets, addresses = targets.len(), "scan requested");

    let (tx, mut rx) = mpsc::channel(256);
    tauri::async_runtime::spawn(rc_discover::scan(targets, rc_discover::ScanOptions::default(), cancel.clone(), tx));
    let scan_id = id.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            let json = match serde_json::to_string(&event) {
                Ok(json) => json,
                Err(e) => {
                    error!(error = %e, "cannot encode a scan event");
                    continue;
                }
            };
            if events.send(InvokeResponseBody::Json(json)).is_err() {
                // The window went away: no one is watching, so stop.
                cancel.cancel();
            }
        }
        let state = app.state::<AppState>();
        let mut running = lock(&state.scan);
        if running.as_ref().is_some_and(|s| s.id == scan_id) {
            *running = None;
        }
    });
    Ok(id)
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>, scan_id: String) {
    if let Some(scan) = lock(&state.scan).as_ref().filter(|s| s.id == scan_id) {
        info!(scan = %scan_id, "scan cancelled");
        scan.cancel.cancel();
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
    // A plain function of the opener crate: it needs no plugin registered (the web UI does not use
    // the opener plugin's commands).
    tauri_plugin_opener::reveal_item_in_dir(&state.log_path).map_err(|e| UiError::other(e.to_string()))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
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
                subnets: Mutex::new(discover::SubnetStore::load(config_dir.join("subnets.json"))),
                scan: Mutex::new(None),
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
            list_subnets,
            save_subnets,
            start_scan,
            cancel_scan,
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
    fn error_kinds_use_the_ui_names() {
        // Every kind the UI knows (app/src/ipc.ts ErrorKind, minus the UI-only "password_required").
        let kinds = [
            (ErrorKind::Unreachable, "unreachable"),
            (ErrorKind::TunnelUnavailable, "tunnel_unavailable"),
            (ErrorKind::AuthFailed, "auth_failed"),
            (ErrorKind::Unsupported, "unsupported"),
            (ErrorKind::Security, "security"),
            (ErrorKind::IdentityChanged, "identity_changed"),
            (ErrorKind::Protocol, "protocol"),
            (ErrorKind::Disconnected, "disconnected"),
            (ErrorKind::Other, "other"),
        ];
        for (kind, name) in kinds {
            assert_eq!(kind_name(kind), name);
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
            let json = serde_json::to_value(UiError::from(&SessionError::new(kind, "d"))).unwrap();
            assert_eq!(json, serde_json::json!({ "kind": name, "detail": "d" }));
        }
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

    fn conn(id: &str) -> Connection {
        Connection {
            id: id.into(),
            name: "Office PC".into(),
            protocol: Protocol::Rdp,
            host: "10.0.0.5".into(),
            port: 3389,
            username: "sam".into(),
            domain: String::new(),
            nla: true,
            ssh_tunnel: true,
            ssh_port: 22,
            pinned_identity: Some("aa".repeat(32)),
            share_clipboard: true,
        }
    }

    #[test]
    fn saving_a_renamed_connection_keeps_its_pin_and_password() {
        let existing = conn("a");
        let incoming = Connection { name: "Renamed".into(), pinned_identity: None, share_clipboard: false, ..existing.clone() };
        let decision = decide_save(Some(&existing), &incoming);
        assert_eq!(decision, SaveDecision { pinned_identity: existing.pinned_identity.clone(), clear_password: false });
    }

    #[test]
    fn a_new_target_drops_the_pin_and_the_saved_password() {
        let existing = conn("a");
        for incoming in [
            Connection { host: "10.0.0.6".into(), ..existing.clone() },
            Connection { port: 3390, ..existing.clone() },
            Connection { protocol: Protocol::Vnc, ..existing.clone() },
            Connection { ssh_tunnel: false, ..existing.clone() },
            Connection { ssh_port: 2222, ..existing.clone() },
        ] {
            let decision = decide_save(Some(&existing), &incoming);
            assert_eq!(decision, SaveDecision { pinned_identity: None, clear_password: true }, "{incoming:?}");
        }
    }

    #[test]
    fn a_new_account_drops_the_saved_password_but_keeps_the_pin() {
        let existing = conn("a");
        for incoming in [
            Connection { username: "admin".into(), ..existing.clone() },
            Connection { domain: "CORP".into(), ..existing.clone() },
        ] {
            let decision = decide_save(Some(&existing), &incoming);
            assert_eq!(decision.pinned_identity, existing.pinned_identity);
            assert!(decision.clear_password, "{incoming:?}");
        }
    }

    #[test]
    fn the_callers_pin_is_never_kept() {
        // A brand-new connection.
        let incoming = Connection { id: String::new(), ..conn("") };
        assert_eq!(decide_save(None, &incoming), SaveDecision { pinned_identity: None, clear_password: false });
        // An id that does not exist: no pin from the caller, and no stale password under that id.
        let unknown = conn("not-saved");
        assert_eq!(decide_save(None, &unknown), SaveDecision { pinned_identity: None, clear_password: true });
        // An existing connection: the stored pin wins over whatever the caller sent.
        let existing = Connection { pinned_identity: None, ..conn("a") };
        let incoming = Connection { pinned_identity: Some("bb".repeat(32)), ..existing.clone() };
        assert_eq!(decide_save(Some(&existing), &incoming).pinned_identity, None);
    }

    #[test]
    fn trusting_a_new_identity_needs_a_typed_password() {
        let saved = || Some("saved".to_owned());
        assert_eq!(choose_password(None, false, saved).unwrap(), "saved");
        assert_eq!(choose_password(Some("typed".into()), false, saved).unwrap(), "typed");
        assert_eq!(choose_password(Some("typed".into()), true, saved).unwrap(), "typed");
        let error = choose_password(None, true, || panic!("the keychain must not be read")).unwrap_err();
        assert_eq!(error.kind, "password_required");
        let error = choose_password(Some(String::new()), true, || panic!("the keychain must not be read")).unwrap_err();
        assert_eq!(error.kind, "password_required");
        assert_eq!(choose_password(None, false, || None).unwrap_err().kind, "password_required");
    }

    #[test]
    fn the_identity_is_pinned_only_for_the_same_target() {
        let first = Connection { pinned_identity: None, ..conn("a") };
        let seen = "cc".repeat(32);
        // First connection: pin what was seen.
        assert_eq!(pin_after_sign_in(Some(&first), &first, Some(&seen), false), Some(seen.clone()));
        // Nothing seen (VNC without a tunnel), or the connection was deleted: nothing to pin.
        assert_eq!(pin_after_sign_in(Some(&first), &first, None, false), None);
        assert_eq!(pin_after_sign_in(None, &first, Some(&seen), false), None);
        // Edited to another host while signing in: the old host's identity is not pinned.
        let edited = Connection { host: "elsewhere".into(), ..first.clone() };
        assert_eq!(pin_after_sign_in(Some(&edited), &first, Some(&seen), false), None);
        assert_eq!(pin_after_sign_in(Some(&edited), &first, Some(&seen), true), None);
        // A matching pin needs no write; a different one is replaced only when trusting.
        let pinned = conn("a");
        let same = pinned.pinned_identity.clone().unwrap();
        assert_eq!(pin_after_sign_in(Some(&pinned), &pinned, Some(&same.to_uppercase()), false), None);
        assert_eq!(pin_after_sign_in(Some(&pinned), &pinned, Some(&seen), false), None);
        assert_eq!(pin_after_sign_in(Some(&pinned), &pinned, Some(&seen), true), Some(seen.clone()));
        // A rename while signing in does not matter.
        let renamed = Connection { name: "New name".into(), ..first.clone() };
        assert_eq!(pin_after_sign_in(Some(&renamed), &first, Some(&seen), false), Some(seen));
    }

    #[test]
    fn a_typed_password_is_saved_only_for_the_same_target_and_account() {
        let target = conn("a");
        assert!(may_save_password(Some(&target), &target));
        assert!(!may_save_password(None, &target));
        assert!(!may_save_password(Some(&Connection { host: "elsewhere".into(), ..target.clone() }), &target));
        assert!(!may_save_password(Some(&Connection { username: "other".into(), ..target.clone() }), &target));
    }

    #[test]
    fn identity_changes_carry_both_fingerprints_to_the_ui() {
        let error = SessionError::identity_changed(
            rc_types::IdentityKind::SshHostKey,
            "AA".repeat(32),
            "bb".repeat(32),
            "changed",
        );
        let json = serde_json::to_value(UiError::from(&error)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "kind": "identity_changed",
                "detail": "changed",
                "identity": {
                    "identity_kind": "ssh_host_key",
                    "expected_sha256": "aa".repeat(32),
                    "received_sha256": "bb".repeat(32),
                },
            })
        );
        // Errors from older backends (no identity field) still deserialize.
        let old: SessionError = serde_json::from_str(r#"{"kind":"security","detail":"x"}"#).unwrap();
        assert!(old.identity.is_none());
    }

    #[test]
    fn connect_args_never_show_the_password() {
        let args: ConnectArgs = serde_json::from_str(
            r#"{"id":"a","password":"hunter2","save_password":true,"width":800,"height":600,
                "scale_factor":100,"trust_new_identity":false}"#,
        )
        .unwrap();
        assert!(args.new_identity.is_none());
        let text = format!("{args:?}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn saved_connections_tell_the_ui_about_a_cleared_password() {
        let json = serde_json::to_value(SavedConnection { connection: conn("a"), password_cleared: true }).unwrap();
        assert_eq!(json["password_cleared"], true);
        assert_eq!(json["connection"]["share_clipboard"], true);
    }
}
