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

/// UI-only kind: a direct Mac connection refused because the Mac did not offer Apple's verified
/// (SRP) sign-in (`rc_vnc::is_srp_not_offered`). Someone may be interfering, or it is an older Mac.
const NO_VERIFIED_SIGN_IN: &str = "no_verified_sign_in";

impl From<&SessionError> for UiError {
    fn from(error: &SessionError) -> Self {
        Self {
            kind: if rc_vnc::is_srp_not_offered(error) { NO_VERIFIED_SIGN_IN } else { kind_name(error.kind) },
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
    /// Like the pin: what the backend learned about this machine, kept only for the same target.
    srp_seen: bool,
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
                srp_seen: same_target && existing.srp_seen,
                clear_password: !same_target || !existing.same_account(incoming),
            }
        }
        // A new id, or one we do not know: start clean, and make sure no stale password from an
        // earlier connection with that id is picked up.
        None => SaveDecision {
            pinned_identity: None,
            srp_seen: false,
            clear_password: !incoming.id.is_empty(),
        },
    }
}

/// Remove the saved password before the connection is pointed elsewhere, and make sure it is
/// really gone: only "no entry" afterwards counts, a keychain error does not. Returns whether a
/// password was removed.
fn clear_saved_password(
    delete: impl FnOnce() -> Result<bool, String>,
    still_there: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, UiError> {
    let refuse = |why: String| {
        UiError::other(format!(
            "The address or username changed, but the saved password could not be removed from the keychain ({why}). \
             Remove it with \"Forget saved password\" and try again."
        ))
    };
    let deleted = delete().map_err(refuse)?;
    match still_there() {
        Ok(false) => Ok(deleted),
        Ok(true) => Err(refuse("it is still there".into())),
        Err(e) => Err(refuse(e)),
    }
}

/// A connection name from the UI: no control characters, nothing invisible or text-reordering
/// (bidi overrides, zero-width characters).
fn clean_name(text: &str) -> String {
    text.chars().filter(|c| !rc_discover::is_unsafe_char(*c)).collect::<String>().trim().to_owned()
}

#[tauri::command]
fn save_connection(state: State<'_, AppState>, mut connection: Connection) -> Result<SavedConnection, UiError> {
    connection.name = clean_name(&connection.name);
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
    connection.srp_seen = decision.srp_seen;
    // Delete before saving, and refuse to save the new target while the old password is still
    // there. (`connect` also refuses a password bound to another target.)
    let deleted = decision.clear_password
        && clear_saved_password(|| secrets::delete(&connection.id), || secrets::exists(&connection.id))?;
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
    // A password left behind is harmless: it is bound to this connection's target, and a new
    // connection never reuses the id without clearing it first.
    if let Err(error) = secrets::delete(&id) {
        warn!(%id, %error, "saved password not removed with its connection");
    }
    lock(&state.store).remove(&id).map_err(UiError::other)
}

#[tauri::command]
fn has_saved_password(id: String) -> Result<bool, UiError> {
    secrets::exists(&id).map_err(UiError::other)
}

#[tauri::command]
fn forget_password(id: String) -> Result<(), UiError> {
    secrets::delete(&id).map(|_| ()).map_err(UiError::other)
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
    /// With `trust_new_identity`: the fingerprint the user reviewed (required). Only that
    /// identity is accepted.
    #[serde(default)]
    new_identity: Option<String>,
}

/// The pin to check this connect against: the reviewed new identity when trusting one (which
/// must be given: there is no "accept whatever is presented"), else the saved pin.
fn pin_for_connect(args: &ConnectArgs, saved: Option<&str>) -> Result<Option<String>, UiError> {
    if !args.trust_new_identity {
        return Ok(saved.map(str::to_owned));
    }
    match args.new_identity.as_deref() {
        Some(f) if f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(Some(f.to_ascii_lowercase())),
        _ => Err(UiError::other("Trusting a new identity needs the fingerprint that was reviewed.")),
    }
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
    saved: impl FnOnce() -> Result<Option<String>, UiError>,
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
    saved()?.ok_or_else(|| UiError::new("password_required", "No password is saved for this connection."))
}

/// The saved password for `connection`, only if it was saved for this very machine and account.
/// Anything else asks for the password: a keychain error, or a password bound to another target
/// (removed on the spot).
fn saved_password(connection: &Connection) -> Result<Option<String>, UiError> {
    match secrets::get(&connection.id, &secrets::Binding::of(connection)) {
        Ok(secrets::Saved::Found(password)) => Ok(Some(password)),
        Ok(secrets::Saved::Missing) => Ok(None),
        Ok(secrets::Saved::WrongTarget) => {
            warn!(id = %connection.id, "saved password belongs to another address or account; removing it");
            if let Err(error) = secrets::delete(&connection.id) {
                warn!(%error, "cannot remove the mismatched saved password");
            }
            Err(UiError::new(
                "password_required",
                "The saved password was for a different address or account, so it was removed and not sent. Enter the password.",
            ))
        }
        Err(error) => {
            warn!(%error, "cannot read the saved password");
            Err(UiError::new(
                "password_required",
                format!("The saved password could not be read from the keychain ({error}). Enter the password."),
            ))
        }
    }
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

    let pinned = pin_for_connect(&args, connection.pinned_identity.as_deref())?;
    let typed_password = args.password.clone().filter(|p| !p.is_empty());
    let password =
        choose_password(typed_password.clone(), args.trust_new_identity, || saved_password(&connection))?;

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
                password: password.clone().into(),
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
        srp_verified: false,
        // Only a password the user just typed needs saving, and only once it has worked.
        password_to_save: typed_password.filter(|_| args.save_password),
        channel: events,
    };
    tauri::async_runtime::spawn(pump.run(handle));

    Ok(session_id)
}

/// VNC-level encryption for a Mac connection. Direct connections must be encrypted by Apple
/// Screen Sharing or not happen at all. Inside the SSH tunnel VNC adds nothing: SSH already
/// encrypts and authenticates the session, and Apple's encryption on top would only risk
/// incompatibilities.
///
/// Direct connections also require Apple's verified (SRP) sign-in, unless `allow_unverified` lets
/// a Mac without it sign in the older way (encrypted, Mac not verified).
fn vnc_options(ssh_tunnel: bool, srp: bool, allow_unverified: bool) -> rc_vnc::VncOptions {
    let encryption = if ssh_tunnel {
        rc_vnc::EncryptionPolicy::Off
    } else {
        rc_vnc::EncryptionPolicy::Required
    };
    rc_vnc::VncOptions::default()
        .with_encryption(encryption)
        .with_srp(srp)
        .with_allow_unverified_sign_in(allow_unverified)
}

/// Whether a direct Mac connection may fall back to Apple's older, unverified sign-in. Only when
/// the user allowed it for this connection and this Mac has never signed in with SRP: a Mac that
/// did SRP before and suddenly does not is treated as someone interfering. The `RC_VNC_SRP=off`
/// troubleshooting knob asks for the older sign-in outright.
fn allow_unverified_sign_in(connection: &Connection, srp: bool) -> bool {
    !srp || (connection.allow_older_mac_sign_in && !connection.srp_seen)
}

/// Troubleshooting knob: `RC_VNC_SRP=off` (or `0`, `false`, `no`) makes direct Mac connections
/// sign in with Apple's older method (encrypted, but the Mac is not verified) instead of SRP.
const SRP_ENV: &str = "RC_VNC_SRP";

fn srp_enabled(value: Option<&str>) -> bool {
    !value.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false" | "no"))
}

/// The tunnel's layer of protection. The host key was checked against the pin (a mismatch ends
/// the session before this), so the Mac is verified exactly when there was a pin.
fn tunnel_security(pinned: Option<&str>) -> SessionEvent {
    SessionEvent::security(true, pinned.is_some(), "SSH tunnel")
}

/// VNC, through an SSH tunnel to the Mac unless the connection opts out.
async fn run_vnc(connection: Connection, password: String, pinned: Option<String>, io: SessionIo) {
    let config = rc_vnc::VncConfig {
        username: Some(connection.username.clone()).filter(|u| !u.is_empty()),
        password: Some(password.clone().into()),
        shared: true,
        view_only: false,
    };
    let srp = srp_enabled(std::env::var(SRP_ENV).ok().as_deref());
    if !srp {
        warn!("{SRP_ENV} turns SRP off: a direct connection will be encrypted, but the Mac will not be verified");
    }
    let allow_unverified = allow_unverified_sign_in(&connection, srp);
    let options = vnc_options(connection.ssh_tunnel, srp, allow_unverified);
    if !connection.ssh_tunnel {
        if connection.allow_older_mac_sign_in && connection.srp_seen {
            info!("older Mac sign-in is allowed for this connection, but ignored: this Mac has signed in with SRP before");
        }
        info!(
            encryption = ?options.encryption,
            srp,
            allow_unverified,
            "VNC without an SSH tunnel: Apple Screen Sharing encryption is required"
        );
        rc_vnc::connect_and_run_with_options(&connection.host, connection.port, config, options, io).await;
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
        password: password.into(),
        target_host: "127.0.0.1".to_owned(),
        target_port: connection.port,
        pinned_host_key_sha256: pinned.clone(),
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
            let _ = io.events.send(tunnel_security(pinned.as_deref())).await;
            let guard = tunnel.guard;
            rc_vnc::run_with_options(tunnel.stream, config, options, io).await;
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
    /// The Mac signed in with SRP (verified) in this session; remembered once the sign-in succeeds.
    srp_verified: bool,
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

/// Whether to remember that this Mac does SRP: it just did, and the connection still points at it.
fn srp_seen_after_sign_in(current: Option<&Connection>, target: &Connection, srp_verified: bool) -> bool {
    srp_verified && current.is_some_and(|c| c.same_target(target) && !c.srp_seen)
}

/// A session that is trusting a new identity checks it against the identity the user just
/// accepted, not one saved from an earlier connection: never report that as verified.
fn security_for_session(event: SessionEvent, trust_new_identity: bool) -> SessionEvent {
    match event {
        SessionEvent::Security { encrypted, server_verified: true, method } if trust_new_identity => {
            SessionEvent::Security { encrypted, server_verified: false, method }
        }
        other => other,
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
                    let other = security_for_session(other, self.trust_new_identity);
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
            SessionEvent::Security { .. } => {
                if rc_vnc::VncSecurity::from_event(event) == Some(rc_vnc::VncSecurity::EncryptedVerified) {
                    self.srp_verified = true;
                }
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
            if srp_seen_after_sign_in(current.as_ref(), &self.target, self.srp_verified) {
                info!(session = %self.session_id, "this Mac signs in with SRP; the older sign-in is no longer allowed for it");
                if let Err(e) = store.set_srp_seen(&id) {
                    error!(error = %e, "cannot save that the Mac signs in with SRP");
                }
            }
            may_save_password(current.as_ref(), &self.target)
        };
        let password = self.password_to_save.take()?;
        if !save_password {
            warn!(session = %self.session_id, "connection was changed while signing in; password not saved");
            return None;
        }
        match secrets::set(&id, &password, &secrets::Binding::of(&self.target)) {
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
        SessionEvent::Security { encrypted, server_verified, method } => json!({
            "type": "security", "encrypted": encrypted, "server_verified": server_verified, "method": method,
        }),
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
    fn security_events_use_the_ui_field_names() {
        let json = to_json(SessionEvent::security(true, false, "TLS + NLA")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "type": "security", "encrypted": true, "server_verified": false, "method": "TLS + NLA" })
        );
        let json = to_json(rc_vnc::VncSecurity::EncryptedVerified.to_event()).unwrap();
        assert_eq!(json["encrypted"], true);
        assert_eq!(json["server_verified"], true);
    }

    #[test]
    fn direct_mac_connections_require_encryption_and_tunnelled_ones_leave_it_to_ssh() {
        let direct = vnc_options(false, true, false);
        assert_eq!(direct.encryption, rc_vnc::EncryptionPolicy::Required);
        assert!(direct.srp);
        assert!(!direct.allow_unverified_sign_in);
        assert!(vnc_options(false, true, true).allow_unverified_sign_in);
        let tunnelled = vnc_options(true, true, false);
        assert_eq!(tunnelled.encryption, rc_vnc::EncryptionPolicy::Off);
        assert!(!vnc_options(false, false, true).srp);
        assert_eq!(vnc_options(false, false, true).encryption, rc_vnc::EncryptionPolicy::Required);
    }

    #[test]
    fn older_mac_sign_in_needs_the_setting_and_no_srp_history() {
        let mac = Connection { protocol: Protocol::Vnc, ssh_tunnel: false, pinned_identity: None, ..conn("m") };
        assert!(!allow_unverified_sign_in(&mac, true), "off by default");
        let allowed = Connection { allow_older_mac_sign_in: true, ..mac.clone() };
        assert!(allow_unverified_sign_in(&allowed, true));
        let seen = Connection { srp_seen: true, ..allowed.clone() };
        assert!(!allow_unverified_sign_in(&seen, true), "a Mac that did SRP before never falls back");
        assert!(allow_unverified_sign_in(&mac, false), "the RC_VNC_SRP=off knob asks for the older sign-in");
    }

    #[test]
    fn srp_is_on_unless_the_knob_turns_it_off() {
        assert!(srp_enabled(None));
        assert!(srp_enabled(Some("")));
        assert!(srp_enabled(Some("on")));
        for off in ["off", "0", "false", "no", " OFF "] {
            assert!(!srp_enabled(Some(off)), "{off}");
        }
    }

    #[test]
    fn the_tunnel_is_verified_only_against_a_pin() {
        let check = |pinned: Option<&str>, verified: bool| match tunnel_security(pinned) {
            SessionEvent::Security { encrypted, server_verified, method } => {
                assert!(encrypted);
                assert_eq!(server_verified, verified);
                assert_eq!(method, "SSH tunnel");
            }
            other => panic!("{other:?}"),
        };
        check(None, false);
        check(Some("ab"), true);
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
    fn a_mac_without_verified_sign_in_gets_its_own_kind() {
        let refused = SessionError::new(ErrorKind::Security, format!("{}; Offered: [30]", rc_vnc::SRP_NOT_OFFERED));
        assert_eq!(UiError::from(&refused).kind, "no_verified_sign_in");
        // The RC_VNC_SRP=off refusal and other security errors stay "security".
        let srp_off = SessionError::new(ErrorKind::Security, "SRP sign-in (Apple's verified sign-in) is turned off for this connection");
        assert_eq!(UiError::from(&srp_off).kind, "security");
        let other = SessionError::new(ErrorKind::Other, rc_vnc::SRP_NOT_OFFERED);
        assert_eq!(UiError::from(&other).kind, "other");
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
            allow_older_mac_sign_in: false,
            srp_seen: false,
        }
    }

    #[test]
    fn saving_a_renamed_connection_keeps_its_pin_and_password() {
        let existing = conn("a");
        let incoming = Connection { name: "Renamed".into(), pinned_identity: None, share_clipboard: false, ..existing.clone() };
        let decision = decide_save(Some(&existing), &incoming);
        assert_eq!(
            decision,
            SaveDecision { pinned_identity: existing.pinned_identity.clone(), srp_seen: false, clear_password: false }
        );
        // What the backend learned about the Mac stays too, whatever the caller sends.
        let mac = Connection { protocol: Protocol::Vnc, ssh_tunnel: false, srp_seen: true, ..existing.clone() };
        let edited = Connection { name: "Mac".into(), srp_seen: false, allow_older_mac_sign_in: true, ..mac.clone() };
        assert!(decide_save(Some(&mac), &edited).srp_seen);
        assert!(!decide_save(None, &Connection { srp_seen: true, ..conn("new") }).srp_seen, "never taken from the caller");
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
            assert_eq!(decision, SaveDecision { pinned_identity: None, srp_seen: false, clear_password: true }, "{incoming:?}");
            let seen = Connection { srp_seen: true, ..existing.clone() };
            assert!(!decide_save(Some(&seen), &incoming).srp_seen, "retargeting forgets SRP: {incoming:?}");
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
        assert_eq!(decide_save(None, &incoming), SaveDecision { pinned_identity: None, srp_seen: false, clear_password: false });
        // An id that does not exist: no pin from the caller, and no stale password under that id.
        let unknown = conn("not-saved");
        assert_eq!(decide_save(None, &unknown), SaveDecision { pinned_identity: None, srp_seen: false, clear_password: true });
        // An existing connection: the stored pin wins over whatever the caller sent.
        let existing = Connection { pinned_identity: None, ..conn("a") };
        let incoming = Connection { pinned_identity: Some("bb".repeat(32)), ..existing.clone() };
        assert_eq!(decide_save(Some(&existing), &incoming).pinned_identity, None);
    }

    #[test]
    fn trusting_a_new_identity_needs_a_typed_password() {
        let saved = || Ok(Some("saved".to_owned()));
        assert_eq!(choose_password(None, false, saved).unwrap(), "saved");
        assert_eq!(choose_password(Some("typed".into()), false, saved).unwrap(), "typed");
        assert_eq!(choose_password(Some("typed".into()), true, saved).unwrap(), "typed");
        let error = choose_password(None, true, || panic!("the keychain must not be read")).unwrap_err();
        assert_eq!(error.kind, "password_required");
        let error = choose_password(Some(String::new()), true, || panic!("the keychain must not be read")).unwrap_err();
        assert_eq!(error.kind, "password_required");
        assert_eq!(choose_password(None, false, || Ok(None)).unwrap_err().kind, "password_required");
        // A keychain problem (or a password for another target) is never "carry on without one".
        let error = choose_password(None, false, || Err(UiError::new("password_required", "keychain locked"))).unwrap_err();
        assert_eq!((error.kind, error.detail.as_str()), ("password_required", "keychain locked"));
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

    #[test]
    fn a_password_is_cleared_only_when_the_keychain_says_it_is_gone() {
        assert!(clear_saved_password(|| Ok(true), || Ok(false)).unwrap());
        assert!(!clear_saved_password(|| Ok(false), || Ok(false)).unwrap(), "nothing to remove is fine");
        let error = clear_saved_password(|| Err("locked".into()), || panic!("not read after a failed delete")).unwrap_err();
        assert!(error.detail.contains("locked"), "{}", error.detail);
        assert!(clear_saved_password(|| Ok(true), || Ok(true)).is_err(), "still there");
        assert!(clear_saved_password(|| Ok(true), || Err("no keychain".into())).is_err(), "an unreadable keychain is not gone");
    }

    #[test]
    fn names_lose_hidden_and_reordering_characters() {
        assert_eq!(clean_name("  Office\u{202E}CP\u{200B}\u{2066} Mac\u{FEFF}\u{7} "), "OfficeCP Mac");
        assert_eq!(clean_name("Café 💻"), "Café 💻");
    }

    #[test]
    fn trusting_a_new_identity_needs_the_reviewed_fingerprint() {
        let args = |trust: bool, new_identity: Option<String>| ConnectArgs {
            id: "a".into(),
            password: Some("pw".into()),
            save_password: false,
            width: 800,
            height: 600,
            scale_factor: 100,
            trust_new_identity: trust,
            new_identity,
        };
        let saved = "aa".repeat(32);
        assert_eq!(pin_for_connect(&args(false, None), Some(&saved)).unwrap(), Some(saved.clone()));
        assert_eq!(pin_for_connect(&args(false, None), None).unwrap(), None);
        let reviewed = "BB".repeat(32);
        assert_eq!(pin_for_connect(&args(true, Some(reviewed)), Some(&saved)).unwrap(), Some("bb".repeat(32)));
        for bad in [None, Some(String::new()), Some("bb".repeat(31)), Some("zz".repeat(32))] {
            assert!(pin_for_connect(&args(true, bad.clone()), Some(&saved)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_newly_trusted_identity_is_never_reported_as_verified() {
        let check = |event: SessionEvent, verified: bool| match event {
            SessionEvent::Security { server_verified, encrypted, .. } => {
                assert!(encrypted);
                assert_eq!(server_verified, verified);
            }
            other => panic!("{other:?}"),
        };
        check(security_for_session(SessionEvent::security(true, true, "SSH tunnel"), true), false);
        check(security_for_session(SessionEvent::security(true, true, "SSH tunnel"), false), true);
        check(security_for_session(SessionEvent::security(true, true, "TLS + NLA"), true), false);
        assert!(matches!(security_for_session(SessionEvent::Bell, true), SessionEvent::Bell));
    }

    #[test]
    fn srp_is_remembered_only_for_the_same_mac() {
        let mac = Connection { protocol: Protocol::Vnc, ssh_tunnel: false, pinned_identity: None, ..conn("m") };
        assert!(srp_seen_after_sign_in(Some(&mac), &mac, true));
        assert!(!srp_seen_after_sign_in(Some(&mac), &mac, false), "no SRP this time");
        assert!(!srp_seen_after_sign_in(None, &mac, true), "deleted while signing in");
        let moved = Connection { host: "10.0.0.77".into(), ..mac.clone() };
        assert!(!srp_seen_after_sign_in(Some(&moved), &mac, true), "edited to another Mac while signing in");
        let already = Connection { srp_seen: true, ..mac.clone() };
        assert!(!srp_seen_after_sign_in(Some(&already), &mac, true), "already saved: no write");
    }
}
