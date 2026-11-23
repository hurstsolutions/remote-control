//! Types shared by every protocol backend (RDP, VNC) and every front end (CLI, desktop app).
//!
//! A backend exposes one async function that takes its own config plus a [`SessionIo`], runs until
//! the session ends, and talks to the front end only through these two channels.

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Clipboard text larger than this many bytes (UTF-8) is not passed between the machines, in
/// either direction: it would stall the session, and nobody means to paste a megabyte.
pub const MAX_CLIPBOARD_BYTES: usize = 1_000_000;

/// Sent from a backend to the front end.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Human-readable progress during connection ("Connecting", "Authenticating"...). Also logged.
    Status(String),
    /// The server proved its identity with this key/certificate (before any credentials are sent
    /// for RDP). `sha256` is lowercase hex. The front end stores it on first use and passes it back
    /// as the pinned value on later connections.
    ServerIdentity { sha256: String },
    /// The session is up. The framebuffer is `width` x `height`; expect [`SessionEvent::Frame`]s next.
    Connected { width: u16, height: u16, name: String },
    /// The remote desktop changed size. Previous pixels are invalid.
    Resized { width: u16, height: u16 },
    /// A rectangle of new pixels. `rgba` is tightly packed RGBA8 (alpha always 255),
    /// `w * h * 4` bytes, row-major, top-down.
    Frame { x: u16, y: u16, w: u16, h: u16, rgba: Vec<u8> },
    /// New remote cursor shape (RGBA8, straight alpha). `None` pixels = hide the cursor.
    Cursor(CursorShape),
    /// The remote clipboard now holds this text.
    Clipboard(String),
    Bell,
    /// The session ended. `error` is `None` for a clean disconnect.
    Closed { error: Option<SessionError> },
}

#[derive(Debug, Clone)]
pub enum CursorShape {
    /// Use the local default arrow.
    Default,
    Hidden,
    Bitmap { width: u16, height: u16, hot_x: u16, hot_y: u16, rgba: Vec<u8> },
}

/// Why a session failed. `kind` lets the UI show a targeted hint; `detail` is the full technical
/// message for the log the user sends back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionError {
    pub kind: ErrorKind,
    pub detail: String,
    /// Set only with [`ErrorKind::IdentityChanged`]: what was pinned and what was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityMismatch>,
}

/// Which kind of server identity a fingerprint belongs to. They are verified in different places
/// on the remote machine, so the UI explains each one differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// SHA-256 of the RDP server's TLS certificate (DER).
    TlsCertificate,
    /// SHA-256 of the SSH host key blob, as `ssh-keygen -l` hashes it.
    SshHostKey,
}

/// A pinned identity that no longer matches. Both fingerprints are lowercase hex SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMismatch {
    pub identity_kind: IdentityKind,
    pub expected_sha256: String,
    pub received_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// DNS failure, connection refused, timeout: the machine or port is not reachable.
    Unreachable,
    /// The SSH tunnel could not be opened because the SSH port refused the connection or did not
    /// answer (on a Mac: Remote Login is off). Not used for sign-in or host key failures. The UI
    /// offers to connect without the tunnel.
    TunnelUnavailable,
    /// Wrong username/password, or account not allowed to log in remotely.
    AuthFailed,
    /// The server offered no security/auth method this client supports.
    Unsupported,
    /// TLS / certificate / SSH host key problem other than a changed identity (a failed handshake,
    /// a certificate that cannot be used).
    Security,
    /// The server presented a different identity (TLS certificate or SSH host key) from the pinned
    /// one. Always comes with [`SessionError::identity`]. Nothing secret was sent.
    IdentityChanged,
    /// The server sent something the client could not parse.
    Protocol,
    /// The connection dropped mid-session.
    Disconnected,
    Other,
}

impl SessionError {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self { kind, detail: detail.into(), identity: None }
    }

    /// A pinned identity mismatch: kind [`ErrorKind::IdentityChanged`] with both fingerprints.
    pub fn identity_changed(
        identity_kind: IdentityKind,
        expected_sha256: impl Into<String>,
        received_sha256: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind: ErrorKind::IdentityChanged,
            detail: detail.into(),
            identity: Some(IdentityMismatch {
                identity_kind,
                expected_sha256: expected_sha256.into().to_ascii_lowercase(),
                received_sha256: received_sha256.into().to_ascii_lowercase(),
            }),
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}
impl std::error::Error for SessionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

/// Sent from the front end to a backend. Coordinates are in remote framebuffer pixels.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionInput {
    PointerMove { x: u16, y: u16 },
    PointerButton { button: MouseButton, down: bool, x: u16, y: u16 },
    /// Scroll. Positive `dy` = wheel up / content moves down; positive `dx` = right.
    /// Unit is wheel notches (may be fractional for trackpads; backends accumulate).
    Wheel { dx: f32, dy: f32, x: u16, y: u16 },
    /// A key changed state.
    /// `code` is the physical key as a W3C `KeyboardEvent.code` value ("KeyA", "ShiftLeft",
    /// "ArrowUp", "MetaLeft"...). `key` is the W3C `KeyboardEvent.key` value: the produced
    /// character ("a", "A", "é", "@") or a named key ("Enter", "Shift").
    /// RDP uses `code` (scancodes); VNC uses `key` (keysyms) and falls back to `code`.
    Key { code: String, key: String, down: bool },
    /// Release every key and button the backend believes is held (sent on focus loss).
    ReleaseAll,
    /// The local clipboard now holds this text.
    Clipboard { text: String },
    /// Ask the server to change the desktop size (RDP display control / VNC SetDesktopSize).
    /// Backends ignore it when the server does not support it.
    Resize { width: u16, height: u16 },
    /// Ask for a full-screen refresh.
    Refresh,
    Close,
}

/// The two channel ends a backend is handed.
pub struct SessionIo {
    pub events: mpsc::Sender<SessionEvent>,
    pub input: mpsc::UnboundedReceiver<SessionInput>,
}

/// The front end's side of the channels.
pub struct SessionHandle {
    pub events: mpsc::Receiver<SessionEvent>,
    pub input: mpsc::UnboundedSender<SessionInput>,
}

/// Create a connected ([`SessionIo`], [`SessionHandle`]) pair.
pub fn session_channels() -> (SessionIo, SessionHandle) {
    let (ev_tx, ev_rx) = mpsc::channel(256);
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    (SessionIo { events: ev_tx, input: in_rx }, SessionHandle { events: ev_rx, input: in_tx })
}
