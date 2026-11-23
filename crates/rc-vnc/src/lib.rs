//! VNC (RFB) client backend.
//!
//! Primary target: macOS's built-in Screen Sharing (RFB "003.889", Apple Remote Desktop
//! authentication with a Mac username and password). Also works with ordinary VNC servers.
//!
//! * Protocol versions 3.3, 3.7, 3.8, and Apple's 003.889 (for encrypted sessions).
//! * Security types: None (1), VNC password (2), Apple Remote Desktop DH/AES (30), Apple SRP (36,
//!   used only for encrypted sessions, preferred over 30).
//! * Apple Screen Sharing's encrypted session (AES-128-CBC record layer with SHA-1 integrity),
//!   selected by [`EncryptionPolicy`] in [`VncOptions`]. Just before `Connected` the session
//!   emits `SessionEvent::Status(text)` where `text` is [`VncSecurity::status_text`] of the
//!   session's protection; [`VncSecurity::from_status`] maps it back.
//! * Encodings: Raw, CopyRect, RRE, Hextile, Zlib, ZRLE, Tight (including JPEG); pseudo-encodings
//!   Cursor, DesktopSize, ExtendedDesktopSize, LastRect.
//!
//! The handshake is logged in detail through `tracing` (never passwords, keys, key strokes or
//! clipboard contents) so that a single log file from a user shows where a connection went wrong.
//!
//! ## Troubleshooting knob
//!
//! The environment variable `RC_VNC_ENCODINGS` overrides the advertised encodings without a
//! rebuild, e.g. `RC_VNC_ENCODINGS=zrle,hextile` or `RC_VNC_ENCODINGS=raw`. Tokens: `raw`,
//! `copyrect`, `rre`, `hextile`, `zlib`, `tight`, `zrle`, `jpeg` (allow lossy JPEG inside Tight),
//! any integer (a raw encoding number), and `nopseudo` (do not add the default pseudo-encodings
//! Cursor / DesktopSize / ExtendedDesktopSize / LastRect).

// `as_chunks` needs a recent toolchain; `chunks_exact` keeps the crate building on older ones.
#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

mod apple;
mod auth;
mod decode;
mod error;
mod fb;
mod input;
mod keysym;
mod proto;
mod record;
mod session;
mod srp;
#[cfg(test)]
mod tests;
mod zlib;

use rc_types::{ErrorKind, SessionError, SessionEvent, SessionIo};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection settings.
#[derive(Clone)]
pub struct VncConfig {
    /// Needed for Apple (macOS account) authentication.
    pub username: Option<String>,
    pub password: Option<String>,
    /// RFB shared flag: leave other viewers connected. Default true.
    pub shared: bool,
    /// Drop all pointer, keyboard, clipboard and resize input.
    pub view_only: bool,
}

impl Default for VncConfig {
    fn default() -> Self {
        VncConfig { username: None, password: None, shared: true, view_only: false }
    }
}

impl std::fmt::Debug for VncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print credentials.
        f.debug_struct("VncConfig")
            .field("username", &self.username.as_ref().map(|_| "<set>"))
            .field("password", &self.password.as_ref().map(|_| "<set>"))
            .field("shared", &self.shared)
            .field("view_only", &self.view_only)
            .finish()
    }
}

/// Whether the session must be encrypted by the VNC protocol itself.
///
/// Only Apple Screen Sharing (macOS, RFB 003.889) can encrypt a VNC session here; it does so
/// after signing in with a macOS username and password (security type 30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionPolicy {
    /// Encrypt or do not connect. For direct connections (no SSH tunnel). Refuses servers that
    /// are not Apple Screen Sharing, and refuses security types None (1) and VNC password (2)
    /// even if the server offers them: a man in the middle could otherwise strip the other
    /// types from the list and read the session. Never falls back to cleartext.
    Required,
    /// Encrypt when the server is a Mac and a macOS username and password are available;
    /// otherwise continue unencrypted (with a warning in the log). Once encryption setup has
    /// started, a failure ends the session; it is never silently downgraded. For use inside an
    /// SSH tunnel, where the tunnel already protects the session.
    Preferred,
    /// Never ask for encryption; behave like a plain RFB 3.8 client (the behaviour before
    /// encryption support existed). Needed for non-Apple VNC servers.
    #[default]
    Off,
}

/// Session options beyond the credentials in [`VncConfig`]. Build with `VncOptions::default()`
/// and set fields; new fields may be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VncOptions {
    /// Default: [`EncryptionPolicy::Off`].
    pub encryption: EncryptionPolicy,
    /// For encrypted sessions, sign in with SRP (security type 36) when the Mac offers it,
    /// which also verifies the Mac's identity. Default true. Turning it off falls back to
    /// type 30 (encrypted, Mac not verified); meant only as an escape hatch while SRP is new.
    pub srp: bool,
}

impl Default for VncOptions {
    fn default() -> Self {
        VncOptions { encryption: EncryptionPolicy::default(), srp: true }
    }
}

impl VncOptions {
    pub fn with_srp(mut self, srp: bool) -> Self {
        self.srp = srp;
        self
    }
    pub fn with_encryption(mut self, encryption: EncryptionPolicy) -> Self {
        self.encryption = encryption;
        self
    }
}

/// How the VNC protocol itself protects a session. Reported once, as a `SessionEvent::Status`
/// with [`VncSecurity::status_text`], just before `Connected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncSecurity {
    /// No VNC-level encryption (the session may still run inside an SSH tunnel).
    Unencrypted,
    /// Encrypted (Apple's AES-128 record layer), but the Mac's identity was not verified: Apple's
    /// Diffie-Hellman sign-in (type 30) is unauthenticated, so this protects against passive
    /// eavesdropping only. An active man in the middle can impersonate the Mac and learn the
    /// password.
    EncryptedUnverified,
    /// Encrypted, and the Mac proved it knows the account's password verifier (SRP, type 36):
    /// protects against eavesdropping and impersonation.
    EncryptedVerified,
}

/// [`VncSecurity::Unencrypted`] status text.
pub const STATUS_UNENCRYPTED: &str = "Session not encrypted by VNC";
/// [`VncSecurity::EncryptedUnverified`] status text.
pub const STATUS_ENCRYPTED_UNVERIFIED: &str =
    "Session encrypted (Apple Screen Sharing, AES-128); the Mac's identity is not verified";
/// [`VncSecurity::EncryptedVerified`] status text.
pub const STATUS_ENCRYPTED_VERIFIED: &str =
    "Session encrypted (Apple Screen Sharing, AES-128); the Mac's identity is verified (SRP)";

impl VncSecurity {
    pub fn status_text(self) -> &'static str {
        match self {
            VncSecurity::Unencrypted => STATUS_UNENCRYPTED,
            VncSecurity::EncryptedUnverified => STATUS_ENCRYPTED_UNVERIFIED,
            VncSecurity::EncryptedVerified => STATUS_ENCRYPTED_VERIFIED,
        }
    }
    /// The security level a status text announces, if it is one of these.
    pub fn from_status(text: &str) -> Option<Self> {
        [VncSecurity::Unencrypted, VncSecurity::EncryptedUnverified, VncSecurity::EncryptedVerified]
            .into_iter()
            .find(|s| s.status_text() == text)
    }
    pub fn is_encrypted(self) -> bool {
        self != VncSecurity::Unencrypted
    }
}

/// Run a session over an already-connected byte stream (TCP or an SSH tunnel), with default
/// [`VncOptions`] (no VNC-level encryption).
///
/// Never panics and never returns an error: failures are reported as
/// `SessionEvent::Closed { error: Some(..) }` with the best-fitting [`rc_types::ErrorKind`].
/// Exactly one `Closed` event is sent, as the last event.
pub async fn run<S>(stream: S, config: VncConfig, io: SessionIo)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_with_options(stream, config, VncOptions::default(), io).await
}

/// [`run`] with explicit [`VncOptions`].
pub async fn run_with_options<S>(stream: S, config: VncConfig, options: VncOptions, io: SessionIo)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let encodings = session::encodings_from_env();
    run_with_encodings(stream, config, options, io, encodings).await
}

pub(crate) async fn run_with_encodings<S>(
    stream: S,
    config: VncConfig,
    options: VncOptions,
    io: SessionIo,
    encodings: Vec<i32>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let SessionIo { events, mut input } = io;
    info!(?config, ?options, "starting VNC session");
    let mut stage = proto::STAGE_VERSION;
    let outcome = {
        let fut = session::session(stream, &config, &options, &events, &mut input, &mut stage, &encodings);
        catch_panic(fut).await
    };
    let error = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(e)) => e.into_session_error(stage),
        Err(panic_msg) => {
            error!(panic = %panic_msg, stage, "internal error in the VNC backend");
            Some(SessionError::new(ErrorKind::Other, format!("internal error in the VNC backend: {panic_msg}")))
        }
    };
    match &error {
        None => info!("VNC session closed cleanly"),
        Some(e) => warn!(kind = ?e.kind, detail = %e.detail, stage, "VNC session ended with an error"),
    }
    // If the receiver is gone there is nobody to tell.
    let _ = events.send(SessionEvent::Closed { error }).await;
}

/// Convenience: TCP connect (10 s timeout, TCP_NODELAY) then [`run`] (default options, no
/// VNC-level encryption).
pub async fn connect_and_run(host: &str, port: u16, config: VncConfig, io: SessionIo) {
    connect_and_run_with_options(host, port, config, VncOptions::default(), io).await
}

/// [`connect_and_run`] with explicit [`VncOptions`]. Direct connections to a Mac should use
/// `EncryptionPolicy::Required`.
pub async fn connect_and_run_with_options(host: &str, port: u16, config: VncConfig, options: VncOptions, io: SessionIo) {
    info!(host, port, encryption = ?options.encryption, "connecting to VNC server");
    if io.events.send(SessionEvent::Status(format!("Connecting to {host}:{port}"))).await.is_err() {
        return;
    }
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, port))).await;
    let detail = match connect {
        Ok(Ok(stream)) => {
            if let Err(e) = stream.set_nodelay(true) {
                warn!("could not set TCP_NODELAY: {e}");
            }
            info!(peer = ?stream.peer_addr().ok(), "TCP connection established");
            return run_with_options(stream, config, options, io).await;
        }
        Ok(Err(e)) => format!("could not connect to {host}:{port}: {e}"),
        Err(_) => format!("could not connect to {host}:{port}: timed out after {} s", CONNECT_TIMEOUT.as_secs()),
    };
    warn!("{detail}");
    let error = Some(SessionError::new(ErrorKind::Unreachable, detail));
    let _ = io.events.send(SessionEvent::Closed { error }).await;
}

/// Poll `fut`, turning a panic inside it into an `Err` with the panic message.
async fn catch_panic<F: Future>(fut: F) -> Result<F::Output, String> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(move |cx| {
        match std::panic::catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
            Ok(poll) => poll.map(Ok),
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                std::task::Poll::Ready(Err(msg))
            }
        }
    })
    .await
}
