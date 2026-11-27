//! VNC (RFB) client backend.
//!
//! Primary target: macOS's built-in Screen Sharing (RFB "003.889", Apple Remote Desktop
//! authentication with a Mac username and password). Also works with ordinary VNC servers.
//!
//! * Protocol versions 3.3, 3.7, 3.8, and Apple's 003.889 (for encrypted sessions).
//! * Security types: None (1), VNC password (2), Apple Remote Desktop DH/AES (30), Apple SRP (33
//!   with its RSA envelope, or 36 when the Mac does not list 33; used only for encrypted sessions,
//!   preferred over 30).
//! * Apple Screen Sharing's encrypted session (AES-128-CBC record layer with SHA-1 integrity),
//!   selected by [`EncryptionPolicy`] in [`VncOptions`]. Just before `Connected` the session
//!   emits one `SessionEvent::Security` describing VNC's own protection
//!   ([`VncSecurity::to_event`]); [`VncSecurity::from_event`] maps it back. In an encrypted
//!   session both are sent only after the Mac's first encrypted message has passed its
//!   integrity check, which confirms the key the sign-in produced.
//! * Under [`EncryptionPolicy::Required`] only the verified sign-in (SRP) is used unless
//!   [`VncOptions::allow_unverified_sign_in`] is set; SRP accepts only the RFC 5054 groups and
//!   checks the Mac's proof.
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
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection settings.
#[derive(Clone)]
pub struct VncConfig {
    /// Needed for Apple (macOS account) authentication.
    pub username: Option<String>,
    /// Wiped from memory when dropped (`Some(password.into())` from a `String`).
    pub password: Option<Zeroizing<String>>,
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
/// after signing in with a macOS username and password (SRP over security type 33 or 36, or
/// type 30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionPolicy {
    /// Encrypt or do not connect. For direct connections (no SSH tunnel). Refuses servers that
    /// are not Apple Screen Sharing, and refuses security types None (1) and VNC password (2)
    /// even if the server offers them: a man in the middle could otherwise strip the other
    /// types from the list and read the session. Never falls back to cleartext.
    ///
    /// Also requires the verified sign-in (SRP, types 33/36): Apple's type 30 is refused unless
    /// [`VncOptions::allow_unverified_sign_in`] is set, whether the Mac did not offer type 36
    /// (see [`SRP_NOT_OFFERED`]) or SRP is turned off with [`VncOptions::srp`].
    Required,
    /// Encrypt when the server is a Mac and a macOS username and password are available;
    /// otherwise continue unencrypted (with a warning in the log). Uses SRP when offered and
    /// falls back to type 30 without asking (`allow_unverified_sign_in` is ignored). Once encryption setup has
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
    /// For encrypted sessions, sign in with SRP when the Mac offers it (lists type 36; carried
    /// by type 33 when that is listed too, as Apple's viewer does),
    /// which also verifies the Mac's identity. Default true. Turning it off falls back to
    /// type 30 (encrypted, Mac not verified); meant only as an escape hatch while SRP is new.
    /// Under [`EncryptionPolicy::Required`] that fallback also needs `allow_unverified_sign_in`.
    pub srp: bool,
    /// Under [`EncryptionPolicy::Required`], allow Apple's type 30 sign-in when SRP is not used
    /// (the Mac did not offer type 36, or `srp` is false). Type 30 encrypts the session but
    /// cannot verify the Mac: a man in the middle can strip type 36 from the Mac's list and then
    /// learn the password. Default false: such a connection fails with a `Security` error, whose
    /// detail starts with [`SRP_NOT_OFFERED`] when the Mac did not offer SRP. No effect under
    /// `Preferred` or `Off`.
    pub allow_unverified_sign_in: bool,
}

impl Default for VncOptions {
    fn default() -> Self {
        VncOptions { encryption: EncryptionPolicy::default(), srp: true, allow_unverified_sign_in: false }
    }
}

/// Start of the `SessionError::detail` (kind `Security`) when encryption is required, SRP is
/// enabled, and the Mac's security list has no SRP (type 36) but type 30: either a man in the
/// middle edited the list, or an older Mac. See [`is_srp_not_offered`].
pub const SRP_NOT_OFFERED: &str = "the Mac didn't offer SRP sign-in (Apple's verified sign-in)";

/// Whether `error` is the [`SRP_NOT_OFFERED`] refusal (so a front end can offer
/// [`VncOptions::allow_unverified_sign_in`] after a warning).
pub fn is_srp_not_offered(error: &SessionError) -> bool {
    error.kind == ErrorKind::Security && error.detail.starts_with(SRP_NOT_OFFERED)
}

impl VncOptions {
    pub fn with_srp(mut self, srp: bool) -> Self {
        self.srp = srp;
        self
    }
    pub fn with_allow_unverified_sign_in(mut self, allow: bool) -> Self {
        self.allow_unverified_sign_in = allow;
        self
    }
    pub fn with_encryption(mut self, encryption: EncryptionPolicy) -> Self {
        self.encryption = encryption;
        self
    }
}

/// How the VNC protocol itself protects a session. Reported once, as a `SessionEvent::Security`
/// ([`VncSecurity::to_event`]), just before `Connected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncSecurity {
    /// No VNC-level encryption (the session may still run inside an SSH tunnel).
    Unencrypted,
    /// Encrypted (Apple's AES-128 record layer), but the Mac's identity was not verified: Apple's
    /// Diffie-Hellman sign-in (type 30) is unauthenticated, so this protects against passive
    /// eavesdropping only. An active man in the middle can impersonate the Mac and learn the
    /// password.
    EncryptedUnverified,
    /// Encrypted, and the Mac proved it knows the account's password verifier (SRP, type 33 or 36,
    /// its proof M2 checked) and the first encrypted message from it passed its integrity check:
    /// protects against eavesdropping and impersonation.
    EncryptedVerified,
}

/// [`VncSecurity::Unencrypted`] method name in `SessionEvent::Security`.
pub const METHOD_UNENCRYPTED: &str = "VNC, unencrypted";
/// [`VncSecurity::EncryptedUnverified`] method name.
pub const METHOD_ENCRYPTED_UNVERIFIED: &str = "Apple Screen Sharing encryption";
/// [`VncSecurity::EncryptedVerified`] method name.
pub const METHOD_ENCRYPTED_VERIFIED: &str = "Apple Screen Sharing encryption, SRP sign-in";

impl VncSecurity {
    const ALL: [VncSecurity; 3] =
        [VncSecurity::Unencrypted, VncSecurity::EncryptedUnverified, VncSecurity::EncryptedVerified];

    /// A sentence for the log.
    pub fn status_text(self) -> &'static str {
        match self {
            VncSecurity::Unencrypted => "Session not encrypted by VNC",
            VncSecurity::EncryptedUnverified => {
                "Session encrypted (Apple Screen Sharing, AES-128); the Mac's identity is not verified"
            }
            VncSecurity::EncryptedVerified => {
                "Session encrypted (Apple Screen Sharing, AES-128); the Mac's identity is verified (SRP)"
            }
        }
    }
    /// The `method` of this level's `SessionEvent::Security`.
    pub fn method(self) -> &'static str {
        match self {
            VncSecurity::Unencrypted => METHOD_UNENCRYPTED,
            VncSecurity::EncryptedUnverified => METHOD_ENCRYPTED_UNVERIFIED,
            VncSecurity::EncryptedVerified => METHOD_ENCRYPTED_VERIFIED,
        }
    }
    pub fn is_encrypted(self) -> bool {
        self != VncSecurity::Unencrypted
    }
    pub fn is_verified(self) -> bool {
        self == VncSecurity::EncryptedVerified
    }
    /// The event the session sends for this level.
    pub fn to_event(self) -> SessionEvent {
        SessionEvent::security(self.is_encrypted(), self.is_verified(), self.method())
    }
    /// The level a `SessionEvent::Security` from this crate announces, if it is one.
    pub fn from_event(event: &SessionEvent) -> Option<Self> {
        match event {
            SessionEvent::Security { encrypted, server_verified, method } => Self::ALL.into_iter().find(|s| {
                s.method() == method && s.is_encrypted() == *encrypted && s.is_verified() == *server_verified
            }),
            _ => None,
        }
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
    connect_to_and_run_with_options(host, port, None, config, options, io).await
}

/// [`connect_and_run_with_options`], connecting to `resolved` (addresses `host` already resolved
/// to, which the caller checked) instead of looking `host` up again. `host` is then only shown in
/// messages. `None` resolves `host`.
pub async fn connect_to_and_run_with_options(
    host: &str,
    port: u16,
    resolved: Option<&[std::net::SocketAddr]>,
    config: VncConfig,
    options: VncOptions,
    io: SessionIo,
) {
    info!(host, port, ?resolved, encryption = ?options.encryption, "connecting to VNC server");
    if io.events.send(SessionEvent::Status(format!("Connecting to {host}:{port}"))).await.is_err() {
        return;
    }
    let tcp = async {
        match resolved {
            Some(addrs) => tokio::net::TcpStream::connect(addrs).await,
            None => tokio::net::TcpStream::connect((host, port)).await,
        }
    };
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, tcp).await;
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
