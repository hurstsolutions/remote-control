//! VNC (RFB) client backend.
//!
//! Primary target: macOS's built-in Screen Sharing (RFB "003.889", Apple Remote Desktop
//! authentication with a Mac username and password). Also works with ordinary VNC servers.
//!
//! * Protocol versions 3.3, 3.7 and 3.8.
//! * Security types: None (1), VNC password (2), Apple Remote Desktop DH/AES (30).
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

mod auth;
mod decode;
mod error;
mod fb;
mod input;
mod keysym;
mod proto;
mod session;
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

/// Run a session over an already-connected byte stream (TCP or an SSH tunnel).
///
/// Never panics and never returns an error: failures are reported as
/// `SessionEvent::Closed { error: Some(..) }` with the best-fitting [`rc_types::ErrorKind`].
/// Exactly one `Closed` event is sent, as the last event.
pub async fn run<S>(stream: S, config: VncConfig, io: SessionIo)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let encodings = session::encodings_from_env();
    run_with_encodings(stream, config, io, encodings).await
}

pub(crate) async fn run_with_encodings<S>(stream: S, config: VncConfig, io: SessionIo, encodings: Vec<i32>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let SessionIo { events, mut input } = io;
    info!(?config, "starting VNC session");
    let mut stage = proto::STAGE_VERSION;
    let outcome = {
        let fut = session::session(stream, &config, &events, &mut input, &mut stage, &encodings);
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

/// Convenience: TCP connect (10 s timeout, TCP_NODELAY) then [`run`].
pub async fn connect_and_run(host: &str, port: u16, config: VncConfig, io: SessionIo) {
    info!(host, port, "connecting to VNC server");
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
            return run(stream, config, io).await;
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
