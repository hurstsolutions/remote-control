//! Internal error type; converted to `rc_types::SessionError` at the edge.

use rc_types::{ErrorKind, SessionError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum VncError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    Unsupported(String),
    /// Encryption could not be set up, was refused by policy, or failed mid-session.
    #[error("{0}")]
    Security(String),
    #[error("{0}")]
    Other(String),
    /// The front end asked us to close (or dropped its input sender). Clean shutdown.
    #[error("closed by user")]
    UserClosed,
    /// The front end dropped the event receiver. Quiet shutdown.
    #[error("event receiver dropped")]
    Gone,
}

pub(crate) type Result<T> = std::result::Result<T, VncError>;

pub(crate) fn proto<T>(msg: impl Into<String>) -> Result<T> {
    Err(VncError::Protocol(msg.into()))
}

fn is_disconnect(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        e.kind(),
        K::UnexpectedEof | K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe | K::NotConnected | K::TimedOut
    )
}

impl VncError {
    /// Map to the public error. `stage` describes what we were doing (for the log the user sends
    /// back); `None` result means a clean close.
    pub(crate) fn into_session_error(self, stage: &str) -> Option<SessionError> {
        let encrypting = stage == crate::proto::STAGE_ENCRYPTION;
        let (kind, detail) = match self {
            VncError::UserClosed | VncError::Gone => return None,
            // The record layer reports integrity failures and malformed records as I/O errors
            // carrying a RecordError; they are a security problem, not a dropped line.
            VncError::Io(e) if e.get_ref().is_some_and(|i| i.is::<crate::record::RecordError>()) => (
                ErrorKind::Security,
                format!(
                    "the encrypted session failed during {stage}: {e}. The data was corrupted or tampered \
                     with on the way, or the two sides disagree about the protocol; the session was closed"
                ),
            ),
            VncError::Io(e) if encrypting => (
                ErrorKind::Security,
                if is_disconnect(&e) {
                    format!("the session could not be encrypted: the Mac closed the connection while setting up encryption ({e})")
                } else {
                    format!("the session could not be encrypted: I/O error while setting up encryption ({e})")
                },
            ),
            VncError::Protocol(m) | VncError::Other(m) if encrypting => {
                (ErrorKind::Security, format!("the session could not be encrypted: {m}"))
            }
            VncError::Security(m) if encrypting => {
                (ErrorKind::Security, format!("the session could not be encrypted: {m}"))
            }
            VncError::Security(m) => (ErrorKind::Security, m),
            VncError::Io(e) => {
                if stage == crate::proto::STAGE_AUTH_RESULT && is_disconnect(&e) {
                    (
                        ErrorKind::AuthFailed,
                        format!(
                            "the server closed the connection instead of sending an authentication result ({e}); \
                             this usually means the credentials were rejected or the account may not log in remotely"
                        ),
                    )
                } else if is_disconnect(&e) {
                    (ErrorKind::Disconnected, format!("connection lost during {stage}: {e}"))
                } else {
                    (ErrorKind::Disconnected, format!("I/O error during {stage}: {e}"))
                }
            }
            VncError::Protocol(m) => (ErrorKind::Protocol, format!("{m} (during {stage})")),
            VncError::Auth(m) => (ErrorKind::AuthFailed, m),
            VncError::Unsupported(m) => (ErrorKind::Unsupported, m),
            VncError::Other(m) => (ErrorKind::Other, format!("{m} (during {stage})")),
        };
        Some(SessionError::new(kind, detail))
    }
}
