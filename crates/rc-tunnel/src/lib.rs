//! SSH tunnel used to carry VNC to a Mac.
//!
//! macOS Screen Sharing does not encrypt the session for third-party clients, so the app connects
//! to the Mac's Remote Login (SSH) service, signs in with the same Mac account, and opens a
//! `direct-tcpip` channel to the Screen Sharing port on the Mac itself. The SSH host key is pinned
//! on first use, exactly like the RDP certificate.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rc_types::{ErrorKind, IdentityKind, SessionError};
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::keys::{Algorithm, EcdsaCurve};
use russh::{ChannelStream, Disconnect, MethodKind, Preferred};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct TunnelConfig {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    /// Wiped from memory when dropped; `open` drops its copy once signed in.
    pub password: Zeroizing<String>,
    /// Where the SSH server should connect to, from its own point of view.
    pub target_host: String,
    pub target_port: u16,
    /// Expected SHA-256 (lowercase hex) of the SSH host key. `None` = first connection. This is the
    /// same digest `ssh-keygen -lf <key>.pub` prints, which shows it as unpadded base64.
    pub pinned_host_key_sha256: Option<String>,
}

/// An open tunnel. Dropping it closes the SSH connection.
pub struct Tunnel {
    /// Byte stream to the target port; hand this to the VNC backend.
    pub stream: ChannelStream<client::Msg>,
    /// SHA-256 (lowercase hex) of the host key that was presented.
    pub host_key_sha256: String,
    /// Keeps the SSH connection alive for as long as the stream is in use.
    pub guard: TunnelGuard,
}

pub struct TunnelGuard {
    handle: client::Handle<Handler>,
}

impl TunnelGuard {
    pub async fn close(self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

struct Handler {
    pinned: Option<String>,
    seen: Arc<std::sync::Mutex<Option<String>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let fingerprint = hex(key.fingerprint(HashAlg::Sha256).as_bytes());
        info!(%fingerprint, algorithm = %key.algorithm(), "SSH host key");
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(fingerprint.clone());
        }
        Ok(match &self.pinned {
            Some(pinned) => pinned.eq_ignore_ascii_case(&fingerprint),
            None => true,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Host key algorithms we accept, strongest first. No `ssh-rsa` (SHA-1 signatures), and no
/// RSA at all: RSA support is compiled out of our russh build (default features off), and every
/// macOS release since 10.x also has Ed25519 and ECDSA host keys.
const HOST_KEY_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
];

fn preferred() -> Preferred {
    Preferred {
        key: Cow::Borrowed(HOST_KEY_ALGORITHMS),
        ..Preferred::DEFAULT
    }
}

/// Connect, verify the host key, sign in and open the forwarding channel.
pub async fn open(mut config: TunnelConfig) -> Result<Tunnel, SessionError> {
    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        preferred: preferred(),
        ..Default::default()
    });
    let seen = Arc::new(std::sync::Mutex::new(None));
    let handler = Handler {
        pinned: config.pinned_host_key_sha256.clone(),
        seen: Arc::clone(&seen),
    };

    info!(host = %config.ssh_host, port = config.ssh_port, "opening SSH tunnel");
    let socket = connect_tcp(&config.ssh_host, config.ssh_port).await?;
    let connect = client::connect_stream(ssh_config, socket, handler);
    let result = tokio::time::timeout(Duration::from_secs(10), connect).await;
    let host_key = seen.lock().ok().and_then(|s| s.clone());

    let mut handle = match result {
        Err(_) => {
            return Err(SessionError::new(
                ErrorKind::Unreachable,
                format!(
                    "SSH (Remote Login) at {}:{} accepted the connection but did not answer within 10 s",
                    config.ssh_host, config.ssh_port
                ),
            ))
        }
        Ok(Err(error)) => {
            // A rejected host key surfaces as a generic key-exchange error; tell the two apart.
            if let (Some(pinned), Some(got)) = (&config.pinned_host_key_sha256, &host_key) {
                if !pinned.eq_ignore_ascii_case(got) {
                    return Err(SessionError::identity_changed(
                        IdentityKind::SshHostKey,
                        pinned.as_str(),
                        got.as_str(),
                        format!(
                            "the Mac's SSH host key changed (expected {pinned}, got {got}). This happens \
                             after macOS is reinstalled, but it can also mean another machine is answering \
                             at this address. No password was sent."
                        ),
                    ));
                }
            }
            let kind = match &error {
                russh::Error::IO(_) | russh::Error::ConnectionTimeout => ErrorKind::Unreachable,
                _ => ErrorKind::Protocol,
            };
            return Err(SessionError::new(
                kind,
                format!(
                    "SSH (Remote Login) connection to {}:{} failed: {error}",
                    config.ssh_host, config.ssh_port
                ),
            ));
        }
        Ok(Ok(handle)) => handle,
    };
    let host_key_sha256 = host_key.unwrap_or_default();

    authenticate(&mut handle, &config).await?;
    // Signed in: the password is not needed again. Dropping it wipes this copy.
    config.password = Zeroizing::default();

    let channel = handle
        .channel_open_direct_tcpip(config.target_host.clone(), u32::from(config.target_port), "127.0.0.1", 0)
        .await
        .map_err(|error| {
            SessionError::new(
                ErrorKind::Unreachable,
                format!(
                    "signed in over SSH, but the Mac refused to open {}:{} ({error}). Check that Screen \
                     Sharing is turned on.",
                    config.target_host, config.target_port
                ),
            )
        })?;
    info!(target = %config.target_host, port = config.target_port, "SSH tunnel open");

    Ok(Tunnel {
        stream: channel.into_stream(),
        host_key_sha256,
        guard: TunnelGuard { handle },
    })
}

/// Open the TCP connection to the SSH port. A name that does not resolve is
/// [`ErrorKind::Unreachable`]; a resolved address whose SSH port refuses or does not answer is
/// [`ErrorKind::TunnelUnavailable`], which on a Mac almost always means Remote Login is off.
async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, SessionError> {
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.collect(),
        Err(error) => {
            return Err(SessionError::new(
                ErrorKind::Unreachable,
                format!("cannot resolve {host}: {error}"),
            ))
        }
    };
    if addrs.is_empty() {
        return Err(SessionError::new(
            ErrorKind::Unreachable,
            format!("{host} did not resolve to any address"),
        ));
    }
    let socket = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addrs.as_slice())).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(error)) => {
            return Err(SessionError::new(
                ErrorKind::TunnelUnavailable,
                format!("SSH (Remote Login) connection to {host}:{port} failed: {error}"),
            ))
        }
        Err(_) => {
            return Err(SessionError::new(
                ErrorKind::TunnelUnavailable,
                format!("no answer from SSH (Remote Login) at {host}:{port} after 10 s"),
            ))
        }
    };
    if let Err(error) = socket.set_nodelay(true) {
        debug!(%error, "set_nodelay failed");
    }
    Ok(socket)
}

async fn authenticate(handle: &mut client::Handle<Handler>, config: &TunnelConfig) -> Result<(), SessionError> {
    let protocol = |error: russh::Error| SessionError::new(ErrorKind::Protocol, format!("SSH sign-in: {error}"));

    let remaining = match handle
        .authenticate_password(config.username.clone(), (*config.password).clone())
        .await
        .map_err(protocol)?
    {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };
    debug!(?remaining, "SSH password sign-in refused");

    // macOS can be set to keyboard-interactive only; answer its prompt with the same password.
    if remaining.contains(&MethodKind::KeyboardInteractive) {
        let mut response = handle
            .authenticate_keyboard_interactive_start(config.username.clone(), None)
            .await
            .map_err(protocol)?;
        for _ in 0..4 {
            match response {
                KeyboardInteractiveAuthResponse::Success => return Ok(()),
                KeyboardInteractiveAuthResponse::Failure { .. } => break,
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let answers = prompts.iter().map(|_| (*config.password).clone()).collect();
                    response = handle
                        .authenticate_keyboard_interactive_respond(answers)
                        .await
                        .map_err(protocol)?;
                }
            }
        }
    }

    warn!("SSH sign-in failed");
    Err(SessionError::new(
        ErrorKind::AuthFailed,
        format!(
            "the Mac rejected the username or password for SSH (Remote Login) as user \"{}\". Check that \
             Remote Login is on and allows this user.",
            config.username
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_algorithms_exclude_sha1_rsa() {
        let preferred = preferred();
        // Excludes SHA-1 `ssh-rsa`, and RSA altogether since it is compiled out of our russh build.
        assert!(!preferred.key.iter().any(|a| matches!(a, Algorithm::Rsa { .. })));
        assert_eq!(preferred.key.first(), Some(&Algorithm::Ed25519));
    }
}
