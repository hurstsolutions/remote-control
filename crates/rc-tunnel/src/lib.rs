//! SSH tunnel used to carry VNC to a Mac.
//!
//! macOS Screen Sharing does not encrypt the session for third-party clients, so the app connects
//! to the Mac's Remote Login (SSH) service, signs in with the same Mac account, and opens a
//! `direct-tcpip` channel to the Screen Sharing port on the Mac itself. The SSH host key is pinned
//! on first use, exactly like the RDP certificate.

use std::sync::Arc;
use std::time::Duration;

use rc_types::{ErrorKind, SessionError};
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::{HashAlg, PublicKey};
use russh::{ChannelStream, Disconnect, MethodKind};
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct TunnelConfig {
    pub ssh_host: String,
    pub ssh_port: u16,
    pub username: String,
    pub password: String,
    /// Where the SSH server should connect to, from its own point of view.
    pub target_host: String,
    pub target_port: u16,
    /// Expected SHA-256 (lowercase hex) of the SSH host key. `None` = first connection.
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

/// Connect, verify the host key, sign in and open the forwarding channel.
pub async fn open(config: TunnelConfig) -> Result<Tunnel, SessionError> {
    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        nodelay: true,
        ..Default::default()
    });
    let seen = Arc::new(std::sync::Mutex::new(None));
    let handler = Handler {
        pinned: config.pinned_host_key_sha256.clone(),
        seen: Arc::clone(&seen),
    };

    info!(host = %config.ssh_host, port = config.ssh_port, "opening SSH tunnel");
    let connect = client::connect(ssh_config, (config.ssh_host.as_str(), config.ssh_port), handler);
    let result = tokio::time::timeout(Duration::from_secs(10), connect).await;
    let host_key = seen.lock().ok().and_then(|s| s.clone());

    let mut handle = match result {
        Err(_) => {
            return Err(SessionError::new(
                ErrorKind::Unreachable,
                format!(
                    "no answer from SSH (Remote Login) at {}:{} after 10 s",
                    config.ssh_host, config.ssh_port
                ),
            ))
        }
        Ok(Err(error)) => {
            // A rejected host key surfaces as a generic key-exchange error; tell the two apart.
            if let (Some(pinned), Some(got)) = (&config.pinned_host_key_sha256, &host_key) {
                if !pinned.eq_ignore_ascii_case(got) {
                    return Err(SessionError::new(
                        ErrorKind::Security,
                        format!(
                            "the Mac's SSH host key changed (expected {pinned}, got {got}). This happens \
                             after macOS is reinstalled, but it can also mean another machine is answering \
                             at this address."
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

async fn authenticate(handle: &mut client::Handle<Handler>, config: &TunnelConfig) -> Result<(), SessionError> {
    let protocol = |error: russh::Error| SessionError::new(ErrorKind::Protocol, format!("SSH sign-in: {error}"));

    let remaining = match handle
        .authenticate_password(config.username.clone(), config.password.clone())
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
                    let answers = prompts.iter().map(|_| config.password.clone()).collect();
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
