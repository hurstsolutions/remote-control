//! Tunnel tests against an in-process SSH server on loopback that forwards `direct-tcpip`
//! channels to an in-test echo listener.

use std::sync::Arc;

use rc_tunnel::{open, TunnelConfig};
use rc_types::ErrorKind;
use russh::server::{self, Auth, Msg, Session};
use russh::Channel;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "macuser";
const PASS: &str = "s3cret pass";

struct SshHandler;

impl server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == USER && password == PASS {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Ok(mut target) = TcpStream::connect((host, port as u16)).await else {
            return Ok(false);
        };
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
        });
        Ok(true)
    }
}

/// Start the mock SSH server; returns its port.
async fn start_ssh() -> u16 {
    let key = russh::keys::PrivateKey::random(&mut rand_core::OsRng, russh::keys::Algorithm::Ed25519).unwrap();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: std::time::Duration::from_millis(10),
        auth_rejection_time_initial: Some(std::time::Duration::from_millis(0)),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, socket, SshHandler).await {
                    let _ = session.await;
                }
            });
        }
    });
    port
}

/// Start an echo listener standing in for the Screen Sharing port; returns its port.
async fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

fn config(ssh_port: u16, target_port: u16, password: &str) -> TunnelConfig {
    TunnelConfig {
        ssh_host: "127.0.0.1".into(),
        ssh_port,
        username: USER.into(),
        password: password.into(),
        target_host: "127.0.0.1".into(),
        target_port,
        pinned_host_key_sha256: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn carries_bytes_both_ways_and_reports_the_host_key() {
    let (ssh, echo) = (start_ssh().await, start_echo().await);
    let mut tunnel = open(config(ssh, echo, PASS)).await.expect("tunnel opens");
    assert_eq!(tunnel.host_key_sha256.len(), 64);

    tunnel.stream.write_all(b"RFB 003.008\n").await.unwrap();
    let mut buf = [0u8; 12];
    tunnel.stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"RFB 003.008\n");

    // The same key is accepted when pinned.
    let mut pinned = config(ssh, echo, PASS);
    pinned.pinned_host_key_sha256 = Some(tunnel.host_key_sha256.clone());
    open(pinned).await.expect("pinned key matches");
    tunnel.guard.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_is_auth_failed() {
    let (ssh, echo) = (start_ssh().await, start_echo().await);
    let error = open(config(ssh, echo, "nope")).await.err().expect("must fail");
    assert_eq!(error.kind, ErrorKind::AuthFailed, "{}", error.detail);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_host_key_is_a_security_error() {
    let (ssh, echo) = (start_ssh().await, start_echo().await);
    let mut cfg = config(ssh, echo, PASS);
    cfg.pinned_host_key_sha256 = Some("11".repeat(32));
    let error = open(cfg).await.err().expect("must fail");
    assert_eq!(error.kind, ErrorKind::Security, "{}", error.detail);
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_target_port_is_reported() {
    let ssh = start_ssh().await;
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let error = open(config(ssh, dead, PASS)).await.err().expect("must fail");
    assert_eq!(error.kind, ErrorKind::Unreachable, "{}", error.detail);
    assert!(error.detail.contains("Screen Sharing"));
}

#[tokio::test(flavor = "multi_thread")]
async fn no_ssh_server_is_unreachable() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let error = open(config(dead, 5900, PASS)).await.err().expect("must fail");
    assert_eq!(error.kind, ErrorKind::Unreachable, "{}", error.detail);
}
