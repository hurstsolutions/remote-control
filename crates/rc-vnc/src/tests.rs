//! End-to-end tests against in-process mock servers over `tokio::io::duplex`.

use crate::auth::tests::MockArdServer;
use crate::{auth, decode, run_with_encodings, session, VncConfig};
use rc_types::{session_channels, CursorShape, ErrorKind, SessionEvent, SessionHandle, SessionInput};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const T: Duration = Duration::from_secs(10);

fn config(user: Option<&str>, pass: Option<&str>) -> VncConfig {
    VncConfig { username: user.map(Into::into), password: pass.map(|p| p.to_owned().into()), ..Default::default() }
}

/// Start a client; returns the server end of the pipe, the front-end handle and the task.
fn start(cfg: VncConfig) -> (DuplexStream, SessionHandle, tokio::task::JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (io, handle) = session_channels();
    let task = tokio::spawn(run_with_encodings(client, cfg, crate::VncOptions::default(), io, session::default_encodings()));
    (server, handle, task)
}

async fn next(h: &mut SessionHandle) -> SessionEvent {
    tokio::time::timeout(T, h.events.recv()).await.expect("timed out waiting for an event").expect("channel closed")
}

/// Next event that is not a Status or Security report.
async fn next_real(h: &mut SessionHandle) -> SessionEvent {
    loop {
        match next(h).await {
            SessionEvent::Status(_) | SessionEvent::Security { .. } => continue,
            ev => return ev,
        }
    }
}

async fn expect_closed(h: &mut SessionHandle) -> Option<rc_types::SessionError> {
    let error = loop {
        match next_real(h).await {
            SessionEvent::Closed { error } => break error,
            _ => continue,
        }
    };
    // Exactly one Closed, and it is the last event.
    assert!(tokio::time::timeout(T, h.events.recv()).await.unwrap().is_none());
    error
}

async fn read_n(s: &mut DuplexStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(T, s.read_exact(&mut buf)).await.expect("timed out reading from client").unwrap();
    buf
}

async fn version(s: &mut DuplexStream, server: &[u8; 12], expect_client: &[u8; 12]) {
    s.write_all(server).await.unwrap();
    assert_eq!(&read_n(s, 12).await, expect_client);
}

fn server_init(w: u16, h: u16, name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&w.to_be_bytes());
    m.extend_from_slice(&h.to_be_bytes());
    // A deliberately odd native format (16 bpp big-endian) the client must override.
    m.extend_from_slice(&[16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0]);
    m.extend_from_slice(&(name.len() as u32).to_be_bytes());
    m.extend_from_slice(name.as_bytes());
    m
}

/// Read ClientInit, send ServerInit, then read and check SetPixelFormat, SetEncodings and the
/// first (full) update request.
async fn init_phase(s: &mut DuplexStream, w: u16, h: u16, name: &str) {
    assert_eq!(read_n(s, 1).await, [1], "shared flag");
    s.write_all(&server_init(w, h, name)).await.unwrap();
    let spf = read_n(s, 20).await;
    assert_eq!(spf[..4], [0, 0, 0, 0]);
    assert_eq!(spf[4..], [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    let head = read_n(s, 4).await;
    assert_eq!(head[..2], [2, 0]);
    let n = u16::from_be_bytes([head[2], head[3]]) as usize;
    let encs: Vec<i32> =
        read_n(s, n * 4).await.chunks(4).map(|c| i32::from_be_bytes(c.try_into().unwrap())).collect();
    assert_eq!(encs, session::default_encodings());
    for e in [0, 1, 2, 5, 6, 7, 16, -239, -223, -308, -224] {
        assert!(encs.contains(&e), "encoding {e} not advertised");
    }
    let mut req = vec![3, 0, 0, 0, 0, 0];
    req.extend_from_slice(&w.to_be_bytes());
    req.extend_from_slice(&h.to_be_bytes());
    assert_eq!(read_n(s, 10).await, req, "first update request must be non-incremental and full-screen");
}

fn rect(x: u16, y: u16, w: u16, h: u16, enc: i32) -> Vec<u8> {
    let mut m = Vec::new();
    for v in [x, y, w, h] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m.extend_from_slice(&enc.to_be_bytes());
    m
}

fn fbu(nrects: u16) -> Vec<u8> {
    let mut m = vec![0, 0];
    m.extend_from_slice(&nrects.to_be_bytes());
    m
}

async fn expect_request(s: &mut DuplexStream, incremental: bool, w: u16, h: u16) {
    let mut req = vec![3, u8::from(incremental), 0, 0, 0, 0];
    req.extend_from_slice(&w.to_be_bytes());
    req.extend_from_slice(&h.to_be_bytes());
    assert_eq!(read_n(s, 10).await, req);
}

#[tokio::test]
async fn vnc_auth_handshake_and_raw_update() {
    let (mut s, mut h, task) = start(config(None, Some("secret")));

    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    s.write_all(&[2, 2, 1]).await.unwrap(); // offers VNC auth and None
    assert_eq!(read_n(&mut s, 1).await, [2], "password supplied => VNC auth preferred over None");
    let challenge: [u8; 16] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    s.write_all(&challenge).await.unwrap();
    assert_eq!(read_n(&mut s, 16).await, auth::vnc_des_response("secret", &challenge));
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, 4, 2, "Test Desktop").await;

    match next_real(&mut h).await {
        SessionEvent::Connected { width: 4, height: 2, name } => assert_eq!(name, "Test Desktop"),
        ev => panic!("unexpected {ev:?}"),
    }

    // One Raw rectangle: 2x2 at (1,0): red, green / blue, white, in wire order B,G,R,X.
    let mut m = fbu(1);
    m.extend(rect(1, 0, 2, 2, decode::ENC_RAW));
    m.extend_from_slice(&[0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0]);
    s.write_all(&m).await.unwrap();
    match next_real(&mut h).await {
        SessionEvent::Frame { x: 1, y: 0, w: 2, h: 2, rgba } => {
            assert_eq!(rgba, [255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255]);
        }
        ev => panic!("unexpected {ev:?}"),
    }
    // The client keeps asking, incrementally.
    expect_request(&mut s, true, 4, 2).await;

    // Input reaches the wire.
    h.input.send(SessionInput::PointerMove { x: 3, y: 1 }).unwrap();
    assert_eq!(read_n(&mut s, 6).await, [5, 0, 0, 3, 0, 1]);
    h.input.send(SessionInput::Key { code: "KeyA".into(), key: "a".into(), down: true }).unwrap();
    assert_eq!(read_n(&mut s, 8).await, [4, 1, 0, 0, 0, 0, 0, 0x61]);
    h.input.send(SessionInput::Refresh).unwrap();
    expect_request(&mut s, false, 4, 2).await;
    h.input.send(SessionInput::Clipboard { text: "hi".into() }).unwrap();
    assert_eq!(read_n(&mut s, 10).await, [6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);

    // Close: the held key is released, then a clean Closed.
    h.input.send(SessionInput::Close).unwrap();
    assert_eq!(read_n(&mut s, 8).await, [4, 0, 0, 0, 0, 0, 0, 0x61]);
    assert!(expect_closed(&mut h).await.is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn macos_style_ard_auth() {
    let (mut s, mut h, task) = start(config(Some("macuser"), Some("mac pass word")));

    // macOS announces 3.889; we must answer 3.8.
    version(&mut s, b"RFB 003.889\n", b"RFB 003.008\n").await;
    s.write_all(&[4, 30, 33, 36, 35]).await.unwrap();
    assert_eq!(read_n(&mut s, 1).await, [30]);

    let ard = MockArdServer::new(0x42);
    let mut m = Vec::new();
    m.extend_from_slice(&ard.generator.to_be_bytes());
    m.extend_from_slice(&(ard.key_len() as u16).to_be_bytes());
    m.extend_from_slice(&ard.prime);
    m.extend_from_slice(&ard.public_key());
    s.write_all(&m).await.unwrap();

    let response = read_n(&mut s, 128 + ard.key_len()).await;
    assert_eq!(ard.decrypt(&response), ("macuser".to_string(), "mac pass word".to_string()));
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, 8, 8, "Zoë’s MacBook Pro").await;

    match next_real(&mut h).await {
        SessionEvent::Connected { width: 8, height: 8, name } => assert_eq!(name, "Zoë’s MacBook Pro"),
        ev => panic!("unexpected {ev:?}"),
    }
    drop(s);
    let err = expect_closed(&mut h).await.expect("server vanished => error");
    assert_eq!(err.kind, ErrorKind::Disconnected);
    task.await.unwrap();
}

#[tokio::test]
async fn auth_failure_carries_the_servers_reason() {
    let (mut s, mut h, task) = start(config(Some("u"), Some("wrong")));
    version(&mut s, b"RFB 003.889\n", b"RFB 003.008\n").await;
    s.write_all(&[2, 30, 2]).await.unwrap();
    assert_eq!(read_n(&mut s, 1).await, [30]);
    let ard = MockArdServer::new(1);
    let mut m = vec![0, 2, 0, 128];
    m.extend_from_slice(&ard.prime);
    m.extend_from_slice(&ard.public_key());
    s.write_all(&m).await.unwrap();
    read_n(&mut s, 256).await;
    let reason = b"Invalid username or password";
    let mut m = vec![0, 0, 0, 1];
    m.extend_from_slice(&(reason.len() as u32).to_be_bytes());
    m.extend_from_slice(reason);
    s.write_all(&m).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    assert!(err.detail.contains("Invalid username or password"), "{}", err.detail);
    task.await.unwrap();
}

#[tokio::test]
async fn auth_failure_when_server_just_hangs_up() {
    let (mut s, mut h, task) = start(config(None, Some("pw")));
    version(&mut s, b"RFB 003.007\n", b"RFB 003.007\n").await;
    s.write_all(&[1, 2]).await.unwrap();
    assert_eq!(read_n(&mut s, 1).await, [2]);
    s.write_all(&[9u8; 16]).await.unwrap();
    read_n(&mut s, 16).await;
    drop(s);
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::AuthFailed, "{}", err.detail);
    task.await.unwrap();
}

#[tokio::test]
async fn auth_failure_3_7_has_no_reason() {
    let (mut s, mut h, task) = start(config(None, Some("pw")));
    version(&mut s, b"RFB 003.007\n", b"RFB 003.007\n").await;
    s.write_all(&[1, 2]).await.unwrap();
    read_n(&mut s, 1).await;
    s.write_all(&[9u8; 16]).await.unwrap();
    read_n(&mut s, 16).await;
    s.write_all(&[0, 0, 0, 1]).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    task.await.unwrap();
    drop(s);
}

#[tokio::test]
async fn unsupported_security_types_are_listed() {
    let (mut s, mut h, task) = start(config(Some("u"), Some("p")));
    version(&mut s, b"RFB 003.889\n", b"RFB 003.008\n").await;
    s.write_all(&[3, 33, 36, 35]).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::Unsupported);
    for t in ["33", "35", "36"] {
        assert!(err.detail.contains(t), "{}", err.detail);
    }
    task.await.unwrap();
}

#[tokio::test]
async fn server_refusal_with_zero_types() {
    let (mut s, mut h, task) = start(config(None, None));
    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    let reason = b"Too many security failures";
    let mut m = vec![0];
    m.extend_from_slice(&(reason.len() as u32).to_be_bytes());
    m.extend_from_slice(reason);
    s.write_all(&m).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    assert!(err.detail.contains("Too many security failures"));
    task.await.unwrap();
}

#[tokio::test]
async fn rfb_3_3_no_auth() {
    let (mut s, mut h, task) = start(config(None, None));
    version(&mut s, b"RFB 003.003\n", b"RFB 003.003\n").await;
    s.write_all(&[0, 0, 0, 1]).await.unwrap(); // server-chosen: None; no SecurityResult in 3.3
    init_phase(&mut s, 2, 2, "old").await;
    assert!(matches!(next_real(&mut h).await, SessionEvent::Connected { width: 2, height: 2, .. }));
    h.input.send(SessionInput::Close).unwrap();
    assert!(expect_closed(&mut h).await.is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn unencrypted_session_reports_its_security_once_just_before_connected() {
    let (mut s, mut h, task) = start(config(None, None));
    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    s.write_all(&[1, 1]).await.unwrap();
    assert_eq!(read_n(&mut s, 1).await, [1]);
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, 2, 2, "plain").await;
    let mut before = Vec::new();
    loop {
        match next(&mut h).await {
            SessionEvent::Connected { .. } => break,
            SessionEvent::Status(_) => {}
            ev => before.push(ev),
        }
    }
    assert_eq!(before.len(), 1, "{before:?}");
    match &before[0] {
        SessionEvent::Security { encrypted, server_verified, method } => {
            assert!(!encrypted && !server_verified);
            assert_eq!(method, crate::METHOD_UNENCRYPTED);
        }
        ev => panic!("expected a Security event, got {ev:?}"),
    }
    assert_eq!(crate::VncSecurity::from_event(&before[0]), Some(crate::VncSecurity::Unencrypted));
    h.input.send(SessionInput::Close).unwrap();
    assert!(expect_closed(&mut h).await.is_none());
    task.await.unwrap();
}

#[test]
fn security_levels_round_trip_through_their_events() {
    use crate::VncSecurity as V;
    for level in [V::Unencrypted, V::EncryptedUnverified, V::EncryptedVerified] {
        assert_eq!(V::from_event(&level.to_event()), Some(level));
    }
    let SessionEvent::Security { encrypted, server_verified, .. } = V::EncryptedVerified.to_event() else {
        panic!("not a Security event");
    };
    assert!(encrypted && server_verified);
    let SessionEvent::Security { encrypted, server_verified, .. } = V::EncryptedUnverified.to_event() else {
        panic!("not a Security event");
    };
    assert!(encrypted && !server_verified);
    // Someone else's layer, or a mismatched claim, is not a VNC level.
    assert_eq!(V::from_event(&SessionEvent::security(true, true, "SSH tunnel")), None);
    assert_eq!(V::from_event(&SessionEvent::security(true, true, crate::METHOD_ENCRYPTED_UNVERIFIED)), None);
    assert_eq!(V::from_event(&SessionEvent::Status("x".into())), None);
}

#[tokio::test]
async fn rfb_3_8_none_still_reads_security_result() {
    let (mut s, mut h, task) = start(config(None, None));
    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    s.write_all(&[1, 1]).await.unwrap();
    assert_eq!(read_n(&mut s, 1).await, [1]);
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, 2, 2, "new").await;
    assert!(matches!(next_real(&mut h).await, SessionEvent::Connected { .. }));
    // Dropping the input sender is a clean close as well.
    let SessionHandle { mut events, input } = h;
    drop(input);
    loop {
        match tokio::time::timeout(T, events.recv()).await.unwrap() {
            Some(SessionEvent::Closed { error }) => {
                assert!(error.is_none());
                break;
            }
            Some(_) => continue,
            None => panic!("no Closed event"),
        }
    }
    task.await.unwrap();
}

#[tokio::test]
async fn not_an_rfb_server() {
    let (mut s, mut h, task) = start(config(None, None));
    s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::Protocol);
    task.await.unwrap();
}

#[tokio::test]
async fn receiver_dropped_shuts_down_quietly() {
    let (mut s, h, task) = start(config(None, None));
    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    s.write_all(&[1, 1]).await.unwrap();
    read_n(&mut s, 1).await;
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, 2, 2, "x").await;
    drop(h);
    tokio::time::timeout(T, task).await.expect("client did not stop").unwrap();
}

#[tokio::test]
async fn close_during_handshake() {
    let (s, mut h, task) = start(config(None, None));
    h.input.send(SessionInput::Close).unwrap();
    assert!(expect_closed(&mut h).await.is_none());
    task.await.unwrap();
    drop(s);
}

/// Bring a no-auth 3.8 session up to the point where updates can flow.
async fn connected(w: u16, h: u16) -> (DuplexStream, SessionHandle, tokio::task::JoinHandle<()>) {
    let (mut s, mut handle, task) = start(config(None, None));
    version(&mut s, b"RFB 003.008\n", b"RFB 003.008\n").await;
    s.write_all(&[1, 1]).await.unwrap();
    read_n(&mut s, 1).await;
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    init_phase(&mut s, w, h, "mock").await;
    assert!(matches!(next_real(&mut handle).await, SessionEvent::Connected { .. }));
    (s, handle, task)
}

#[tokio::test]
async fn session_messages() {
    let (mut s, mut h, task) = connected(4, 4).await;

    // Bell and clipboard (Latin-1: 0xe9 = é).
    s.write_all(&[2]).await.unwrap();
    assert!(matches!(next_real(&mut h).await, SessionEvent::Bell));
    s.write_all(&[3, 0, 0, 0, 0, 0, 0, 4, b'c', b'a', b'f', 0xe9]).await.unwrap();
    match next_real(&mut h).await {
        SessionEvent::Clipboard(t) => assert_eq!(t, "café"),
        ev => panic!("unexpected {ev:?}"),
    }
    // A colour map message is skipped without derailing the stream.
    s.write_all(&[1, 0, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 2]).await.unwrap();
    assert!(matches!(next_real(&mut h).await, SessionEvent::Bell));

    // Update: RRE fill of the top-left 2x2 in red, then CopyRect of it to (2,2), then a cursor,
    // with the rectangle count unknown (0xFFFF) and terminated by LastRect.
    let mut m = fbu(0xffff);
    m.extend(rect(0, 0, 2, 2, decode::ENC_RRE));
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 255, 0]);
    m.extend(rect(2, 2, 2, 2, decode::ENC_COPYRECT));
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend(rect(1, 0, 2, 1, decode::ENC_CURSOR));
    m.extend_from_slice(&[255, 255, 255, 0, 0, 0, 0, 0, 0b1000_0000]);
    m.extend(rect(0, 0, 0, 0, decode::ENC_LAST_RECT));
    s.write_all(&m).await.unwrap();
    let red = [255u8, 0, 0, 255].repeat(4);
    match next_real(&mut h).await {
        SessionEvent::Frame { x: 0, y: 0, w: 2, h: 2, rgba } => assert_eq!(rgba, red),
        ev => panic!("unexpected {ev:?}"),
    }
    match next_real(&mut h).await {
        SessionEvent::Frame { x: 2, y: 2, w: 2, h: 2, rgba } => assert_eq!(rgba, red),
        ev => panic!("unexpected {ev:?}"),
    }
    match next_real(&mut h).await {
        SessionEvent::Cursor(CursorShape::Bitmap { width: 2, height: 1, hot_x: 1, hot_y: 0, rgba }) => {
            assert_eq!(rgba, [255, 255, 255, 255, 0, 0, 0, 0]);
        }
        ev => panic!("unexpected {ev:?}"),
    }
    expect_request(&mut s, true, 4, 4).await;

    // An empty cursor hides it.
    let mut m = fbu(1);
    m.extend(rect(0, 0, 0, 0, decode::ENC_CURSOR));
    s.write_all(&m).await.unwrap();
    assert!(matches!(next_real(&mut h).await, SessionEvent::Cursor(CursorShape::Hidden)));
    expect_request(&mut s, true, 4, 4).await;

    // DesktopSize: the pipelined incremental request (sent as the update starts, still for the
    // old size), Resized, then a full request for the new size.
    let mut m = fbu(1);
    m.extend(rect(0, 0, 6, 3, decode::ENC_DESKTOP_SIZE));
    s.write_all(&m).await.unwrap();
    expect_request(&mut s, true, 4, 4).await;
    assert!(matches!(next_real(&mut h).await, SessionEvent::Resized { width: 6, height: 3 }));
    expect_request(&mut s, false, 6, 3).await;

    // Resize input is ignored until the server shows ExtendedDesktopSize support...
    h.input.send(SessionInput::Resize { width: 10, height: 10 }).unwrap();
    h.input.send(SessionInput::PointerMove { x: 100, y: 100 }).unwrap();
    assert_eq!(read_n(&mut s, 6).await, [5, 0, 0, 5, 0, 2], "clamped to the new size; no SetDesktopSize before it");

    // ...which arrives as a pseudo-rect with one screen (same size => no Resized event).
    let mut m = fbu(1);
    m.extend(rect(0, 0, 6, 3, decode::ENC_EXT_DESKTOP_SIZE));
    m.extend_from_slice(&[1, 0, 0, 0]);
    m.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 6, 0, 3, 0, 0, 0, 0]);
    s.write_all(&m).await.unwrap();
    expect_request(&mut s, true, 6, 3).await;
    h.input.send(SessionInput::Resize { width: 10, height: 12 }).unwrap();
    assert_eq!(
        read_n(&mut s, 24).await,
        [251, 0, 0, 10, 0, 12, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 10, 0, 12, 0, 0, 0, 0]
    );
    // Server refuses (reason 1 = our request, status 1 = prohibited): no Resized.
    let mut m = fbu(1);
    m.extend(rect(1, 1, 10, 12, decode::ENC_EXT_DESKTOP_SIZE));
    m.extend_from_slice(&[0, 0, 0, 0]);
    s.write_all(&m).await.unwrap();
    expect_request(&mut s, true, 6, 3).await;
    // Server accepts.
    let mut m = fbu(1);
    m.extend(rect(1, 0, 10, 12, decode::ENC_EXT_DESKTOP_SIZE));
    m.extend_from_slice(&[1, 0, 0, 0]);
    m.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 10, 0, 12, 0, 0, 0, 0]);
    s.write_all(&m).await.unwrap();
    expect_request(&mut s, true, 6, 3).await;
    assert!(matches!(next_real(&mut h).await, SessionEvent::Resized { width: 10, height: 12 }));
    expect_request(&mut s, false, 10, 12).await;

    // An unknown message type ends the session with a protocol error.
    s.write_all(&[0x99]).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::Protocol);
    assert!(err.detail.contains("153"), "{}", err.detail);
    task.await.unwrap();
}

#[tokio::test]
async fn unsupported_encoding_is_a_protocol_error() {
    let (mut s, mut h, task) = connected(4, 4).await;
    let mut m = fbu(1);
    m.extend(rect(0, 0, 1, 1, 1011));
    s.write_all(&m).await.unwrap();
    let err = expect_closed(&mut h).await.unwrap();
    assert_eq!(err.kind, ErrorKind::Protocol);
    assert!(err.detail.contains("1011"), "{}", err.detail);
    task.await.unwrap();
}

#[tokio::test]
async fn large_update_is_delivered_in_bands() {
    // 1200x1000 = 1.2 M pixels > MAX_FRAME_PIXELS, so it must arrive as several Frames that
    // tile the rectangle exactly.
    let (w, h) = (1200u16, 1000u16);
    let (mut s, mut handle, task) = connected(w, h).await;
    let server = tokio::spawn(async move {
        let mut m = fbu(1);
        m.extend(rect(0, 0, w, h, decode::ENC_RAW));
        s.write_all(&m).await.unwrap();
        let row: Vec<u8> = (0..w).flat_map(|x| [(x % 256) as u8, 7, 9, 0]).collect();
        for _ in 0..h {
            s.write_all(&row).await.unwrap();
        }
        s
    });
    let mut next_row = 0u16;
    let mut frames = 0;
    while next_row < h {
        match next_real(&mut handle).await {
            SessionEvent::Frame { x: 0, y, w: fw, h: fh, rgba } => {
                assert_eq!(y, next_row);
                assert_eq!(fw, w);
                assert_eq!(rgba.len(), fw as usize * fh as usize * 4);
                assert!(rgba.len() <= 4 * 512 * 1024);
                assert_eq!(rgba[5 * 4..5 * 4 + 4], [9, 7, 5, 255]);
                next_row += fh;
                frames += 1;
            }
            ev => panic!("unexpected {ev:?}"),
        }
    }
    assert!(frames >= 3);
    let s = server.await.unwrap();
    drop(s);
    assert_eq!(expect_closed(&mut handle).await.unwrap().kind, ErrorKind::Disconnected);
    task.await.unwrap();
}

#[test]
fn encoding_override_parsing() {
    let (list, unknown) = session::parse_encodings("zrle, Hextile bogus 1000");
    assert_eq!(list, [16, 5, 1000, -239, -223, -308, -224]);
    assert_eq!(unknown, ["bogus"]);
    let (list, _) = session::parse_encodings("raw nopseudo");
    assert_eq!(list, [0]);
    let (list, _) = session::parse_encodings("tight jpeg");
    assert_eq!(list[..2], [7, -24]);
}
