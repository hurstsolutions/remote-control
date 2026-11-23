//! End-to-end tests against an in-process IronRDP server on the loopback interface.
//!
//! The server shows a synthetic picture (left half red, right half blue) and records the input it
//! receives, so these tests cover TLS, certificate pinning, NLA sign-in, frame decoding (including
//! colour channel order) and input encoding without any real remote-desktop host.

use std::net::{SocketAddr, TcpListener};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironrdp_server::{
    BitmapUpdate, Credentials, DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, TlsIdentityCtx,
};
use rc_rdp::RdpConfig;
use rc_types::{session_channels, ErrorKind, MouseButton, SessionError, SessionEvent, SessionHandle, SessionInput};

const WIDTH: u16 = 640;
const HEIGHT: u16 = 480;
const USER: &str = "tester";
const PASS: &str = "correct horse";

type InputLog = Arc<Mutex<Vec<String>>>;

#[derive(Clone)]
struct Handler {
    log: InputLog,
}

impl RdpServerInputHandler for Handler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        self.log.lock().unwrap().push(format!("{event:?}"));
    }

    fn mouse(&mut self, event: MouseEvent) {
        self.log.lock().unwrap().push(format!("{event:?}"));
    }
}

struct Updates {
    sent: bool,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        // Repaint periodically: an update sent before the client finished activating is dropped.
        if self.sent {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        self.sent = true;
        let mut data = Vec::with_capacity(usize::from(WIDTH) * usize::from(HEIGHT) * 4);
        for _y in 0..HEIGHT {
            for x in 0..WIDTH {
                // BGRA: left half pure red, right half pure blue.
                if x < WIDTH / 2 {
                    data.extend_from_slice(&[0, 0, 255, 255]);
                } else {
                    data.extend_from_slice(&[255, 0, 0, 255]);
                }
            }
        }
        Ok(Some(DisplayUpdate::Bitmap(BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(WIDTH).unwrap(),
            height: NonZeroU16::new(HEIGHT).unwrap(),
            format: PixelFormat::BgrA32,
            data: data.into(),
            stride: NonZeroUsize::new(usize::from(WIDTH) * 4).unwrap(),
        })))
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for Handler {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: WIDTH, height: HEIGHT }
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Updates { sent: false }))
    }
}

struct Server {
    port: u16,
    log: InputLog,
}

/// Start a mock server on a free loopback port. `nla` selects CredSSP (as Windows requires).
fn start_server(nla: bool) -> Server {
    // Set RC_LOG=debug (or e.g. RC_LOG=ironrdp_session=trace) to see protocol logs.
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_env("RC_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
    }
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let log: InputLog = Arc::default();
    let handler = Handler { log: Arc::clone(&log) };

    let dir = std::env::temp_dir().join(format!("rc-rdp-test-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, certified.cert.pem()).unwrap();
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let identity = TlsIdentityCtx::init_from_paths(&cert_path, &key_path).unwrap();
            let acceptor = identity.make_acceptor().unwrap();
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();
            let builder = RdpServer::builder().with_addr(addr);
            let builder = if nla {
                builder.with_hybrid(acceptor, identity.pub_key.clone())
            } else {
                builder.with_tls(acceptor)
            };
            let mut server = builder
                .with_input_handler(handler.clone())
                .with_display_handler(handler)
                .build();
            server.set_credentials(Some(Credentials {
                username: USER.to_owned(),
                password: PASS.to_owned(),
                domain: None,
            }));
            let _ = server.run().await;
        });
    });

    // Wait until the listener is up.
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Server { port, log }
}

fn config(port: u16, password: &str, nla: bool) -> RdpConfig {
    RdpConfig {
        host: "127.0.0.1".to_owned(),
        port,
        username: USER.to_owned(),
        password: password.to_owned(),
        domain: None,
        width: WIDTH,
        height: HEIGHT,
        scale_factor: 100,
        pinned_cert_sha256: None,
        nla,
        clipboard: true,
    }
}

#[derive(Default)]
struct Seen {
    connected: Option<(u16, u16)>,
    identity: Option<String>,
    screen: Vec<u8>,
    frames: usize,
    closed: Option<Option<SessionError>>,
}

impl Seen {
    fn pixel(&self, x: u16, y: u16) -> [u8; 4] {
        let i = (usize::from(y) * usize::from(WIDTH) + usize::from(x)) * 4;
        self.screen[i..i + 4].try_into().unwrap()
    }
}

/// Collect events until `done` says so, the session closes, or the timeout expires.
async fn collect(handle: &mut SessionHandle, seen: &mut Seen, timeout: Duration, done: impl Fn(&Seen) -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !done(seen) && seen.closed.is_none() {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, handle.events.recv()).await else {
            return;
        };
        match event {
            SessionEvent::Connected { width, height, .. } => {
                seen.connected = Some((width, height));
                seen.screen = vec![0; usize::from(width) * usize::from(height) * 4];
            }
            SessionEvent::ServerIdentity { sha256 } => seen.identity = Some(sha256),
            SessionEvent::Frame { x, y, w, h, rgba } => {
                assert_eq!(rgba.len(), usize::from(w) * usize::from(h) * 4, "frame size must match its rectangle");
                seen.frames += 1;
                for row in 0..usize::from(h) {
                    let dst = ((usize::from(y) + row) * usize::from(WIDTH) + usize::from(x)) * 4;
                    let src = row * usize::from(w) * 4;
                    seen.screen[dst..dst + usize::from(w) * 4].copy_from_slice(&rgba[src..src + usize::from(w) * 4]);
                }
            }
            SessionEvent::Closed { error } => seen.closed = Some(error),
            _ => {}
        }
    }
}

/// The server may use a lossy codec, so allow a couple of levels of rounding per channel.
fn assert_colour(actual: [u8; 4], expected: [u8; 4], what: &str) {
    let close = actual.iter().zip(expected).all(|(a, e)| a.abs_diff(e) <= 3);
    assert!(close, "{what}: expected about {expected:?}, got {actual:?}");
}

fn painted(seen: &Seen) -> bool {
    !seen.screen.is_empty() && seen.pixel(10, 10)[3] == 255 && seen.pixel(WIDTH - 10, HEIGHT - 10)[3] == 255
}

async fn connect_and_paint(server: &Server, nla: bool) -> (SessionHandle, Seen) {
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(config(server.port, PASS, nla), io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(20), painted).await;
    assert!(seen.closed.is_none(), "session closed early: {:?}", seen.closed);
    assert_eq!(seen.connected, Some((WIDTH, HEIGHT)));
    assert!(painted(&seen), "screen was not fully painted ({} frames)", seen.frames);
    (handle, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_login_paints_correct_colours_and_sends_input() {
    let server = start_server(false);
    let (mut handle, mut seen) = connect_and_paint(&server, false).await;

    assert_eq!(seen.identity.as_ref().map(String::len), Some(64), "certificate fingerprint reported");
    assert_colour(seen.pixel(10, 10), [255, 0, 0, 255], "left half must be red (RGBA)");
    assert_colour(seen.pixel(WIDTH - 10, 10), [0, 0, 255, 255], "right half must be blue (RGBA)");

    let key = |down| SessionInput::Key { code: "KeyA".into(), key: "a".into(), down };
    handle.input.send(key(true)).unwrap();
    handle.input.send(key(false)).unwrap();
    let arrow = |down| SessionInput::Key { code: "ArrowUp".into(), key: "ArrowUp".into(), down };
    handle.input.send(arrow(true)).unwrap();
    handle.input.send(arrow(false)).unwrap();
    handle.input.send(SessionInput::PointerButton { button: MouseButton::Left, down: true, x: 100, y: 50 }).unwrap();
    handle.input.send(SessionInput::PointerButton { button: MouseButton::Left, down: false, x: 100, y: 50 }).unwrap();
    handle.input.send(SessionInput::Wheel { dx: 0.0, dy: 1.0, x: 100, y: 50 }).unwrap();

    let expect = [
        "Pressed { code: 30, extended: false }",
        "Released { code: 30, extended: false }",
        "Pressed { code: 72, extended: true }",
        "Move { x: 100, y: 50 }",
        "LeftPressed",
        "LeftReleased",
        "VerticalScroll { value: 120 }",
    ];
    let mut log = Vec::new();
    for _ in 0..100 {
        log = server.log.lock().unwrap().clone();
        if expect.iter().all(|e| log.iter().any(|l| l == e)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for e in expect {
        assert!(log.iter().any(|l| l == e), "server never saw {e}; got {log:?}");
    }

    handle.input.send(SessionInput::Close).unwrap();
    collect(&mut handle, &mut seen, Duration::from_secs(10), |_| false).await;
    assert!(matches!(seen.closed, Some(None)), "expected a clean close, got {:?}", seen.closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn nla_login_succeeds_with_the_right_password() {
    let server = start_server(true);
    let (_handle, seen) = connect_and_paint(&server, true).await;
    assert_colour(seen.pixel(10, 10), [255, 0, 0, 255], "left half");
}

#[tokio::test(flavor = "multi_thread")]
async fn nla_login_fails_with_the_wrong_password() {
    let server = start_server(true);
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(config(server.port, "wrong password", true), io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(20), |_| false).await;
    assert!(seen.connected.is_none(), "must not get a session with a wrong password");
    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::AuthFailed, "detail: {}", error.detail);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_certificate_is_rejected_before_sign_in() {
    let server = start_server(true);
    let mut cfg = config(server.port, PASS, true);
    cfg.pinned_cert_sha256 = Some("00".repeat(32));
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(cfg, io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(20), |_| false).await;
    assert!(seen.connected.is_none());
    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::IdentityChanged, "detail: {}", error.detail);
    let identity = error.identity.expect("both fingerprints come with the error");
    assert_eq!(identity.identity_kind, rc_types::IdentityKind::TlsCertificate);
    assert_eq!(identity.expected_sha256, "00".repeat(32));
    assert_eq!(identity.received_sha256.len(), 64);
    assert_ne!(identity.received_sha256, identity.expected_sha256);
    // The new identity is not reported as if it had been accepted.
    assert!(seen.identity.is_none(), "a rejected certificate must not be reported as the server identity");
}

#[tokio::test(flavor = "multi_thread")]
async fn pinned_certificate_that_matches_is_accepted() {
    let server = start_server(false);
    let (mut first_handle, mut first) = connect_and_paint(&server, false).await;
    // The mock serves one client at a time: end the first session before reconnecting.
    first_handle.input.send(SessionInput::Close).unwrap();
    collect(&mut first_handle, &mut first, Duration::from_secs(10), |_| false).await;
    let mut cfg = config(server.port, PASS, false);
    cfg.pinned_cert_sha256 = first.identity.clone();
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(cfg, io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(20), painted).await;
    assert!(painted(&seen), "closed: {:?}", seen.closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_port_reports_unreachable() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(config(port, PASS, true), io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(15), |_| false).await;
    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::Unreachable, "detail: {}", error.detail);
}
