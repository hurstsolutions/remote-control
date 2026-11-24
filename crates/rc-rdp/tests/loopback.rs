//! End-to-end tests against an in-process IronRDP server on the loopback interface.
//!
//! The server shows a synthetic picture (left half red, right half blue) and records the input it
//! receives, so these tests cover TLS, certificate pinning, NLA sign-in, frame decoding (including
//! colour channel order) and input encoding without any real remote-desktop host.
//!
//! Further down, hand-rolled mock servers play a man in the middle: one that presents the real
//! certificate without holding its key, and one that tries to talk the client out of NLA.

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
        password: password.to_owned().into(),
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
    /// (encrypted, server_verified, method) of every Security event.
    security: Vec<(bool, bool, String)>,
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
            SessionEvent::Security { encrypted, server_verified, method } => {
                assert!(seen.connected.is_none(), "security is reported before Connected");
                seen.security.push((encrypted, server_verified, method));
            }
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
    // First use: encrypted, but nothing pinned to check the certificate against.
    assert_eq!(seen.security, [(true, false, "TLS".to_owned())]);
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
    assert_eq!(seen.security, [(true, false, "TLS + NLA".to_owned())]);
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
    assert!(seen.security.is_empty(), "no security is claimed for a rejected certificate");
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
    // The pin matched: the server is verified.
    assert_eq!(seen.security, [(true, true, "TLS".to_owned())]);
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

// ── Hostile servers ──────────────────────────────────────────────────────────

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme, SupportedProtocolVersion,
};

/// X.224 Connection Confirm with RDP_NEG_RSP selecting PROTOCOL_SSL (TLS without CredSSP).
const CONFIRM_SSL: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
];
/// The same, selecting PROTOCOL_HYBRID (CredSSP), as a Windows PC with NLA does.
const CONFIRM_HYBRID: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
];

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// An RSA key that only signs with PKCS#1 v1.5, like many Windows TLS 1.2 stacks.
#[derive(Debug)]
struct Pkcs1Only(Arc<dyn SigningKey>);

impl SigningKey for Pkcs1Only {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let pkcs1: Vec<_> = offered
            .iter()
            .copied()
            .filter(|s| {
                matches!(
                    s,
                    SignatureScheme::RSA_PKCS1_SHA256 | SignatureScheme::RSA_PKCS1_SHA384 | SignatureScheme::RSA_PKCS1_SHA512
                )
            })
            .collect();
        self.0.choose_scheme(&pkcs1)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

fn server_config(
    versions: &[&'static SupportedProtocolVersion],
    cert: CertificateDer<'static>,
    signer: Arc<dyn SigningKey>,
) -> Arc<rustls::ServerConfig> {
    let key = Arc::new(CertifiedKey::new(vec![cert], signer));
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(key)));
    Arc::new(config)
}

fn load_key(pkcs8: Vec<u8>) -> Arc<dyn SigningKey> {
    provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)))
        .unwrap()
}

/// What a mock server saw.
#[derive(Debug, Default)]
struct MockLog {
    tls_ok: bool,
    /// Bytes received after the Connection Confirm (decrypted, when TLS was established).
    after_confirm: Vec<u8>,
}

/// One-shot mock: answer the X.224 Connection Request with `confirm`, then either accept TLS with
/// `tls` or just listen, and record what the client sends next.
fn start_mock(confirm: [u8; 19], tls: Option<Arc<rustls::ServerConfig>>) -> (u16, tokio::task::JoinHandle<MockLog>) {
    start_mock_with(confirm.to_vec(), tls)
}

/// [`start_mock`] with arbitrary bytes for the Connection Confirm (sent in one write).
fn start_mock_with(confirm: Vec<u8>, tls: Option<Arc<rustls::ServerConfig>>) -> (u16, tokio::task::JoinHandle<MockLog>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut log = MockLog::default();
        let mut tpkt = [0u8; 4];
        tcp.read_exact(&mut tpkt).await.unwrap();
        let mut rest = vec![0u8; usize::from(u16::from_be_bytes([tpkt[2], tpkt[3]])) - 4];
        tcp.read_exact(&mut rest).await.unwrap();
        tcp.write_all(&confirm).await.unwrap();

        let mut buf = [0u8; 4096];
        let read = |n: std::io::Result<usize>| n.unwrap_or(0);
        match tls {
            Some(config) => {
                let accepted = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio_rustls::TlsAcceptor::from(config).accept(tcp),
                )
                .await;
                if let Ok(Ok(mut stream)) = accepted {
                    log.tls_ok = true;
                    if let Ok(n) = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                        log.after_confirm.extend_from_slice(&buf[..read(n)]);
                    }
                }
            }
            None => loop {
                match tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => log.after_confirm.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            },
        }
        log
    });
    (port, task)
}

async fn run_to_close(cfg: RdpConfig) -> Seen {
    let (io, mut handle) = session_channels();
    rc_rdp::spawn(cfg, io).unwrap();
    let mut seen = Seen::default();
    collect(&mut handle, &mut seen, Duration::from_secs(20), |_| false).await;
    seen
}

/// A man in the middle presents the PC's real certificate (public) but signs the handshake with
/// its own key. The pin matches, so only the handshake signature check stops it.
async fn mitm_with_real_certificate_is_rejected(version: &'static SupportedProtocolVersion) {
    let real = rcgen::generate_simple_self_signed(vec!["windows-pc".to_owned()]).unwrap();
    let real_der = real.cert.der().clone();
    let attacker = rcgen::KeyPair::generate().unwrap();
    let config = server_config(&[version], real_der.clone(), load_key(attacker.serialize_der()));
    let (port, mock) = start_mock(CONFIRM_HYBRID, Some(config));

    let mut cfg = config_for(port, true);
    cfg.pinned_cert_sha256 = Some(sha256_hex(&real_der));
    let seen = run_to_close(cfg).await;

    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::Security, "detail: {}", error.detail);
    assert!(seen.identity.is_none(), "an unproven certificate must not be reported as the server identity");
    let log = mock.await.unwrap();
    assert!(!log.tls_ok, "the client must abort the TLS handshake");
    assert!(log.after_confirm.is_empty(), "nothing may be sent to the impostor");
}

#[tokio::test(flavor = "multi_thread")]
async fn mitm_with_real_certificate_but_wrong_key_is_rejected_tls12() {
    mitm_with_real_certificate_is_rejected(&rustls::version::TLS12).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mitm_with_real_certificate_but_wrong_key_is_rejected_tls13() {
    mitm_with_real_certificate_is_rejected(&rustls::version::TLS13).await;
}

fn config_for(port: u16, nla: bool) -> RdpConfig {
    config(port, PASS, nla)
}

/// A Windows-like server: self-signed 2048-bit RSA certificate, holding its key. The handshake
/// must succeed and CredSSP must start.
async fn rsa_server_is_accepted(version: &'static SupportedProtocolVersion, pkcs1_only: bool) {
    use aws_lc_rs::encoding::AsDer as _;
    let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let pkcs8 = rsa.as_der().unwrap().as_ref().to_vec();
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.clone()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let cert = rcgen::CertificateParams::new(vec!["windows-pc".to_owned()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let der = cert.der().clone();
    let mut signer = load_key(pkcs8);
    if pkcs1_only {
        signer = Arc::new(Pkcs1Only(signer));
    }
    let (port, mock) = start_mock(CONFIRM_HYBRID, Some(server_config(&[version], der.clone(), signer)));

    let mut cfg = config_for(port, true);
    cfg.pinned_cert_sha256 = Some(sha256_hex(&der));
    let seen = run_to_close(cfg).await;

    let log = mock.await.unwrap();
    assert!(log.tls_ok, "TLS handshake must succeed; client said {:?}", seen.closed);
    assert_eq!(seen.identity, Some(sha256_hex(&der)), "accepted certificate is reported");
    // CredSSP's first message (TSRequest, a DER SEQUENCE carrying NTLM NEGOTIATE) follows.
    assert_eq!(log.after_confirm.first(), Some(&0x30), "CredSSP must start: {:?}", log.after_confirm);
}

#[tokio::test(flavor = "multi_thread")]
async fn rsa_tls12_pkcs1_server_is_accepted() {
    rsa_server_is_accepted(&rustls::version::TLS12, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rsa_tls12_pss_server_is_accepted() {
    rsa_server_is_accepted(&rustls::version::TLS12, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rsa_tls13_server_is_accepted() {
    rsa_server_is_accepted(&rustls::version::TLS13, false).await;
}

/// A man in the middle answers the Connection Request with PROTOCOL_SSL to skip CredSSP, so the
/// password would travel in the Client Info PDU. With NLA on, the client must refuse at once.
#[tokio::test(flavor = "multi_thread")]
async fn nla_downgrade_to_plain_tls_is_refused() {
    let (port, mock) = start_mock(CONFIRM_SSL, None);
    let seen = run_to_close(config_for(port, true)).await;

    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::Security, "detail: {}", error.detail);
    assert!(error.detail.contains("Network Level Authentication"), "detail: {}", error.detail);
    assert!(seen.connected.is_none());
    let log = mock.await.unwrap();
    // Not even a TLS ClientHello, let alone credentials or a Client Info PDU.
    assert!(log.after_confirm.is_empty(), "client sent {} bytes after the downgrade", log.after_confirm.len());
}

/// Security audit round 2: bytes after the Connection Confirm, before TLS, are cleartext a man in
/// the middle could inject; they used to be fed into the TLS-protected stream. Refused now.
#[tokio::test(flavor = "multi_thread")]
async fn cleartext_after_connection_confirm_is_refused() {
    let real = rcgen::generate_simple_self_signed(vec!["windows-pc".to_owned()]).unwrap();
    let der = real.cert.der().clone();
    let tls = server_config(&[&rustls::version::TLS13], der.clone(), load_key(real.signing_key.serialize_der()));
    let mut confirm = CONFIRM_HYBRID.to_vec();
    // An injected X.224 data TPKT right behind the Confirm, in the same TCP segment.
    confirm.extend_from_slice(&[3, 0, 0, 9, 2, 0xf0, 0x80, 0x7f, 0x65]);
    let (port, mock) = start_mock_with(confirm, Some(tls));
    let mut cfg = config_for(port, true);
    cfg.pinned_cert_sha256 = Some(sha256_hex(&der));
    let seen = run_to_close(cfg).await;

    let error = seen.closed.expect("session must close").expect("with an error");
    assert_eq!(error.kind, ErrorKind::Security, "detail: {}", error.detail);
    assert!(error.detail.contains("cleartext"), "detail: {}", error.detail);
    assert!(seen.connected.is_none());
    let log = mock.await.unwrap();
    assert!(!log.tls_ok, "the client must not start TLS");
    assert!(log.after_confirm.is_empty(), "nothing may be sent after the injected bytes");
}
