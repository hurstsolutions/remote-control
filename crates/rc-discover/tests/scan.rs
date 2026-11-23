//! The scanner against in-process servers on the loopback interface. No real network is touched:
//! every probe goes to 127.0.0.0/8.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ironrdp_server::{
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler, TlsIdentityCtx,
};
use rc_discover::{CancelToken, Host, HostKind, Ports, ScanEvent, ScanOptions};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;
const CN: &str = "DESKTOP-TEST01";

// ---- mock servers ---------------------------------------------------------------------------

/// A TCP server that sends `greeting` to every client and closes.
async fn greeter(greeting: &'static [u8]) -> u16 {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(greeting).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            });
        }
    });
    port
}

/// A UDP server that answers every datagram with `reply(request)`.
async fn udp_responder(reply: fn(&[u8]) -> Vec<u8>) -> u16 {
    let socket = UdpSocket::bind((LOCAL, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&reply(&buffer[..n]), from).await;
        }
    });
    port
}

#[derive(Clone)]
struct Handler;

impl RdpServerInputHandler for Handler {
    fn keyboard(&mut self, _event: KeyboardEvent) {}
    fn mouse(&mut self, _event: MouseEvent) {}
}

struct NoUpdates;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for NoUpdates {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for Handler {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize { width: 640, height: 480 }
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(NoUpdates))
    }
}

/// An IronRDP server whose certificate has subject CN=DESKTOP-TEST01. Returns its port and the
/// certificate (DER). `hybrid` makes it offer CredSSP as Windows does.
fn rdp_server(hybrid: bool) -> (u16, Vec<u8>) {
    let port = std::net::TcpListener::bind((LOCAL, 0)).unwrap().local_addr().unwrap().port();
    let mut params = rcgen::CertificateParams::new(vec!["desktop-test01.example".to_owned()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, CN);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();

    let dir = std::env::temp_dir().join(format!("rc-discover-test-{}-{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let identity = TlsIdentityCtx::init_from_paths(&cert_path, &key_path).unwrap();
            let acceptor = identity.make_acceptor().unwrap();
            let builder = RdpServer::builder().with_addr(SocketAddr::from((LOCAL, port)));
            let builder = if hybrid {
                builder.with_hybrid(acceptor, identity.pub_key.clone())
            } else {
                builder.with_tls(acceptor)
            };
            let mut server = builder.with_input_handler(Handler).with_display_handler(Handler).build();
            let _ = server.run().await;
        });
    });
    for _ in 0..100 {
        if std::net::TcpStream::connect((LOCAL, port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (port, der)
}

fn sha256_hex(der: &[u8]) -> String {
    rc_discover::rdp::cert_info(der).sha256
}

fn quiet_options(ports: Ports) -> ScanOptions {
    ScanOptions {
        ports,
        reverse_dns: false, // would ask the system resolver, i.e. the real network
        connect_timeout: Duration::from_millis(500),
        ..ScanOptions::default()
    }
}

async fn run_scan(targets: Vec<Ipv4Addr>, options: ScanOptions, cancel: CancelToken) -> (Vec<Host>, ScanEvent) {
    let (tx, mut rx) = mpsc::channel(64);
    let scan = tokio::spawn(rc_discover::scan(targets, options, cancel, tx));
    let mut hosts = Vec::new();
    let mut last = None;
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Host { host } => hosts.push(*host),
            finished @ ScanEvent::Finished { .. } => last = Some(finished),
            ScanEvent::Progress { done, total, .. } => assert!(done <= total),
        }
    }
    scan.await.unwrap();
    (hosts, last.expect("a Finished event"))
}

// ---- tests ----------------------------------------------------------------------------------

#[tokio::test]
async fn reads_the_computer_name_from_the_rdp_certificate() {
    for hybrid in [false, true] {
        let (port, der) = rdp_server(hybrid);
        let tcp = tokio::net::TcpStream::connect((LOCAL, port)).await.unwrap();
        let info = rc_discover::rdp::certificate(tcp, Duration::from_secs(5)).await.expect("certificate");
        assert_eq!(info.name.as_deref(), Some(CN), "hybrid {hybrid}");
        assert_eq!(info.sha256, sha256_hex(&der));
    }
}

#[tokio::test]
async fn a_non_rdp_server_gives_no_certificate_quickly() {
    let port = greeter(b"RFB 003.889\n").await;
    let tcp = tokio::net::TcpStream::connect((LOCAL, port)).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(rc_discover::rdp::certificate(tcp, Duration::from_secs(2)).await, None);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn reads_the_rfb_banner() {
    let port = greeter(b"RFB 003.889\n").await;
    let tcp = tokio::net::TcpStream::connect((LOCAL, port)).await.unwrap();
    let info = rc_discover::banner::rfb(tcp, Duration::from_secs(2)).await.unwrap();
    assert_eq!(info.version, "003.889");
    assert!(info.apple);
    // A server that says nothing: the time box ends it.
    let silent = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let tcp = tokio::net::TcpStream::connect(silent.local_addr().unwrap()).await.unwrap();
    assert_eq!(rc_discover::banner::rfb(tcp, Duration::from_millis(200)).await, None);
}

#[tokio::test]
async fn finds_services_and_names_on_loopback() {
    let (rdp, der) = rdp_server(false);
    let vnc = greeter(b"RFB 003.889\n").await;
    let ssh = greeter(b"SSH-2.0-OpenSSH_9.6\r\n").await;
    let mdns = udp_responder(|q| rc_discover::mdns::sample_reply(q, "Studio-Mac.local", "Studio Mac", "Mac14,3")).await;
    let netbios = udp_responder(|q| rc_discover::netbios::sample_reply(q, &[("DESKTOP-TEST01", 0, false)])).await;
    let ports = Ports { rdp, vnc, ssh, mdns, netbios };

    let mut targets = vec![LOCAL];
    // Linux routes all of 127.0.0.0/8 to the loopback interface; nothing listens on these.
    if cfg!(target_os = "linux") {
        targets.extend([Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)]);
    }
    let total = targets.len();
    let (hosts, finished) = run_scan(targets, quiet_options(ports), CancelToken::default()).await;
    assert_eq!(finished, ScanEvent::Finished { cancelled: false, done: total, total, found: 1 });
    assert_eq!(hosts.len(), 1, "{hosts:?}");
    let host = &hosts[0];
    assert_eq!(host.ip, "127.0.0.1");
    assert_eq!((host.rdp, host.vnc, host.ssh), (Some(rdp), Some(vnc), Some(ssh)));
    assert_eq!(host.name.as_deref(), Some(CN), "the certificate name comes first");
    assert_eq!(host.names.rdp_certificate.as_deref(), Some(CN));
    assert_eq!(host.names.mdns_host.as_deref(), Some("Studio-Mac.local"));
    assert_eq!(host.names.mdns_name.as_deref(), Some("Studio Mac"));
    assert_eq!(host.names.netbios.as_deref(), Some("DESKTOP-TEST01"));
    assert_eq!(host.names.dns, None);
    assert_eq!(host.model.as_deref(), Some("Mac14,3"));
    assert_eq!(host.rfb_version.as_deref(), Some("003.889"));
    assert_eq!(host.ssh_banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
    assert_eq!(host.rdp_certificate_sha256.as_deref(), Some(sha256_hex(&der).as_str()));
    assert_eq!(host.kind, HostKind::Mac, "an Apple RFB greeting wins");
}

#[tokio::test]
async fn closed_ports_find_nothing() {
    // Free ports, then closed again.
    let free = || std::net::TcpListener::bind((LOCAL, 0)).unwrap().local_addr().unwrap().port();
    let ports = Ports { rdp: free(), vnc: free(), ssh: free(), mdns: free(), netbios: free() };
    let (hosts, finished) = run_scan(vec![LOCAL], quiet_options(ports), CancelToken::default()).await;
    assert!(hosts.is_empty());
    assert_eq!(finished, ScanEvent::Finished { cancelled: false, done: 1, total: 1, found: 0 });
}

#[tokio::test]
async fn cancel_stops_the_scan_and_the_rate_cap_holds() {
    let vnc = greeter(b"RFB 003.008\n").await;
    let ports = Ports { rdp: vnc, vnc, ssh: vnc, ..Ports::default() };
    let options = ScanOptions { max_probes_per_sec: 60, mdns: false, netbios: false, ..quiet_options(ports) };
    let cancel = CancelToken::default();
    let canceller = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        canceller.cancel();
    });
    let started = std::time::Instant::now();
    let (hosts, finished) = run_scan(vec![LOCAL; 1000], options, cancel).await;
    assert!(started.elapsed() < Duration::from_secs(3), "cancel is prompt");
    let ScanEvent::Finished { cancelled, done, total, .. } = finished else { unreachable!() };
    assert!(cancelled);
    assert_eq!(total, 1000);
    // 60 connects per second at three per host: about 20 hosts a second, so about 10 in 0.5 s.
    assert!(done <= 20, "rate cap: {done} hosts in 0.5 s");
    assert!(hosts.len() <= done);
}
