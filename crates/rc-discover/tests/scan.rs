//! The scanner against in-process servers on the loopback interface. No real network is touched:
//! every probe goes to 127.0.0.0/8.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ironrdp_server::{
    DesktopSize, DisplayUpdate, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler, TlsIdentityCtx,
};
use rc_discover::{CancelToken, Host, HostKind, HostTarget, Ports, ScanEvent, ScanOptions, ScanSummary, TailscaleLabel};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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

/// A TCP server that accepts every connection and holds it open without a word, like a proxy or
/// firewall answering for every address.
async fn silent_holder() -> u16 {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                drop(stream);
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

/// What a fake SMB server received from each client: the messages, in order.
type SmbLog = Arc<Mutex<Vec<Vec<Vec<u8>>>>>;

/// A fake SMB server: answers NEGOTIATE and SESSION_SETUP with an NTLM challenge naming
/// STUDIO-MAC / Studio-Mac.local, then records anything else the client sends until it closes.
async fn smb_server() -> (u16, SmbLog) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: SmbLog = Arc::default();
    let server_log = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let log = Arc::clone(&server_log);
            tokio::spawn(async move {
                let (negotiate, setup) = rc_discover::smb::sample_responses("STUDIO-MAC", "Studio-Mac.local");
                let mut received = Vec::new();
                for reply in [Some(negotiate), Some(setup), None, None] {
                    let mut frame = [0u8; 4];
                    if stream.read_exact(&mut frame).await.is_err() {
                        break;
                    }
                    let length = usize::from(frame[1]) << 16 | usize::from(frame[2]) << 8 | usize::from(frame[3]);
                    let mut message = vec![0u8; length.min(65536)];
                    if stream.read_exact(&mut message).await.is_err() {
                        break;
                    }
                    received.push(message);
                    if let Some(reply) = reply {
                        let _ = stream.write_all(&reply).await;
                    }
                }
                log.lock().unwrap().push(received);
            });
        }
    });
    (port, log)
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
    let (hosts, finished, _) = run_scan_summary(targets, options, cancel).await;
    (hosts, finished)
}

async fn run_scan_summary(
    targets: Vec<Ipv4Addr>,
    options: ScanOptions,
    cancel: CancelToken,
) -> (Vec<Host>, ScanEvent, ScanSummary) {
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
    let summary = scan.await.unwrap();
    (hosts, last.expect("a Finished event"), summary)
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
    let (smb, _) = smb_server().await;
    let ports = Ports { rdp, vnc, ssh, mdns, netbios, smb };

    let mut targets = vec![LOCAL];
    // Linux routes all of 127.0.0.0/8 to the loopback interface; nothing listens on these.
    if cfg!(target_os = "linux") {
        targets.extend([Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)]);
    }
    let total = targets.len();
    let (hosts, finished) = run_scan(targets, quiet_options(ports), CancelToken::default()).await;
    assert_eq!(finished, ScanEvent::Finished { cancelled: false, too_many: false, done: total, total, found: 1 });
    assert_eq!(hosts.len(), 1, "{hosts:?}");
    let host = &hosts[0];
    assert_eq!(host.ip, "127.0.0.1");
    assert_eq!((host.rdp, host.vnc, host.ssh), (Some(rdp), Some(vnc), Some(ssh)));
    assert_eq!(host.name.as_deref(), Some(CN), "the certificate name comes first");
    assert_eq!(host.names.rdp_certificate.as_deref(), Some(CN));
    assert_eq!(host.names.mdns_host.as_deref(), Some("Studio-Mac.local"));
    assert_eq!(host.names.mdns_name.as_deref(), Some("Studio Mac"));
    assert_eq!(host.names.netbios.as_deref(), Some("DESKTOP-TEST01"));
    assert_eq!(host.names.smb.as_deref(), Some("Studio-Mac.local"));
    assert_eq!(host.names.dns, None);
    assert_eq!(host.model.as_deref(), Some("Mac14,3"));
    assert_eq!(host.rfb_version.as_deref(), Some("003.889"));
    assert_eq!(host.ssh_banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
    assert_eq!(host.rdp_certificate_sha256.as_deref(), Some(sha256_hex(&der).as_str()));
    assert_eq!(host.kind, HostKind::Mac, "an Apple RFB greeting wins");
}

#[tokio::test]
async fn host_list_scan_carries_tailscale_names() {
    let ssh = greeter(b"SSH-2.0-OpenSSH_9.6\r\n").await;
    let free = || std::net::TcpListener::bind((LOCAL, 0)).unwrap().local_addr().unwrap().port();
    let ports = Ports { rdp: free(), vnc: free(), ssh, mdns: free(), netbios: free(), smb: free() };
    let label = TailscaleLabel {
        name: Some("studio-mac".into()),
        dns_name: Some("studio-mac.example.ts.net".into()),
        os: Some("macOS".into()),
    };
    let mut hosts = vec![
        HostTarget { ip: LOCAL, tailscale: Some(label.clone()) },
        HostTarget { ip: LOCAL, tailscale: None }, // a duplicate: the first is kept
    ];
    if cfg!(target_os = "linux") {
        hosts.push(HostTarget { ip: Ipv4Addr::new(127, 0, 0, 2), tailscale: None });
    }
    let hosts = rc_discover::host_targets(hosts).unwrap();
    let total = hosts.len();
    let options = options_without_lookups(ports);
    let (tx, mut rx) = mpsc::channel(64);
    let scan = tokio::spawn(rc_discover::scan_hosts(hosts, options, CancelToken::default(), tx));
    let mut found = Vec::new();
    let mut last = None;
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::Host { host } => found.push(*host),
            finished @ ScanEvent::Finished { .. } => last = Some(finished),
            ScanEvent::Progress { .. } => {}
        }
    }
    scan.await.unwrap();
    assert_eq!(last, Some(ScanEvent::Finished { cancelled: false, too_many: false, done: total, total, found: 1 }));
    assert_eq!(found.len(), 1);
    let host = &found[0];
    assert_eq!((host.ip.as_str(), host.ssh, host.name.as_deref()), ("127.0.0.1", Some(ssh), None));
    assert_eq!(host.kind, HostKind::Mac, "classified by the Tailscale OS");
    let json = serde_json::to_value(ScanEvent::Host { host: Box::new(host.clone()) }).unwrap();
    assert_eq!(json["host"]["tailscaleName"], "studio-mac");
    assert_eq!(json["host"]["tailscaleDnsName"], "studio-mac.example.ts.net");
    assert_eq!(json["host"]["tailscaleOs"], "macOS");
    assert_eq!(json["host"]["kind"], "mac");

    // A subnet scan of the same machine has no Tailscale fields at all.
    let (plain, _) = run_scan(vec![LOCAL], options_without_lookups(ports), CancelToken::default()).await;
    let json = serde_json::to_value(&plain[0]).unwrap();
    assert!(json.get("tailscaleName").is_none() && json.get("tailscaleOs").is_none() && json.get("tailscaleDnsName").is_none());
    assert_eq!(plain[0].kind, HostKind::Unknown);
}

fn options_without_lookups(ports: Ports) -> ScanOptions {
    ScanOptions { netbios: false, smb: false, mdns: false, ..quiet_options(ports) }
}

#[test]
fn host_lists_are_capped() {
    let many: Vec<HostTarget> = (0..=rc_discover::MAX_HOST_LIST as u32)
        .map(|i| HostTarget { ip: Ipv4Addr::from(0x6440_0000 + i), tailscale: None })
        .collect();
    assert!(rc_discover::host_targets(many.clone()).unwrap_err().contains("at most"));
    assert_eq!(rc_discover::host_targets(many[..rc_discover::MAX_HOST_LIST].to_vec()).unwrap().len(), rc_discover::MAX_HOST_LIST);
}

#[tokio::test]
async fn closed_ports_find_nothing() {
    // Free ports, then closed again.
    let free = || std::net::TcpListener::bind((LOCAL, 0)).unwrap().local_addr().unwrap().port();
    let ports = Ports { rdp: free(), vnc: free(), ssh: free(), mdns: free(), netbios: free(), smb: free() };
    let (hosts, finished) = run_scan(vec![LOCAL], quiet_options(ports), CancelToken::default()).await;
    assert!(hosts.is_empty());
    assert_eq!(finished, ScanEvent::Finished { cancelled: false, too_many: false, done: 1, total: 1, found: 0 });
}

#[tokio::test]
async fn cancel_stops_the_scan_and_the_rate_cap_holds() {
    let vnc = greeter(b"RFB 003.008\n").await;
    let ports = Ports { rdp: vnc, vnc, ssh: vnc, ..Ports::default() };
    let options = ScanOptions { max_probes_per_sec: 60, mdns: false, netbios: false, smb: false, ..quiet_options(ports) };
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

/// Small limits so the test is quick: 2 hosts probed and 2 described at once.
fn tight_options(ports: Ports) -> ScanOptions {
    ScanOptions {
        max_in_flight: 6,
        max_name_lookups: 2,
        max_probes_per_sec: 100_000,
        name_timeout: Duration::from_millis(150),
        mdns: false,
        netbios: false,
        ..quiet_options(ports)
    }
}

#[tokio::test]
async fn open_sockets_stay_bounded_when_everything_answers() {
    let a = silent_holder().await;
    let b = silent_holder().await;
    // SMB answers too (and says nothing), so each described host holds a fourth socket.
    let ports = Ports { rdp: a, vnc: b, ssh: a, smb: b, ..Ports::default() };
    let options = tight_options(ports);
    let bound = rc_discover::socket_bound(&options);
    assert_eq!(bound, 3 * 2 + 4 * 2);

    let count = 40;
    let (hosts, finished, summary) = run_scan_summary(vec![LOCAL; count], options, CancelToken::default()).await;
    assert_eq!(hosts.len(), count);
    let ScanEvent::Finished { too_many, found, .. } = finished else { unreachable!() };
    assert!(!too_many);
    assert_eq!(found, count);
    assert_eq!(summary.described, count);
    assert!(summary.peak_sockets > 0);
    assert!(summary.peak_sockets <= bound, "the scan held {} sockets; the bound is {bound}", summary.peak_sockets);
}

#[tokio::test]
async fn too_many_answers_stop_the_scan_and_cap_the_lookups() {
    let port = silent_holder().await;
    let ports = Ports { rdp: port, vnc: port, ssh: port, smb: port, ..Ports::default() };
    let options = ScanOptions { max_described_hosts: 3, max_reported_hosts: 10, ..tight_options(ports) };
    let bound = rc_discover::socket_bound(&options);
    let (hosts, finished, summary) = run_scan_summary(vec![LOCAL; 200], options, CancelToken::default()).await;
    let ScanEvent::Finished { cancelled, too_many, done, found, .. } = finished else { unreachable!() };
    assert!(too_many, "the scan stopped itself");
    assert!(!cancelled);
    assert!(done < 200, "stopped early, after {done}");
    assert_eq!(found, 10, "found is capped at the report limit");
    assert!(hosts.len() <= 10, "{} hosts reported", hosts.len());
    assert!(summary.too_many);
    assert!(summary.described <= 3, "{} hosts described", summary.described);
    // Machines past the lookup cap still show their open ports.
    assert!(hosts.iter().all(|h| h.rdp == Some(port)));
    assert!(summary.peak_sockets <= bound);
}

#[tokio::test]
async fn reads_the_smb_computer_name_without_signing_in() {
    let (port, log) = smb_server().await;
    let tcp = tokio::net::TcpStream::connect((LOCAL, port)).await.unwrap();
    let names = rc_discover::smb::names(tcp, Duration::from_secs(2)).await.expect("names");
    assert_eq!(names.netbios.as_deref(), Some("STUDIO-MAC"));
    assert_eq!(names.dns.as_deref(), Some("Studio-Mac.local"));
    // Wait for the server to see the connection close, then check what it was sent.
    for _ in 0..100 {
        if !log.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let sessions = log.lock().unwrap().clone();
    assert_eq!(sessions.len(), 1);
    let messages = &sessions[0];
    assert_eq!(messages.len(), 2, "NEGOTIATE and one SESSION_SETUP, then the client closed");
    let ntlm_types: Vec<u8> = messages
        .iter()
        .flat_map(|m| m.windows(9).filter(|w| &w[..8] == b"NTLMSSP\0").map(|w| w[8]).collect::<Vec<_>>())
        .collect();
    assert_eq!(ntlm_types, [1], "only an NTLM NEGOTIATE; never an AUTHENTICATE (type 3)");
}

#[tokio::test]
async fn a_non_smb_server_gives_no_names_quickly() {
    let port = greeter(b"SSH-2.0-OpenSSH_9.6\r\n").await;
    let tcp = tokio::net::TcpStream::connect((LOCAL, port)).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(rc_discover::smb::names(tcp, Duration::from_secs(2)).await, None);
    assert!(started.elapsed() < Duration::from_secs(3));
    // A server that never answers: the time box ends it.
    let silent = silent_holder().await;
    let tcp = tokio::net::TcpStream::connect((LOCAL, silent)).await.unwrap();
    assert_eq!(rc_discover::smb::names(tcp, Duration::from_millis(200)).await, None);
}
