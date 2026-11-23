//! Find computers on configured subnets: which addresses answer on the Remote Desktop (3389),
//! Screen Sharing / VNC (5900) and SSH / Remote Login (22) ports, plus a best-effort name.
//!
//! Probes are plain TCP connects, with bounded concurrency, a rate cap and a short timeout.
//! Nothing sent can sign in or lock out an account: name lookups read what servers announce before
//! authentication (TLS certificate, RFB / SSH greetings) or ask name services (reverse DNS,
//! unicast mDNS, NetBIOS node status). A scan result is never trusted for anything: certificate
//! fingerprints are information only and pinning happens on the first real connection.

pub mod banner;
pub mod cidr;
mod dns;
pub mod mdns;
pub mod netbios;
pub mod rdp;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;

pub use cidr::{Cidr, CidrError, MAX_SCAN_ADDRESSES, MIN_PREFIX, WARN_PREFIX};

/// Ports to probe. Tests point them at in-process listeners.
#[derive(Debug, Clone, Copy)]
pub struct Ports {
    pub rdp: u16,
    pub vnc: u16,
    pub ssh: u16,
    pub mdns: u16,
    pub netbios: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Self {
            rdp: 3389,
            vnc: 5900,
            ssh: 22,
            mdns: mdns::MDNS_PORT,
            netbios: netbios::NETBIOS_PORT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub ports: Ports,
    /// How long one TCP connect may take.
    pub connect_timeout: Duration,
    /// TCP connects in flight at once.
    pub max_in_flight: usize,
    /// New TCP connects per second, so a scan stays well below what trips most IDS rate rules.
    pub max_probes_per_sec: u32,
    /// The time box for each name lookup on a found machine.
    pub name_timeout: Duration,
    /// Found machines whose names are looked up at once.
    pub max_name_lookups: usize,
    pub reverse_dns: bool,
    pub mdns: bool,
    pub netbios: bool,
    /// Read the RDP certificate, the RFB greeting and the SSH greeting.
    pub greetings: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: Ports::default(),
            connect_timeout: Duration::from_millis(600),
            max_in_flight: 128,
            max_probes_per_sec: 500,
            name_timeout: Duration::from_millis(1500),
            max_name_lookups: 16,
            reverse_dns: true,
            mdns: true,
            netbios: true,
            greetings: true,
        }
    }
}

/// Names a machine gave, by source. Every string came from the network: untrusted, cleaned of
/// control characters and cut to a sane length, but still to be shown as plain text only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Names {
    /// Subject name of the RDP TLS certificate (usually the Windows computer name).
    pub rdp_certificate: Option<String>,
    /// Bonjour friendly name (Macs).
    pub mdns_name: Option<String>,
    /// Bonjour host name, e.g. "Studio-Mac.local".
    pub mdns_host: Option<String>,
    pub netbios: Option<String>,
    /// Reverse DNS (PTR).
    pub dns: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    Windows,
    Mac,
    Unknown,
}

/// A machine that answered on at least one port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Host {
    pub ip: String,
    /// The open ports (None when closed or filtered).
    pub rdp: Option<u16>,
    pub vnc: Option<u16>,
    pub ssh: Option<u16>,
    /// The best name we found, if any.
    pub name: Option<String>,
    pub names: Names,
    pub kind: HostKind,
    /// SHA-256 of the RDP certificate. Information only: never pinned from a scan.
    pub rdp_certificate_sha256: Option<String>,
    /// The RFB version, e.g. "003.889" (Apple).
    pub rfb_version: Option<String>,
    pub ssh_banner: Option<String>,
    /// Mac model identifier from Bonjour.
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEvent {
    Progress { done: usize, total: usize, found: usize },
    Host { host: Box<Host> },
    Finished { cancelled: bool, done: usize, total: usize, found: usize },
}

/// Stops a scan. Clones share the same state.
#[derive(Debug, Clone)]
pub struct CancelToken(Arc<watch::Sender<bool>>);

impl Default for CancelToken {
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }
}

impl CancelToken {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.0.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

/// The addresses to scan for a set of subnets: overlaps removed, order kept. Refuses more than
/// `MAX_SCAN_ADDRESSES` in total.
pub fn targets(subnets: &[Cidr]) -> Result<Vec<Ipv4Addr>, String> {
    let total: u64 = subnets.iter().map(Cidr::host_count).sum();
    if total > MAX_SCAN_ADDRESSES {
        return Err(format!(
            "Those subnets add up to {total} addresses; one scan can cover at most {MAX_SCAN_ADDRESSES}. Select fewer subnets."
        ));
    }
    let mut seen = HashSet::new();
    Ok(subnets
        .iter()
        .flat_map(Cidr::hosts)
        .filter(|ip| seen.insert(*ip))
        .collect())
}

struct Context {
    options: ScanOptions,
    done: AtomicUsize,
    found: AtomicUsize,
    names: Semaphore,
    events: mpsc::Sender<ScanEvent>,
}

/// Probe every target, sending progress and found machines on `events`, and finally one
/// `Finished`. Returns when done or soon after `cancel` fires.
pub async fn scan(targets: Vec<Ipv4Addr>, options: ScanOptions, cancel: CancelToken, events: mpsc::Sender<ScanEvent>) {
    let total = targets.len();
    // Each host costs three connects, made together.
    let host_slots = Arc::new(Semaphore::new((options.max_in_flight / 3).max(1)));
    let spacing = Duration::from_secs_f64(3.0 / f64::from(options.max_probes_per_sec.max(3)));
    let context = Arc::new(Context {
        names: Semaphore::new(options.max_name_lookups.max(1)),
        options,
        done: AtomicUsize::new(0),
        found: AtomicUsize::new(0),
        events: events.clone(),
    });
    tracing::info!(total, "scan started");

    let reporter = {
        let context = Arc::clone(&context);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let event = ScanEvent::Progress {
                    done: context.done.load(Ordering::Relaxed),
                    total,
                    found: context.found.load(Ordering::Relaxed),
                };
                if context.events.send(event).await.is_err() {
                    break;
                }
            }
        })
    };

    let mut tasks = JoinSet::new();
    let run = async {
        let mut next = Instant::now();
        for ip in targets {
            tokio::time::sleep_until(next).await;
            next = next.max(Instant::now()) + spacing;
            let Ok(permit) = Arc::clone(&host_slots).acquire_owned().await else { break };
            while tasks.try_join_next().is_some() {}
            tasks.spawn(probe_host(ip, permit, Arc::clone(&context)));
        }
        while tasks.join_next().await.is_some() {}
    };
    let cancelled = tokio::select! {
        () = run => false,
        () = cancel.cancelled() => true,
    };
    tasks.shutdown().await;
    reporter.abort();
    let (done, found) = (context.done.load(Ordering::Relaxed), context.found.load(Ordering::Relaxed));
    tracing::info!(done, total, found, cancelled, "scan finished");
    let _ = events.send(ScanEvent::Progress { done, total, found }).await;
    let _ = events.send(ScanEvent::Finished { cancelled, done, total, found }).await;
}

async fn connect(ip: Ipv4Addr, port: u16, limit: Duration) -> Option<TcpStream> {
    tokio::time::timeout(limit, TcpStream::connect(SocketAddr::from((ip, port))))
        .await
        .ok()?
        .ok()
}

async fn probe_host(ip: Ipv4Addr, permit: tokio::sync::OwnedSemaphorePermit, context: Arc<Context>) {
    let ports = context.options.ports;
    let limit = context.options.connect_timeout;
    let (rdp, vnc, ssh) = tokio::join!(connect(ip, ports.rdp, limit), connect(ip, ports.vnc, limit), connect(ip, ports.ssh, limit));
    drop(permit);
    context.done.fetch_add(1, Ordering::Relaxed);
    if rdp.is_none() && vnc.is_none() && ssh.is_none() {
        return;
    }
    context.found.fetch_add(1, Ordering::Relaxed);
    let Ok(_slot) = context.names.acquire().await else { return };
    let host = describe(ip, rdp, vnc, ssh, &context.options).await;
    let _ = context.events.send(ScanEvent::Host { host: Box::new(host) }).await;
}

/// Look up everything we can about a machine, each source time-boxed, all at once.
async fn describe(
    ip: Ipv4Addr,
    rdp: Option<TcpStream>,
    vnc: Option<TcpStream>,
    ssh: Option<TcpStream>,
    options: &ScanOptions,
) -> Host {
    let limit = options.name_timeout;
    let ports = options.ports;
    let (rdp_open, vnc_open, ssh_open) = (rdp.is_some(), vnc.is_some(), ssh.is_some());
    let greetings = options.greetings;
    let (cert, rfb, ssh_banner, dns_name, bonjour, netbios_name) = tokio::join!(
        async move { rdp::certificate(rdp.filter(|_| greetings)?, limit).await },
        async move { banner::rfb(vnc.filter(|_| greetings)?, limit).await },
        async move { banner::ssh(ssh.filter(|_| greetings)?, limit).await },
        async { if options.reverse_dns { reverse_dns(ip, limit).await } else { None } },
        async {
            if options.mdns && (vnc_open || ssh_open) {
                mdns::query(ip, ports.mdns, limit).await
            } else {
                None
            }
        },
        async {
            if options.netbios && rdp_open {
                netbios::query(ip, ports.netbios, limit).await
            } else {
                None
            }
        },
    );
    let bonjour = bonjour.unwrap_or_default();
    let names = Names {
        rdp_certificate: cert.as_ref().and_then(|c| clean(c.name.clone())),
        mdns_name: clean(bonjour.friendly_name),
        mdns_host: clean(bonjour.host_name),
        netbios: clean(netbios_name),
        dns: clean(dns_name),
    };
    let model = clean(bonjour.model);
    let apple = rfb.as_ref().is_some_and(|r| r.apple);
    let kind = if apple || names.mdns_name.is_some() || model.as_deref().is_some_and(|m| m.contains("Mac")) {
        HostKind::Mac
    } else if rdp_open {
        HostKind::Windows
    } else {
        HostKind::Unknown
    };
    let name = [&names.rdp_certificate, &names.mdns_name, &names.mdns_host, &names.netbios, &names.dns]
        .into_iter()
        .find_map(Clone::clone);
    Host {
        ip: ip.to_string(),
        rdp: rdp_open.then_some(ports.rdp),
        vnc: vnc_open.then_some(ports.vnc),
        ssh: ssh_open.then_some(ports.ssh),
        name,
        names,
        kind,
        rdp_certificate_sha256: cert.map(|c| c.sha256),
        rfb_version: rfb.map(|r| r.version),
        ssh_banner: clean(ssh_banner),
        model,
    }
}

async fn reverse_dns(ip: Ipv4Addr, limit: Duration) -> Option<String> {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = tokio::time::timeout(limit, lookup).await.ok()?.ok()??;
    // getnameinfo hands back the address itself when there is no name.
    (name != ip.to_string()).then_some(name)
}

/// Make a string from the network safe to show: no control characters, no trailing dot,
/// at most 128 characters, and None when nothing is left.
pub fn clean(text: Option<String>) -> Option<String> {
    let text: String = text?.chars().filter(|c| !c.is_control()).take(128).collect();
    let text = text.trim().trim_end_matches('.').trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Send one datagram and wait for the first reply from that address.
pub(crate) async fn udp_exchange(to: SocketAddr, message: &[u8], limit: Duration) -> Option<Vec<u8>> {
    let bind: SocketAddr = if to.ip().is_loopback() { ([127, 0, 0, 1], 0).into() } else { ([0, 0, 0, 0], 0).into() };
    let socket = UdpSocket::bind(bind).await.ok()?;
    let exchange = async {
        socket.send_to(message, to).await.ok()?;
        let mut buffer = vec![0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buffer).await.ok()?;
            if from.ip() == to.ip() {
                buffer.truncate(n);
                return Some(buffer);
            }
        }
    };
    tokio::time::timeout(limit, exchange).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_untrusted_names() {
        assert_eq!(clean(Some("pc-01.corp.example.\u{0}\u{1b}[31m".into())).as_deref(), Some("pc-01.corp.example.[31m"));
        assert_eq!(clean(Some("host.example.".into())).as_deref(), Some("host.example"));
        assert_eq!(clean(Some(" \n ".into())), None);
        assert_eq!(clean(Some("x".repeat(500))).unwrap().len(), 128);
    }

    #[test]
    fn targets_are_deduplicated_and_capped() {
        let a = Cidr::parse("10.0.0.0/30").unwrap();
        let b = Cidr::parse("10.0.0.2/32").unwrap();
        assert_eq!(targets(&[a, b]).unwrap(), [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
        let big = Cidr::parse("10.0.0.0/16").unwrap();
        assert!(targets(&[big]).is_ok());
        assert!(targets(&[big, Cidr::parse("10.1.0.0/16").unwrap()]).unwrap_err().contains("at most"));
    }

    #[test]
    fn events_use_the_ui_names() {
        let json = serde_json::to_value(ScanEvent::Progress { done: 1, total: 2, found: 0 }).unwrap();
        assert_eq!(json, serde_json::json!({ "type": "progress", "done": 1, "total": 2, "found": 0 }));
    }
}
