//! The user's tailnet, as the Tailscale client already signed in on this computer sees it.
//!
//! Runs `tailscale status --json` and nothing else: from a fixed list of absolute paths (never a
//! PATH lookup, never a shell), with fixed arguments, a time limit and bounded output. Nothing is
//! stored and no API key is involved.
//!
//! The output is untrusted: other tailnet users choose their device names. Every string is cleaned
//! of control and hidden characters and cut to length, addresses must parse, and the device list
//! is capped.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::{clean, is_unsafe_char, HostTarget, TailscaleLabel};

/// At most this many devices (this computer included) are reported.
pub const MAX_DEVICES: usize = 4096;
/// More standard output than this is refused.
pub const MAX_STDOUT: usize = 4 * 1024 * 1024;
/// Standard error kept; anything beyond is read and dropped.
const MAX_STDERR: usize = 16 * 1024;
/// How long `tailscale status` may take before it is killed.
pub const TIMEOUT: Duration = Duration::from_secs(3);
/// How long one reading of `tailscale status` is reused. Several views poll it, and a connect to a
/// MagicDNS name reads it too: within this time they share one run of the client.
pub const CACHE_TTL: Duration = Duration::from_secs(3);
/// MagicDNS names of shared-in devices end in another tailnet's `<name>.ts.net`.
const TS_NET: &str = "ts.net";
/// Tags kept per device.
const MAX_TAGS: usize = 64;
/// Longest DNS name kept (the DNS limit).
const MAX_DNS_NAME: usize = 253;
/// Windows: start the console program without a console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Why the tailnet cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No Tailscale client at any of the known places.
    NotInstalled,
    /// The client is there but its service is not running, or Tailscale is turned off.
    NotRunning,
    /// Tailscale runs but nobody is signed in.
    LoggedOut,
    /// Anything else; `detail` says what.
    Error,
}

/// The `tailscale_status` answer for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleStatus {
    pub available: bool,
    pub reason: Option<Reason>,
    pub detail: Option<String>,
    /// The MagicDNS suffix, e.g. "example.ts.net" (else the tailnet's name). For display.
    pub tailnet: Option<String>,
    /// The MagicDNS suffix only ("example.ts.net"), lowercase, when the client reports a valid
    /// one. Device names must end in it (or in `.ts.net`).
    pub magic_dns_suffix: Option<String>,
    pub self_name: Option<String>,
    /// This computer first, then the others by name.
    pub devices: Vec<Device>,
}

impl TailscaleStatus {
    fn unavailable(reason: Reason, detail: Option<&str>) -> Self {
        Self {
            available: false,
            reason: Some(reason),
            detail: detail.map(str::to_owned),
            tailnet: None,
            magic_dns_suffix: None,
            self_name: None,
            devices: Vec::new(),
        }
    }
}

/// One device of the tailnet. Strings are cleaned but chosen by other people: plain text only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub name: String,
    /// MagicDNS name without the trailing dot, e.g. "studio-mac.example.ts.net". Only letters,
    /// digits, '-' and '.', so it can be used as a host name; never an IP address, and always
    /// ending in the tailnet's MagicDNS suffix or `.ts.net`.
    pub dns_name: Option<String>,
    /// As Tailscale reports it: "windows", "macOS", "linux", "iOS", "android", ...
    pub os: Option<String>,
    /// Only an address in 100.64.0.0/10.
    pub ipv4: Option<String>,
    /// Only an address in fd7a:115c:a1e0::/48. For display only; scans use IPv4.
    pub ipv6: Option<String>,
    pub online: bool,
    /// RFC 3339, or None when never seen / not reported.
    pub last_seen: Option<String>,
    pub tags: Vec<String>,
    pub is_self: bool,
}

// ── Finding and running the client ───────────────────────────────────────────

/// Where the Tailscale command line client lives on this platform.
pub fn candidate_paths() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        vec![windows_program_files().join("Tailscale").join("tailscale.exe")]
    }
    #[cfg(target_os = "macos")]
    {
        ["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"]
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        ["/usr/bin/tailscale", "/usr/sbin/tailscale", "/usr/local/bin/tailscale"].into_iter().map(PathBuf::from).collect()
    }
}

/// The Program Files folder as Windows knows it (the 64-bit one in a 64-bit process), asked of the
/// shell rather than read from the `ProgramFiles` environment variable, which any parent process
/// can set. Falls back to `%SystemDrive%\Program Files`, then `C:\Program Files`.
#[cfg(windows)]
fn windows_program_files() -> PathBuf {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: valid GUID pointer, no flags, the current user's token (null), and an out pointer the
    // shell fills with a NUL-terminated string allocated with CoTaskMemAlloc (or leaves null).
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut raw) };
    let mut found = None;
    if !raw.is_null() {
        if hr >= 0 {
            // SAFETY: on success `raw` points to a NUL-terminated UTF-16 string.
            let wide = unsafe {
                let mut len = 0usize;
                while *raw.add(len) != 0 {
                    len += 1;
                }
                std::slice::from_raw_parts(raw, len)
            };
            found = Some(PathBuf::from(std::ffi::OsString::from_wide(wide)));
        }
        // SAFETY: the buffer came from SHGetKnownFolderPath and must be freed even on failure.
        unsafe { CoTaskMemFree(raw.cast_const().cast()) };
    }
    if let Some(path) = found.filter(|p| p.is_absolute()) {
        return path;
    }
    tracing::debug!(hr, "tailscale: SHGetKnownFolderPath(ProgramFiles) failed; using the system drive");
    // Only a plain drive letter ("C:") is taken from the environment, never a network path.
    let drive = std::env::var("SystemDrive").ok().filter(|d| {
        let b = d.as_bytes();
        b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    });
    PathBuf::from(format!("{}\\Program Files", drive.as_deref().unwrap_or("C:")))
}

/// The first candidate that is an absolute path to a regular file (symbolic links followed).
pub fn find_binary(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .filter(|p| p.is_absolute())
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()))
        .cloned()
}

#[derive(Debug, Clone, Copy)]
pub struct RunLimits {
    pub timeout: Duration,
    pub max_stdout: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self { timeout: TIMEOUT, max_stdout: MAX_STDOUT }
    }
}

/// Why running the client gave no output to parse.
#[derive(Debug)]
pub enum RunError {
    Spawn(io::Error),
    TimedOut,
    TooLarge,
    /// It exited unsuccessfully; what it wrote, both streams bounded.
    Failed { stdout: Vec<u8>, stderr: String },
}

/// Run `<binary> status --json` with the limits. Ok holds standard output of a successful run.
pub async fn run_status_json(binary: &Path, limits: RunLimits) -> Result<Vec<u8>, RunError> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.start_kill();
        return Err(RunError::Spawn(io::Error::other("no pipes")));
    };
    let max_stdout = limits.max_stdout;
    let work = async {
        let (out, err) = tokio::try_join!(read_capped(stdout, max_stdout), read_dropping_excess(stderr, MAX_STDERR))?;
        let status = child.wait().await.map_err(RunError::Spawn)?;
        Ok::<_, RunError>((status, out, err))
    };
    let result = tokio::time::timeout(limits.timeout, work).await;
    let (status, stdout, stderr) = match result {
        Ok(Ok(done)) => done,
        Ok(Err(error)) => {
            let _ = child.start_kill();
            return Err(error);
        }
        Err(_) => {
            let _ = child.start_kill();
            return Err(RunError::TimedOut);
        }
    };
    if status.success() {
        Ok(stdout)
    } else {
        Err(RunError::Failed { stdout, stderr: String::from_utf8_lossy(&stderr).into_owned() })
    }
}

/// Read all of a stream, refusing more than `max` bytes.
async fn read_capped(stream: impl AsyncRead + Unpin, max: usize) -> Result<Vec<u8>, RunError> {
    let mut out = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    stream.take(limit).read_to_end(&mut out).await.map_err(RunError::Spawn)?;
    if out.len() > max {
        return Err(RunError::TooLarge);
    }
    Ok(out)
}

/// Read a stream to its end, keeping the first `max` bytes, so a chatty child never blocks.
async fn read_dropping_excess(mut stream: impl AsyncRead + Unpin, max: usize) -> Result<Vec<u8>, RunError> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = stream.read(&mut buffer).await.map_err(RunError::Spawn)?;
        if n == 0 {
            return Ok(kept);
        }
        let room = max.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..n.min(room)]);
    }
}

/// One reading of the status, reused for [`CACHE_TTL`]. Callers that arrive while it is being
/// read wait for that reading instead of starting another (single flight).
pub struct StatusCache {
    slot: tokio::sync::Mutex<Option<(Instant, TailscaleStatus)>>,
}

impl StatusCache {
    pub const fn new() -> Self {
        Self { slot: tokio::sync::Mutex::const_new(None) }
    }

    /// The cached status if it is younger than `ttl`, else the one `read` gives (then cached).
    pub async fn get<F>(&self, ttl: Duration, read: impl FnOnce() -> F) -> TailscaleStatus
    where
        F: std::future::Future<Output = TailscaleStatus>,
    {
        let mut slot = self.slot.lock().await;
        if let Some((at, status)) = slot.as_ref() {
            if at.elapsed() < ttl {
                return status.clone();
            }
        }
        let status = read().await;
        *slot = Some((Instant::now(), status.clone()));
        status
    }
}

impl Default for StatusCache {
    fn default() -> Self {
        Self::new()
    }
}

static CACHE: StatusCache = StatusCache::new();

/// The tailnet as the local Tailscale client sees it, at most [`CACHE_TTL`] old.
pub async fn status() -> TailscaleStatus {
    let candidates = candidate_paths();
    CACHE.get(CACHE_TTL, || status_with(&candidates, RunLimits::default())).await
}

/// What the last status said, for logging changes only.
type Summary = (bool, Option<Reason>, Option<String>);
static LAST_SUMMARY: Mutex<Option<Summary>> = Mutex::new(None);

/// Whether a status says something different from the last one logged (availability, reason or
/// detail). Updates the record.
fn status_changed(last: &Mutex<Option<Summary>>, status: &TailscaleStatus) -> bool {
    let summary = (status.available, status.reason, status.detail.clone());
    let mut last = last.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let changed = last.as_ref() != Some(&summary);
    *last = Some(summary);
    changed
}

/// Info when the state changes, debug otherwise: the views poll every 30 seconds.
fn log_status(status: &TailscaleStatus) {
    let changed = status_changed(&LAST_SUMMARY, status);
    match (status.available, changed) {
        (true, true) => tracing::info!(devices = status.devices.len(), "tailscale: status read"),
        (true, false) => tracing::debug!(devices = status.devices.len(), "tailscale: status read"),
        (false, true) => tracing::info!(reason = ?status.reason, detail = ?status.detail, "tailscale: not available"),
        (false, false) => tracing::debug!(reason = ?status.reason, detail = ?status.detail, "tailscale: not available"),
    }
    if status.available {
        tracing::debug!(devices = ?status.devices, "tailscale: devices");
    }
}

/// [`status`] with the candidate paths and limits given (tests). Not cached.
pub async fn status_with(candidates: &[PathBuf], limits: RunLimits) -> TailscaleStatus {
    let status = read_status(candidates, limits).await;
    log_status(&status);
    status
}

async fn read_status(candidates: &[PathBuf], limits: RunLimits) -> TailscaleStatus {
    let Some(binary) = find_binary(candidates) else {
        return TailscaleStatus::unavailable(Reason::NotInstalled, None);
    };
    match run_status_json(&binary, limits).await {
        Ok(stdout) => parse_status(&stdout)
            .unwrap_or_else(|| TailscaleStatus::unavailable(Reason::Error, Some("Tailscale gave an answer RemoteControl cannot read."))),
        // With --json the client prints the status and exits 0 whatever the state, but take
        // a readable status from a failed run too.
        Err(RunError::Failed { stdout, stderr }) => parse_status(&stdout).unwrap_or_else(|| failure_status(&stderr)),
        Err(RunError::Spawn(error)) if error.kind() == io::ErrorKind::NotFound => {
            TailscaleStatus::unavailable(Reason::NotInstalled, None)
        }
        Err(RunError::Spawn(error)) => {
            tracing::debug!(%error, binary = %binary.display(), "tailscale: cannot run the client");
            TailscaleStatus::unavailable(Reason::Error, Some("The Tailscale client could not be started."))
        }
        Err(RunError::TimedOut) => {
            TailscaleStatus::unavailable(Reason::Error, Some("Tailscale did not answer within 3 seconds."))
        }
        Err(RunError::TooLarge) => {
            TailscaleStatus::unavailable(Reason::Error, Some("Tailscale's answer was too large."))
        }
    }
}

/// A failed run that printed no status: the service is not running, or something else.
fn failure_status(stderr: &str) -> TailscaleStatus {
    let lower = stderr.to_ascii_lowercase();
    let not_running = [
        "failed to connect",
        "not running",
        "is tailscale running",
        "tailscaled.sock",
        "connection refused",
        "cannot find the file",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if not_running {
        return TailscaleStatus::unavailable(Reason::NotRunning, None);
    }
    let first_line = stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    let detail: String = first_line.chars().filter(|c| !is_unsafe_char(*c)).take(200).collect();
    tracing::debug!(stderr = %detail, "tailscale: status failed");
    let detail = if detail.is_empty() { "Tailscale reported an error.".to_owned() } else { detail };
    TailscaleStatus::unavailable(Reason::Error, Some(&detail))
}

// ── Parsing ──────────────────────────────────────────────────────────────────

/// A field of the wrong type reads as its default instead of failing the whole status.
fn lenient<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(T::deserialize(value).unwrap_or_default())
}

/// The parts of `ipnstate.Status` used here (tailscale/tailscale, ipn/ipnstate/ipnstate.go).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawStatus {
    #[serde(rename = "BackendState", deserialize_with = "lenient")]
    backend_state: String,
    #[serde(rename = "Self", deserialize_with = "lenient")]
    self_: Option<RawPeer>,
    #[serde(rename = "Peer", deserialize_with = "lenient")]
    peer: Option<BTreeMap<String, serde_json::Value>>,
    /// Deprecated in favour of CurrentTailnet.MagicDNSSuffix, still sent.
    #[serde(rename = "MagicDNSSuffix", deserialize_with = "lenient")]
    magic_dns_suffix: String,
    #[serde(rename = "CurrentTailnet", deserialize_with = "lenient")]
    current_tailnet: Option<RawTailnet>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawTailnet {
    #[serde(rename = "Name", deserialize_with = "lenient")]
    name: String,
    #[serde(rename = "MagicDNSSuffix", deserialize_with = "lenient")]
    magic_dns_suffix: String,
}

/// The parts of `ipnstate.PeerStatus` used here.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawPeer {
    #[serde(rename = "ID", deserialize_with = "lenient")]
    id: String,
    #[serde(rename = "HostName", deserialize_with = "lenient")]
    host_name: String,
    #[serde(rename = "DNSName", deserialize_with = "lenient")]
    dns_name: String,
    #[serde(rename = "OS", deserialize_with = "lenient")]
    os: String,
    #[serde(rename = "TailscaleIPs", deserialize_with = "lenient")]
    tailscale_ips: Option<Vec<serde_json::Value>>,
    #[serde(rename = "Online", deserialize_with = "lenient")]
    online: bool,
    #[serde(rename = "LastSeen", deserialize_with = "lenient")]
    last_seen: String,
    #[serde(rename = "Tags", deserialize_with = "lenient")]
    tags: Option<Vec<serde_json::Value>>,
}

/// Turn `tailscale status --json` output into the UI's status. None when it is not a JSON object.
pub fn parse_status(json: &[u8]) -> Option<TailscaleStatus> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    if !value.is_object() {
        return None;
    }
    let raw = RawStatus::deserialize(value).ok()?;
    match raw.backend_state.as_str() {
        "NeedsLogin" | "NoState" => return Some(TailscaleStatus::unavailable(Reason::LoggedOut, None)),
        "Stopped" => {
            return Some(TailscaleStatus::unavailable(Reason::NotRunning, Some("Tailscale is turned off on this computer.")))
        }
        "NeedsMachineAuth" => {
            return Some(TailscaleStatus::unavailable(
                Reason::Error,
                Some("This computer is waiting for a tailnet admin to approve it."),
            ))
        }
        _ => {}
    }
    let reported_suffix = raw
        .current_tailnet
        .as_ref()
        .map(|t| t.magic_dns_suffix.clone())
        .and_then(non_empty)
        .or_else(|| non_empty(raw.magic_dns_suffix.clone()));
    let magic_dns_suffix = reported_suffix.as_deref().and_then(magic_dns_suffix);
    let tailnet = reported_suffix
        .or_else(|| raw.current_tailnet.as_ref().map(|t| t.name.clone()).and_then(non_empty))
        .and_then(|t| clean(Some(t)));
    let suffix = magic_dns_suffix.as_deref();

    let mut devices = Vec::new();
    let mut self_name = None;
    if let Some(me) = raw.self_ {
        let device = device(me, "self", true, suffix);
        self_name = Some(device.name.clone());
        devices.push(device);
    }
    let mut peers: Vec<Device> = raw
        .peer
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(key, value)| Some(device(RawPeer::deserialize(value).ok()?, &key, false, suffix)))
        .take(MAX_DEVICES.saturating_sub(devices.len()))
        .collect();
    peers.sort_by_cached_key(|d| d.name.to_lowercase());
    devices.extend(peers);
    Some(TailscaleStatus { available: true, reason: None, detail: None, tailnet, magic_dns_suffix, self_name, devices })
}

fn non_empty(text: String) -> Option<String> {
    (!text.trim().is_empty()).then_some(text)
}

fn device(raw: RawPeer, key: &str, is_self: bool, suffix: Option<&str>) -> Device {
    let addresses: Vec<IpAddr> = raw
        .tailscale_ips
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v.as_str()?.trim().parse().ok())
        .collect();
    // Only addresses in Tailscale's own ranges: anything else could point outside the tailnet.
    let ipv4 = addresses.iter().find(|a| matches!(a, IpAddr::V4(v4) if is_tailscale_ipv4(*v4))).map(ToString::to_string);
    let ipv6 = addresses.iter().find(|a| matches!(a, IpAddr::V6(v6) if is_tailscale_ipv6(*v6))).map(ToString::to_string);
    let dns_name = dns_name(&raw.dns_name, suffix);
    let name = clean(Some(raw.host_name))
        .or_else(|| dns_name.as_deref().and_then(|d| d.split('.').next()).map(str::to_owned))
        .or_else(|| ipv4.clone())
        .unwrap_or_else(|| "(unnamed)".to_owned());
    let id = clean(Some(raw.id)).or_else(|| clean(Some(key.to_owned()))).unwrap_or_default();
    let tags = raw
        .tags
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| clean(Some(t.as_str()?.to_owned())))
        .take(MAX_TAGS)
        .collect();
    Device {
        id,
        name,
        dns_name,
        os: clean(Some(raw.os)),
        ipv4,
        ipv6,
        online: raw.online,
        last_seen: last_seen(&raw.last_seen),
        tags,
        is_self,
    }
}

/// A plain host name: trailing dot dropped, lowercase, ASCII letters, digits, '-' and '.' only,
/// no empty label, at most 253 characters, and not an address (the last label is not all digits,
/// and it does not parse as an IP).
fn host_name(raw: &str) -> Option<String> {
    let name = raw.trim().strip_suffix('.').unwrap_or(raw.trim()).to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= MAX_DNS_NAME
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && name.split('.').all(|label| !label.is_empty() && label.len() <= 63 && !label.starts_with('-'))
        && !name.rsplit('.').next().unwrap_or("").bytes().all(|b| b.is_ascii_digit())
        && name.parse::<IpAddr>().is_err();
    valid.then_some(name)
}

/// The tailnet's MagicDNS suffix, if it is a host name of at least two labels.
fn magic_dns_suffix(raw: &str) -> Option<String> {
    host_name(raw).filter(|s| s.contains('.'))
}

/// Whether a host name is in the tailnet's MagicDNS domain (`<suffix>`) or another tailnet's
/// (`.ts.net`, for shared-in devices). The name must have a label before the suffix.
pub fn in_magic_dns_domain(name: &str, suffix: Option<&str>) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let in_suffix = |suffix: &str| {
        let suffix = suffix.trim_start_matches('.');
        !suffix.is_empty()
            && name.len() > suffix.len() + 1
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
    };
    in_suffix(TS_NET) || suffix.is_some_and(|s| in_suffix(&s.to_ascii_lowercase()))
}

/// A device's MagicDNS name, kept only if it is a plain host name in the tailnet's MagicDNS
/// domain (`suffix`) or ending in `.ts.net`. Anything else is not kept.
fn dns_name(raw: &str, suffix: Option<&str>) -> Option<String> {
    host_name(raw).filter(|name| in_magic_dns_domain(name, suffix))
}

/// A timestamp as Tailscale writes it (RFC 3339), or None for Go's zero time and anything odd.
fn last_seen(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let plausible = (20..=40).contains(&raw.len())
        && raw.as_bytes()[4] == b'-'
        && raw.bytes().all(|b| b.is_ascii_digit() || b"-:.TZ+".contains(&b))
        && !raw.starts_with("0001-");
    plausible.then(|| raw.to_owned())
}

/// Whether an address is in Tailscale's range, 100.64.0.0/10.
pub fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (b & 0xC0) == 64
}

/// Whether an address is in Tailscale's IPv6 range, fd7a:115c:a1e0::/48.
pub fn is_tailscale_ipv6(ip: Ipv6Addr) -> bool {
    let [a, b, c, ..] = ip.segments();
    (a, b, c) == (0xfd7a, 0x115c, 0xa1e0)
}

/// Whether an address is a Tailscale address (either range; an IPv4-mapped IPv6 address counts as
/// its IPv4 address).
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => is_tailscale_ipv4(v4),
        IpAddr::V6(v6) => is_tailscale_ipv6(v6),
    }
}

/// What a Tailscale scan checks: the other online devices' IPv4 addresses in 100.64.0.0/10,
/// each with its Tailscale names.
pub fn scan_targets(status: &TailscaleStatus) -> Vec<HostTarget> {
    let own: Vec<Option<&str>> = status.devices.iter().filter(|d| d.is_self).map(|d| d.ipv4.as_deref()).collect();
    status
        .devices
        .iter()
        .filter(|d| d.online && !d.is_self && !own.contains(&d.ipv4.as_deref()))
        .filter_map(|d| {
            let ip: Ipv4Addr = d.ipv4.as_deref()?.parse().ok()?;
            is_tailscale_ipv4(ip).then(|| HostTarget {
                ip,
                tailscale: Some(TailscaleLabel { name: Some(d.name.clone()), dns_name: d.dns_name.clone(), os: d.os.clone() }),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like real `tailscale status --json` output; every name and address is made up.
    const FIXTURE: &str = r#"{
      "Version": "1.90.0-t0000000-g0000000",
      "TUN": true,
      "BackendState": "Running",
      "HaveNodeKey": true,
      "AuthURL": "",
      "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
      "Self": {
        "ID": "nSELF0CNTRL", "PublicKey": "nodekey:0000", "HostName": "my-laptop",
        "DNSName": "my-laptop.example.ts.net.", "OS": "linux", "UserID": 1,
        "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
        "Online": true, "LastSeen": "0001-01-01T00:00:00Z", "Unknown": {"x": [1, 2]}
      },
      "Health": [],
      "MagicDNSSuffix": "example.ts.net",
      "CurrentTailnet": { "Name": "example.com", "StableID": "T0000", "MagicDNSSuffix": "example.ts.net", "MagicDNSEnabled": true },
      "CertDomains": ["my-laptop.example.ts.net"],
      "Peer": {
        "nodekey:1111": {
          "ID": "n1111CNTRL", "PublicKey": "nodekey:1111", "HostName": "studio-mac",
          "DNSName": "studio-mac.example.ts.net.", "OS": "macOS", "UserID": 1,
          "TailscaleIPs": ["fd7a:115c:a1e0::2", "100.64.0.2"],
          "Tags": ["tag:office"], "Online": true, "LastSeen": "2026-11-27T10:00:00Z",
          "Created": "2026-01-01T00:00:00Z", "ExitNode": false, "Active": true
        },
        "nodekey:2222": {
          "ID": "n2222CNTRL", "HostName": "Office\u202ePC\u200b",
          "DNSName": "office-pc.example.ts.net.", "OS": "windows",
          "TailscaleIPs": ["100.64.0.3", "not-an-ip"], "Online": false, "LastSeen": "2026-11-20T08:30:00.5Z"
        },
        "nodekey:3333": { "HostName": "", "DNSName": "bare-box.example.ts.net.", "TailscaleIPs": ["100.64.0.4"], "Online": "yes" },
        "nodekey:4444": { "ID": "n4444CNTRL", "HostName": "outside", "OS": "linux", "TailscaleIPs": ["192.0.2.7"], "Online": true },
        "nodekey:5555": { "ID": "n5555CNTRL", "HostName": "evil", "DNSName": "evil host;rm -rf.example.ts.net.", "OS": "linux", "TailscaleIPs": ["100.64.0.5"], "Online": true },
        "nodekey:6666": null,
        "nodekey:7777": { "ID": "n7777CNTRL", "HostName": "friend-pc", "DNSName": "friend-pc.other-tailnet.ts.net.", "OS": "windows", "TailscaleIPs": ["100.64.0.7", "fd7a:115c:a1e0::7"], "Online": false },
        "nodekey:8888": { "ID": "n8888CNTRL", "HostName": "elsewhere", "DNSName": "server.example.com.", "OS": "linux", "TailscaleIPs": ["10.0.0.8", "2001:db8::8"], "Online": false },
        "nodekey:9999": { "ID": "n9999CNTRL", "HostName": "numeric", "DNSName": "10.0.0.9.", "OS": "linux", "TailscaleIPs": ["100.64.0.9"], "Online": false }
      },
      "User": {}
    }"#;

    fn find<'a>(status: &'a TailscaleStatus, name: &str) -> &'a Device {
        status.devices.iter().find(|d| d.name == name).unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn parses_a_realistic_status() {
        let status = parse_status(FIXTURE.as_bytes()).unwrap();
        assert!(status.available);
        assert_eq!(status.tailnet.as_deref(), Some("example.ts.net"));
        assert_eq!(status.magic_dns_suffix.as_deref(), Some("example.ts.net"));
        assert_eq!(status.self_name.as_deref(), Some("my-laptop"));
        assert_eq!(status.devices.len(), 9);
        let me = &status.devices[0];
        assert!(me.is_self && me.name == "my-laptop" && me.last_seen.is_none());
        assert_eq!(me.dns_name.as_deref(), Some("my-laptop.example.ts.net"));

        let mac = find(&status, "studio-mac");
        assert_eq!(
            serde_json::to_value(mac).unwrap(),
            serde_json::json!({
                "id": "n1111CNTRL", "name": "studio-mac", "dnsName": "studio-mac.example.ts.net",
                "os": "macOS", "ipv4": "100.64.0.2", "ipv6": "fd7a:115c:a1e0::2", "online": true,
                "lastSeen": "2026-11-27T10:00:00Z", "tags": ["tag:office"], "isSelf": false
            })
        );
        // Hidden and reordering characters are gone; a bad address is skipped.
        let pc = find(&status, "OfficePC");
        assert_eq!((pc.ipv4.as_deref(), pc.ipv6.as_deref(), pc.online), (Some("100.64.0.3"), None, false));
        assert_eq!(pc.last_seen.as_deref(), Some("2026-11-20T08:30:00.5Z"));
        // Missing fields: name from the DNS name, id from the map key; a wrong type reads as default.
        let bare = find(&status, "bare-box");
        assert_eq!((bare.id.as_str(), bare.os.as_deref(), bare.online), ("nodekey:3333", None, false));
        assert!(bare.tags.is_empty());
        // A DNS name that is not a host name is not kept.
        assert_eq!(find(&status, "evil").dns_name, None);
        // Shared-in devices keep their other tailnet's name; names outside *.ts.net and the
        // tailnet's suffix, and addresses outside Tailscale's ranges, are dropped.
        let friend = find(&status, "friend-pc");
        assert_eq!(friend.dns_name.as_deref(), Some("friend-pc.other-tailnet.ts.net"));
        assert_eq!((friend.ipv4.as_deref(), friend.ipv6.as_deref()), (Some("100.64.0.7"), Some("fd7a:115c:a1e0::7")));
        let elsewhere = find(&status, "elsewhere");
        assert_eq!((elsewhere.dns_name.as_deref(), elsewhere.ipv4.as_deref(), elsewhere.ipv6.as_deref()), (None, None, None));
        assert_eq!(find(&status, "outside").ipv4, None);
        assert_eq!(find(&status, "numeric").dns_name, None);
        // Others are sorted by name after this computer.
        let names: Vec<&str> = status.devices.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            ["my-laptop", "bare-box", "elsewhere", "evil", "friend-pc", "numeric", "OfficePC", "outside", "studio-mac"]
        );
    }

    #[test]
    fn whole_status_json_matches_the_ui_contract() {
        let json = serde_json::to_value(parse_status(FIXTURE.as_bytes()).unwrap()).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["available", "detail", "devices", "magicDnsSuffix", "reason", "selfName", "tailnet"]);
        assert_eq!(json["reason"], serde_json::Value::Null);
        let down = serde_json::to_value(TailscaleStatus::unavailable(Reason::NotInstalled, None)).unwrap();
        assert_eq!(
            down,
            serde_json::json!({ "available": false, "reason": "not_installed", "detail": null, "tailnet": null, "magicDnsSuffix": null, "selfName": null, "devices": [] })
        );
    }

    #[test]
    fn signed_out_and_stopped_states() {
        for state in ["NeedsLogin", "NoState"] {
            let json = format!(r#"{{"BackendState":"{state}","Self":{{"HostName":"x"}},"Peer":null,"AuthURL":"https://login.example/a"}}"#);
            let status = parse_status(json.as_bytes()).unwrap();
            assert_eq!((status.available, status.reason), (false, Some(Reason::LoggedOut)));
            assert!(status.devices.is_empty());
        }
        let stopped = parse_status(br#"{"BackendState":"Stopped"}"#).unwrap();
        assert_eq!(stopped.reason, Some(Reason::NotRunning));
        assert_eq!(parse_status(br#"{"BackendState":"NeedsMachineAuth"}"#).unwrap().reason, Some(Reason::Error));
        assert!(parse_status(b"not json").is_none());
        assert!(parse_status(b"[1,2]").is_none());
    }

    #[test]
    fn failures_map_to_reasons() {
        let r = |s: &str| failure_status(s).reason;
        assert_eq!(r("failed to connect to local tailscaled; it doesn't appear to be running"), Some(Reason::NotRunning));
        assert_eq!(r("Failed to connect to local Tailscale daemon for /localapi/v0/status; not running?"), Some(Reason::NotRunning));
        let other = failure_status("something odd\u{202E} happened\nmore");
        assert_eq!((other.reason, other.detail.as_deref()), (Some(Reason::Error), Some("something odd happened")));
        assert_eq!(failure_status("").detail.as_deref(), Some("Tailscale reported an error."));
    }

    #[test]
    fn device_list_is_capped() {
        let peers: Vec<String> = (0..MAX_DEVICES + 10)
            .map(|i| format!(r#""nodekey:{i}":{{"HostName":"h{i}","TailscaleIPs":["100.64.0.9"]}}"#))
            .collect();
        let json = format!(r#"{{"BackendState":"Running","Self":{{"HostName":"me"}},"Peer":{{{}}}}}"#, peers.join(","));
        assert_eq!(parse_status(json.as_bytes()).unwrap().devices.len(), MAX_DEVICES);
    }

    #[test]
    fn names_are_capped() {
        let json = format!(r#"{{"BackendState":"Running","Peer":{{"k":{{"HostName":"{}"}}}}}}"#, "x".repeat(500));
        assert_eq!(parse_status(json.as_bytes()).unwrap().devices[0].name.len(), 128);
    }

    #[test]
    fn scan_targets_are_online_tailnet_ipv4_without_self() {
        let status = parse_status(FIXTURE.as_bytes()).unwrap();
        let targets = scan_targets(&status);
        let ips: Vec<Ipv4Addr> = targets.iter().map(|t| t.ip).collect();
        // Not self, not offline (office-pc, bare-box), not outside 100.64.0.0/10.
        assert_eq!(ips, [Ipv4Addr::new(100, 64, 0, 5), Ipv4Addr::new(100, 64, 0, 2)]);
        let mac = targets.iter().find(|t| t.ip == Ipv4Addr::new(100, 64, 0, 2)).unwrap();
        assert_eq!(
            mac.tailscale,
            Some(TailscaleLabel {
                name: Some("studio-mac".into()),
                dns_name: Some("studio-mac.example.ts.net".into()),
                os: Some("macOS".into())
            })
        );
        assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 127, 255, 255)) && is_tailscale_ipv4(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 128, 0, 1)) && !is_tailscale_ipv4(Ipv4Addr::new(100, 63, 0, 1)));
    }

    #[test]
    fn dns_names_must_be_in_the_tailnet_and_not_addresses() {
        let suffix = Some("example.ts.net");
        let ok = |raw: &str, suffix: Option<&str>| dns_name(raw, suffix);
        assert_eq!(ok("Studio-Mac.Example.ts.net.", suffix).as_deref(), Some("studio-mac.example.ts.net"));
        assert_eq!(ok("pc.other-tailnet.ts.net", None).as_deref(), Some("pc.other-tailnet.ts.net"));
        // A tailnet with its own (older) suffix.
        assert_eq!(ok("pc.example.beta.tailscale.net", Some("example.beta.tailscale.net")).as_deref(), Some("pc.example.beta.tailscale.net"));
        for bad in [
            "pc.example.com",       // outside the tailnet's domain
            "pc.example.ts.net.evil.com",
            "pc-ts.net",            // not a label boundary
            "ts.net",               // nothing before the suffix
            "10.0.0.1",             // an address
            "100.64.0.1",
            "pc.123",               // all-digit last label
            "0x7f.1",
            "pc..example.ts.net",
            "-pc.example.ts.net",
            "",
        ] {
            assert_eq!(ok(bad, suffix), None, "{bad}");
        }
        assert_eq!(ok("pc.example.beta.tailscale.net", suffix), None);
        assert_eq!(magic_dns_suffix("Example.ts.net."), Some("example.ts.net".to_owned()));
        assert_eq!(magic_dns_suffix("100.64.0.1"), None);
        assert_eq!(magic_dns_suffix("localhost"), None);
        assert!(in_magic_dns_domain("PC.example.ts.net.", None));
        assert!(!in_magic_dns_domain("pc.example.com", Some(".")));
    }

    #[test]
    fn tailscale_address_ranges() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_tailscale_ip(ip("100.64.0.1")) && is_tailscale_ip(ip("100.127.255.254")));
        assert!(!is_tailscale_ip(ip("100.128.0.1")) && !is_tailscale_ip(ip("10.0.0.1")));
        assert!(is_tailscale_ip(ip("fd7a:115c:a1e0::1")) && is_tailscale_ip(ip("fd7a:115c:a1e0:ffff::1")));
        assert!(!is_tailscale_ip(ip("fd7a:115c:a1e1::1")) && !is_tailscale_ip(ip("2001:db8::1")));
        assert!(is_tailscale_ip(ip("::ffff:100.64.0.1")) && !is_tailscale_ip(ip("::ffff:10.0.0.1")));
    }

    #[tokio::test]
    async fn status_reads_are_shared_and_reused_briefly() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let cache = Arc::new(StatusCache::new());
        let reads = Arc::new(AtomicUsize::new(0));
        let read = |reads: Arc<AtomicUsize>| async move {
            reads.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            TailscaleStatus::unavailable(Reason::NotRunning, None)
        };
        let ttl = Duration::from_millis(300);
        let (a, b) = tokio::join!(
            cache.get(ttl, || read(reads.clone())),
            cache.get(ttl, || read(reads.clone()))
        );
        assert_eq!((a.reason, b.reason), (Some(Reason::NotRunning), Some(Reason::NotRunning)));
        assert_eq!(reads.load(Ordering::SeqCst), 1, "concurrent callers share one read");
        cache.get(ttl, || read(reads.clone())).await;
        assert_eq!(reads.load(Ordering::SeqCst), 1, "reused within the time");
        tokio::time::sleep(ttl).await;
        cache.get(ttl, || read(reads.clone())).await;
        assert_eq!(reads.load(Ordering::SeqCst), 2, "read again once stale");
    }

    #[test]
    fn only_changes_are_logged_at_info() {
        let last = Mutex::new(None);
        let down = TailscaleStatus::unavailable(Reason::NotRunning, None);
        assert!(status_changed(&last, &down));
        assert!(!status_changed(&last, &down));
        assert!(status_changed(&last, &TailscaleStatus::unavailable(Reason::LoggedOut, None)));
        let up = parse_status(FIXTURE.as_bytes()).unwrap();
        assert!(status_changed(&last, &up));
        assert!(!status_changed(&last, &up));
    }

    #[test]
    fn picks_the_first_regular_file() {
        let dir = std::env::temp_dir().join(format!("rc-tailscale-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a-directory")).unwrap();
        std::fs::write(dir.join("tailscale"), b"").unwrap();
        let candidates = vec![
            dir.join("missing"),
            dir.join("a-directory"),
            PathBuf::from("tailscale"), // relative: never used
            dir.join("tailscale"),
        ];
        assert_eq!(find_binary(&candidates), Some(dir.join("tailscale")));
        assert_eq!(find_binary(&candidates[..3]), None);
        assert!(candidate_paths().iter().all(|p| p.is_absolute()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_client_is_not_installed() {
        let status = status_with(&[PathBuf::from("/nonexistent/rc-test/tailscale")], RunLimits::default()).await;
        assert_eq!((status.available, status.reason), (false, Some(Reason::NotInstalled)));
    }

    /// Fake clients as shell scripts (run directly through their #! line, as the real binary
    /// would be). One test, so no other thread forks while a script is open for writing.
    #[cfg(unix)]
    #[tokio::test]
    async fn fake_clients_time_out_overflow_and_answer() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("rc-tailscale-fake-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            vec![path]
        };
        let limits = RunLimits { timeout: Duration::from_millis(500), max_stdout: 64 * 1024 };

        let ok = script("ok", &format!("[ \"$1 $2\" = 'status --json' ] || exit 9\ncat <<'EOF'\n{FIXTURE}\nEOF"));
        let status = status_with(&ok, limits).await;
        assert!(status.available, "{status:?}");
        assert_eq!(status.devices.len(), 9);

        let slow = script("slow", "exec sleep 30");
        let started = std::time::Instant::now();
        let status = status_with(&slow, limits).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(status.reason, Some(Reason::Error));
        assert!(status.detail.unwrap().contains("did not answer"));

        let flood = script("flood", "exec yes 0123456789abcdef");
        let started = std::time::Instant::now();
        let status = status_with(&flood, limits).await;
        assert!(started.elapsed() < Duration::from_millis(450), "refused before the time limit");
        assert!(status.detail.unwrap().contains("too large"));

        // Plenty of standard error is drained without blocking and kept short.
        let down = script(
            "down",
            "i=0; while [ $i -lt 2000 ]; do echo 'failed to connect to local tailscaled; it does not appear to be running' >&2; i=$((i+1)); done; exit 1",
        );
        assert_eq!(status_with(&down, limits).await.reason, Some(Reason::NotRunning));

        let broken = script("broken", "echo 'unexpected trouble' >&2; exit 2");
        let status = status_with(&broken, limits).await;
        assert_eq!((status.reason, status.detail.as_deref()), (Some(Reason::Error), Some("unexpected trouble")));

        let logged_out = script("logged-out", "echo '{\"BackendState\":\"NeedsLogin\"}'; exit 1");
        assert_eq!(status_with(&logged_out, limits).await.reason, Some(Reason::LoggedOut));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
