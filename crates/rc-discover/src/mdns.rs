//! Bonjour names, asked of one machine at a time.
//!
//! Instead of browsing by multicast (which reaches every device on the segment), we send a
//! one-shot query to the host's mDNS port from an ephemeral port. RFC 6762 §6.7 calls this a
//! "legacy unicast" query: the responder answers by unicast to our source port, repeating the ID
//! and questions. (The QU bit is only meaningful for multicast queries, so it is not set.)
//!
//! We ask for:
//! - the reverse-address name (PTR `d.c.b.a.in-addr.arpa`), which mDNSResponder registers for each
//!   interface address and which gives the host name, e.g. "Studio-Mac.local";
//! - the service types a Mac advertises when sharing is on (`_rfb._tcp` for Screen Sharing,
//!   `_ssh._tcp` / `_sftp-ssh._tcp` for Remote Login, `_smb._tcp` for File Sharing). Their instance
//!   names are the computer name ("Studio Mac"). When mDNSResponder answers a service PTR it adds
//!   its `<name>._device-info._tcp.local` TXT record (model=...) as an additional record. There is
//!   no `_device-info._tcp.local` PTR to ask for directly.
//!
//! Limit: mDNSResponder only answers unicast queries from a source on one of its own subnets
//! (`QueryWasLocalUnicast` in mDNSCore/mDNS.c; RFC 6762 §5.5), except for records registered with
//! "allow remote query", which the host and sharing records are not. So this names Macs on the
//! viewer's own VLAN only; SMB and reverse DNS are the cross-subnet sources.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::dns;

pub const MDNS_PORT: u16 = 5353;
const DEVICE_INFO: &str = "_device-info._tcp.local";
/// Service types whose instance name is the computer name on a Mac.
const SERVICES: [&str; 4] = ["_rfb._tcp.local", "_smb._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsInfo {
    /// The host name, e.g. "Studio-Mac.local".
    pub host_name: Option<String>,
    /// The friendly computer name from `_device-info._tcp`.
    pub friendly_name: Option<String>,
    /// The model identifier, e.g. "MacBookPro18,3".
    pub model: Option<String>,
}

impl MdnsInfo {
    fn is_empty(&self) -> bool {
        self.host_name.is_none() && self.friendly_name.is_none() && self.model.is_none()
    }
}

pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

pub async fn query(ip: Ipv4Addr, port: u16, limit: Duration) -> Option<MdnsInfo> {
    let reverse = reverse_name(ip);
    let id = transaction_id(ip);
    let message = request(id, &reverse);
    let reply = crate::udp_exchange(SocketAddr::from((ip, port)), &message, limit).await?;
    let info = parse(&reply, id, &reverse);
    (!info.is_empty()).then_some(info)
}

pub fn request(id: u16, reverse: &str) -> Vec<u8> {
    let mut questions = vec![(reverse, dns::TYPE_PTR)];
    questions.extend(SERVICES.iter().map(|s| (*s, dns::TYPE_PTR)));
    dns::query(id, 0, &questions)
}

pub fn parse(reply: &[u8], id: u16, reverse: &str) -> MdnsInfo {
    let mut info = MdnsInfo::default();
    let Some(records) = dns::records(reply, id) else {
        return info;
    };
    let device_suffix = format!(".{DEVICE_INFO}");
    for record in &records {
        match record.rtype {
            dns::TYPE_PTR => {
                let Some((target, _)) = dns::read_name(reply, record.data_offset) else { continue };
                if record.name.eq_ignore_ascii_case(reverse) {
                    info.host_name.get_or_insert(target);
                } else if let Some(service) = SERVICES.iter().find(|s| record.name.eq_ignore_ascii_case(s)) {
                    if let Some(instance) = strip_suffix_ignore_case(&target, &format!(".{service}")) {
                        info.friendly_name.get_or_insert(instance.to_owned());
                    }
                }
            }
            dns::TYPE_TXT => {
                if let Some(instance) = strip_suffix_ignore_case(&record.name, &device_suffix) {
                    if info.model.is_none() {
                        info.model = txt_value(&record.data, "model");
                    }
                    info.friendly_name.get_or_insert(instance.to_owned());
                }
            }
            _ => {}
        }
    }
    info
}

/// `text` without `suffix` (ASCII case ignored), when something is left before it.
fn strip_suffix_ignore_case<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    let cut = text.len().checked_sub(suffix.len())?;
    (cut > 0 && text.is_char_boundary(cut) && text[cut..].eq_ignore_ascii_case(suffix)).then(|| &text[..cut])
}

fn txt_value(data: &[u8], key: &str) -> Option<String> {
    let mut rest = data;
    while let Some((&length, tail)) = rest.split_first() {
        let entry = tail.get(..usize::from(length))?;
        rest = &tail[usize::from(length)..];
        let text = String::from_utf8_lossy(entry);
        if let Some((k, v)) = text.split_once('=') {
            if k.eq_ignore_ascii_case(key) {
                return Some(v.to_owned());
            }
        }
    }
    None
}

fn transaction_id(ip: Ipv4Addr) -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (u32::from(ip) ^ nanos) as u16 | 1
}

/// Build the reply a Mac with Screen Sharing on would send (used by tests): the reverse PTR, the
/// `_rfb._tcp` PTR, and the device-info TXT as an additional record.
#[doc(hidden)]
pub fn sample_reply(query: &[u8], host_name: &str, friendly_name: &str, model: &str) -> Vec<u8> {
    let id = [query[0], query[1]];
    let ip_reverse = dns::read_name(query, 12).map(|(n, _)| n).unwrap_or_default();
    let instance = format!("{friendly_name}._rfb._tcp.local");
    let device = format!("{friendly_name}.{DEVICE_INFO}");
    let mut out = vec![id[0], id[1], 0x84, 0x00, 0, 0, 0, 2, 0, 0, 0, 1];
    let record = |out: &mut Vec<u8>, name: &str, rtype: u16, data: Vec<u8>| {
        dns::push_name(out, name);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 10]);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    };
    let name_bytes = |name: &str| {
        let mut v = Vec::new();
        dns::push_name(&mut v, name);
        v
    };
    record(&mut out, &ip_reverse, dns::TYPE_PTR, name_bytes(host_name));
    record(&mut out, "_rfb._tcp.local", dns::TYPE_PTR, name_bytes(&instance));
    let entry = format!("model={model}");
    let mut txt = vec![entry.len() as u8];
    txt.extend_from_slice(entry.as_bytes());
    record(&mut out, &device, dns::TYPE_TXT, txt);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_the_right_questions() {
        let query = request(0x1234, &reverse_name(Ipv4Addr::new(10, 0, 0, 7)));
        // Flags 0 (a standard query), five questions, no QU bit (class IN exactly).
        assert_eq!(&query[2..6], &[0, 0, 0, 5]);
        assert_eq!(dns::read_name(&query, 12).unwrap().0, "7.0.0.10.in-addr.arpa");
        let after = dns::read_name(&query, 12).unwrap().1;
        assert_eq!(&query[after..after + 4], &[0, 12, 0, 1], "PTR, class IN");
        assert_eq!(dns::read_name(&query, after + 4).unwrap().0, "_rfb._tcp.local");
    }

    #[test]
    fn reads_a_macs_answer() {
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let reverse = reverse_name(ip);
        assert_eq!(reverse, "7.0.0.10.in-addr.arpa");
        let query = request(0x1234, &reverse);
        let reply = sample_reply(&query, "Studio-Mac.local", "Studio Mac", "Mac14,3");
        let info = parse(&reply, 0x1234, &reverse);
        assert_eq!(info.host_name.as_deref(), Some("Studio-Mac.local"));
        assert_eq!(info.friendly_name.as_deref(), Some("Studio Mac"));
        assert_eq!(info.model.as_deref(), Some("Mac14,3"));
        assert_eq!(parse(&reply, 0x9999, &reverse), MdnsInfo::default());
        // Someone else's reverse name is not ours.
        assert_eq!(parse(&reply, 0x1234, "8.0.0.10.in-addr.arpa").host_name, None);
    }

    #[test]
    fn suffixes_are_cut_safely() {
        assert_eq!(strip_suffix_ignore_case("Caf\u{e9}._RFB._tcp.local", "._rfb._tcp.local"), Some("Caf\u{e9}"));
        assert_eq!(strip_suffix_ignore_case("._rfb._tcp.local", "._rfb._tcp.local"), None);
        assert_eq!(strip_suffix_ignore_case("\u{e9}", "x"), None);
        assert_eq!(strip_suffix_ignore_case("a\u{e9}.local", "\u{a9}.local"), None);
    }
}
