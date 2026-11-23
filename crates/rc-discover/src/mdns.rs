//! Bonjour names, asked of one machine at a time.
//!
//! Instead of browsing by multicast (which reaches every device on the segment), we send a
//! one-shot unicast query to the host's mDNS port (RFC 6762 §5.5, "legacy unicast"), asking for
//! its reverse-address name ("Studio-Mac.local") and its `_device-info._tcp` instance (the Mac's
//! friendly name and model). Macs answer these; most other systems do not. In practice macOS only
//! answers queries from its own subnet, so this works on the local VLAN only.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;


use crate::dns;

pub const MDNS_PORT: u16 = 5353;
const DEVICE_INFO: &str = "_device-info._tcp.local";

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
    let message = dns::query(id, 0, &[(&reverse, dns::TYPE_PTR), (DEVICE_INFO, dns::TYPE_PTR)]);
    let reply = crate::udp_exchange(SocketAddr::from((ip, port)), &message, limit).await?;
    let info = parse(&reply, id, &reverse);
    (!info.is_empty()).then_some(info)
}

pub fn parse(reply: &[u8], id: u16, reverse: &str) -> MdnsInfo {
    let mut info = MdnsInfo::default();
    let Some(records) = dns::records(reply, id) else {
        return info;
    };
    let suffix = format!(".{DEVICE_INFO}");
    let mut instance = None;
    for record in &records {
        if record.rtype != dns::TYPE_PTR {
            continue;
        }
        let Some((target, _)) = dns::read_name(reply, record.data_offset) else { continue };
        if record.name.eq_ignore_ascii_case(reverse) {
            info.host_name.get_or_insert(target);
        } else if record.name.eq_ignore_ascii_case(DEVICE_INFO) {
            if let Some(name) = target.strip_suffix(&suffix) {
                info.friendly_name.get_or_insert(name.to_owned());
                instance.get_or_insert(target.clone());
            }
        }
    }
    if let Some(instance) = instance {
        let txt = records
            .iter()
            .find(|r| r.rtype == dns::TYPE_TXT && r.name.eq_ignore_ascii_case(&instance));
        if let Some(txt) = txt {
            info.model = txt_value(&txt.data, "model");
        }
    }
    info
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

/// Build the reply a Mac would send (used by tests).
#[doc(hidden)]
pub fn sample_reply(query: &[u8], host_name: &str, friendly_name: &str, model: &str) -> Vec<u8> {
    let id = [query[0], query[1]];
    let ip_reverse = dns::read_name(query, 12).map(|(n, _)| n).unwrap_or_default();
    let instance = format!("{friendly_name}.{DEVICE_INFO}");
    let mut out = vec![id[0], id[1], 0x84, 0x00, 0, 0, 0, 3, 0, 0, 0, 0];
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
    record(&mut out, DEVICE_INFO, dns::TYPE_PTR, name_bytes(&instance));
    let entry = format!("model={model}");
    let mut txt = vec![entry.len() as u8];
    txt.extend_from_slice(entry.as_bytes());
    record(&mut out, &instance, dns::TYPE_TXT, txt);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_macs_answer() {
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let reverse = reverse_name(ip);
        assert_eq!(reverse, "7.0.0.10.in-addr.arpa");
        let query = dns::query(0x1234, 0, &[(&reverse, dns::TYPE_PTR), (DEVICE_INFO, dns::TYPE_PTR)]);
        let reply = sample_reply(&query, "Studio-Mac.local", "Studio Mac", "Mac14,3");
        let info = parse(&reply, 0x1234, &reverse);
        assert_eq!(info.host_name.as_deref(), Some("Studio-Mac.local"));
        assert_eq!(info.friendly_name.as_deref(), Some("Studio Mac"));
        assert_eq!(info.model.as_deref(), Some("Mac14,3"));
        assert_eq!(parse(&reply, 0x9999, &reverse), MdnsInfo::default());
    }
}
