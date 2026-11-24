//! The NetBIOS computer name, from a node status request (UDP 137, RFC 1002 §4.2.17).
//! Windows answers it when file sharing / NetBIOS over TCP/IP is on. It carries no credentials.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::dns;

pub const NETBIOS_PORT: u16 = 137;

/// The "*" wildcard name, first-level encoded: 'C','K' then 'A','A' for each NUL pad byte.
fn wildcard() -> String {
    let mut name = String::from("CK");
    name.push_str(&"A".repeat(30));
    name
}

pub fn request(id: u16) -> Vec<u8> {
    dns::query(id, 0, &[(&wildcard(), dns::TYPE_NBSTAT)])
}

pub async fn query(ip: Ipv4Addr, port: u16, limit: Duration) -> Option<String> {
    // A random transaction ID, so another host cannot easily forge the reply.
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).ok()?;
    let id = u16::from_be_bytes(b);
    let reply = crate::udp_exchange(SocketAddr::from((ip, port)), &request(id), limit).await?;
    parse(&reply, id)
}

/// The first unique workstation name (suffix 0x00) in a node status response.
pub fn parse(reply: &[u8], id: u16) -> Option<String> {
    let records = dns::records(reply, id)?;
    let record = records.iter().find(|r| r.rtype == dns::TYPE_NBSTAT)?;
    let (&count, entries) = record.data.split_first()?;
    entries
        .as_chunks::<18>()
        .0
        .iter()
        .take(usize::from(count))
        .find(|entry| entry[15] == 0x00 && entry[16] & 0x80 == 0)
        .map(|entry| String::from_utf8_lossy(&entry[..15]).trim_end().to_owned())
        .filter(|name| !name.is_empty())
}

/// Build the reply a Windows PC would send (used by tests).
#[doc(hidden)]
pub fn sample_reply(request: &[u8], names: &[(&str, u8, bool)]) -> Vec<u8> {
    let mut out = vec![request[0], request[1], 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
    dns::push_name(&mut out, &wildcard());
    out.extend_from_slice(&dns::TYPE_NBSTAT.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    let mut data = vec![names.len() as u8];
    for (name, suffix, group) in names {
        let mut padded = format!("{name:<15}").into_bytes();
        padded.truncate(15);
        data.extend_from_slice(&padded);
        data.push(*suffix);
        data.extend_from_slice(&[if *group { 0x84 } else { 0x04 }, 0x00]);
    }
    data.extend_from_slice(&[0u8; 46]); // statistics
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_unique_workstation_name() {
        let request = request(0x0102);
        assert_eq!(request.len(), 12 + 34 + 4);
        let reply = sample_reply(&request, &[("WORKGROUP", 0x00, true), ("DESKTOP-TEST01", 0x20, false), ("DESKTOP-TEST01", 0x00, false)]);
        assert_eq!(parse(&reply, 0x0102).as_deref(), Some("DESKTOP-TEST01"));
        assert_eq!(parse(&reply[..reply.len() - 60], 0x0102), None);
    }
}
