//! The computer name an SMB server gives during NTLM negotiation (TCP 445), before any sign-in.
//!
//! We send an SMB2 NEGOTIATE, then a SESSION_SETUP carrying an NTLMSSP NEGOTIATE_MESSAGE wrapped
//! in SPNEGO ([MS-SMB2] 3.2.4.2.3, [MS-NLMP] 2.2.1.1). The server replies with
//! STATUS_MORE_PROCESSING_REQUIRED and an NTLMSSP CHALLENGE_MESSAGE whose TargetInfo lists its
//! NetBIOS and DNS computer names ([MS-NLMP] 2.2.2.1, MsvAvNbComputerName / MsvAvDnsComputerName).
//! We read that and close. No AUTHENTICATE_MESSAGE is ever sent: no user name, no password, no
//! sign-in attempt, nothing that can lock out an account.
//!
//! Windows answers this whenever file sharing (port 445) is reachable; a Mac answers it when File
//! Sharing is on. It works across subnets, unlike Bonjour.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

pub const SMB_PORT: u16 = 445;

/// The largest SMB message we read. Real NEGOTIATE / SESSION_SETUP responses are a few hundred
/// bytes.
const MAX_MESSAGE: usize = 16 * 1024;
/// The most AV pairs looked at in a TargetInfo.
const MAX_AV_PAIRS: usize = 32;
/// The longest name value we decode, in bytes of UTF-16.
const MAX_NAME_BYTES: usize = 512;

const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const COMMAND_NEGOTIATE: u16 = 0;
const COMMAND_SESSION_SETUP: u16 = 1;
const NTLMSSP: &[u8; 8] = b"NTLMSSP\0";

/// Names from the NTLM challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmbNames {
    /// MsvAvNbComputerName, e.g. "STUDIO-MAC".
    pub netbios: Option<String>,
    /// MsvAvDnsComputerName, e.g. "Studio-Mac.local" or "pc-01.corp.example".
    pub dns: Option<String>,
}

impl SmbNames {
    /// The DNS form when there is one (it keeps the case the owner chose), else the NetBIOS name.
    pub fn best(self) -> Option<String> {
        self.dns.or(self.netbios)
    }
}

/// An SMB2 header for a request.
fn header(command: u16, message_id: u64, credit_charge: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"\xFESMB");
    out.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    out.extend_from_slice(&credit_charge.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Status
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    out.extend_from_slice(&0u32.to_le_bytes()); // Flags
    out.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    out.extend_from_slice(&message_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved (ProcessId)
    out.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    out.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    out.extend_from_slice(&[0u8; 16]); // Signature
    out
}

/// Prefix a message with the 4-byte direct-TCP transport header ([MS-SMB2] 2.1).
fn framed(message: Vec<u8>) -> Vec<u8> {
    let length = message.len() as u32;
    let mut out = Vec::with_capacity(4 + message.len());
    out.push(0);
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.extend(message);
    out
}

/// SMB2 NEGOTIATE offering dialects 2.0.2 to 3.0.2 (3.1.1 needs negotiate contexts; we don't need it).
pub fn negotiate_request() -> Vec<u8> {
    const DIALECTS: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut out = header(COMMAND_NEGOTIATE, 0, 0);
    out.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    out.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    out.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    // ClientGuid: random per probe, so the scan carries no fixed fingerprint.
    let mut guid = [0u8; 16];
    if getrandom::fill(&mut guid).is_err() {
        guid = [0x11; 16];
    }
    out.extend_from_slice(&guid);
    out.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for dialect in DIALECTS {
        out.extend_from_slice(&dialect.to_le_bytes());
    }
    framed(out)
}

/// NTLMSSP NEGOTIATE_MESSAGE: Unicode, OEM, request target, NTLM, always sign, extended session
/// security, 128-bit, 56-bit. No domain, no workstation.
pub fn ntlm_negotiate() -> [u8; 32] {
    let flags: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0200 | 0x0000_8000 | 0x0008_0000 | 0x2000_0000 | 0x8000_0000;
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(NTLMSSP);
    out[8..12].copy_from_slice(&1u32.to_le_bytes());
    out[12..16].copy_from_slice(&flags.to_le_bytes());
    // DomainNameFields and WorkstationFields: empty, pointing at the end of the message.
    out[20..24].copy_from_slice(&32u32.to_le_bytes());
    out[28..32].copy_from_slice(&32u32.to_le_bytes());
    out
}

/// DER tag + short-form length + content. Every piece here is under 128 bytes.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    debug_assert!(content.len() < 128);
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

/// GSS-API / SPNEGO NegTokenInit (RFC 4178) offering only NTLMSSP, with the NTLM negotiate as the
/// mechToken.
pub fn spnego_negotiate() -> Vec<u8> {
    const SPNEGO_OID: [u8; 8] = [0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
    const NTLMSSP_OID: [u8; 12] = [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
    let mech_types = der(0xA0, &der(0x30, &NTLMSSP_OID));
    let mech_token = der(0xA2, &der(0x04, &ntlm_negotiate()));
    let init = der(0x30, &[mech_types, mech_token].concat());
    der(0x60, &[&SPNEGO_OID[..], &der(0xA0, &init)].concat())
}

pub fn session_setup_request() -> Vec<u8> {
    let token = spnego_negotiate();
    let mut out = header(COMMAND_SESSION_SETUP, 1, 1);
    out.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    out.push(0); // Flags
    out.push(1); // SecurityMode: signing enabled
    out.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    out.extend_from_slice(&0u32.to_le_bytes()); // Channel
    out.extend_from_slice(&(64u16 + 24).to_le_bytes()); // SecurityBufferOffset
    out.extend_from_slice(&(token.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    out.extend_from_slice(&token);
    framed(out)
}

/// Read one framed SMB2 message, refusing anything over `MAX_MESSAGE`.
async fn read_message(tcp: &mut TcpStream) -> Option<Vec<u8>> {
    let mut frame = [0u8; 4];
    tcp.read_exact(&mut frame).await.ok()?;
    let length = usize::from(frame[1]) << 16 | usize::from(frame[2]) << 8 | usize::from(frame[3]);
    if frame[0] != 0 || !(64..=MAX_MESSAGE).contains(&length) {
        return None;
    }
    let mut message = vec![0u8; length];
    tcp.read_exact(&mut message).await.ok()?;
    Some(message)
}

/// The command and status of an SMB2 response, or None when it isn't one.
fn response_header(message: &[u8]) -> Option<(u16, u32)> {
    if message.get(..4)? != b"\xFESMB" || message.get(4..6)? != [64, 0] {
        return None;
    }
    let status = u32::from_le_bytes(message.get(8..12)?.try_into().ok()?);
    let command = u16::from_le_bytes(message.get(12..14)?.try_into().ok()?);
    let flags = u32::from_le_bytes(message.get(16..20)?.try_into().ok()?);
    // SMB2_FLAGS_SERVER_TO_REDIR.
    (flags & 1 == 1).then_some((command, status))
}

/// The security buffer of a SESSION_SETUP response.
pub fn session_setup_token(message: &[u8]) -> Option<&[u8]> {
    let (command, status) = response_header(message)?;
    if command != COMMAND_SESSION_SETUP || status != STATUS_MORE_PROCESSING_REQUIRED {
        return None;
    }
    let body = message.get(64..72)?;
    if u16::from_le_bytes([body[0], body[1]]) != 9 {
        return None;
    }
    let offset = usize::from(u16::from_le_bytes([body[4], body[5]]));
    let length = usize::from(u16::from_le_bytes([body[6], body[7]]));
    message.get(offset..offset.checked_add(length)?)
}

/// The names in the NTLM CHALLENGE_MESSAGE inside a security token (bare or SPNEGO-wrapped: we
/// look for the NTLMSSP signature rather than parse the ASN.1 around it).
pub fn names_from_token(token: &[u8]) -> Option<SmbNames> {
    let start = token.windows(12).position(|w| &w[..8] == NTLMSSP && w[8..12] == [2, 0, 0, 0])?;
    let challenge = &token[start..];
    let info_length = usize::from(u16::from_le_bytes(challenge.get(40..42)?.try_into().ok()?));
    let info_offset = usize::try_from(u32::from_le_bytes(challenge.get(44..48)?.try_into().ok()?)).ok()?;
    let info = challenge.get(info_offset..info_offset.checked_add(info_length)?)?;
    let mut names = SmbNames::default();
    let mut rest = info;
    for _ in 0..MAX_AV_PAIRS {
        let Some((pair, tail)) = rest.split_at_checked(4) else { break };
        let id = u16::from_le_bytes([pair[0], pair[1]]);
        let length = usize::from(u16::from_le_bytes([pair[2], pair[3]]));
        if id == 0 {
            break; // MsvAvEOL
        }
        let Some((value, tail)) = tail.split_at_checked(length) else { break };
        match id {
            1 => names.netbios = names.netbios.or_else(|| utf16(value)),
            3 => names.dns = names.dns.or_else(|| utf16(value)),
            _ => {}
        }
        rest = tail;
    }
    (names != SmbNames::default()).then_some(names)
}

fn utf16(bytes: &[u8]) -> Option<String> {
    let bytes = &bytes[..bytes.len().min(MAX_NAME_BYTES)];
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let text = String::from_utf16_lossy(&units);
    (!text.trim().is_empty()).then_some(text)
}

/// Negotiate, ask for an NTLM challenge, read the names and close. Bounded by `limit`.
pub async fn names(mut tcp: TcpStream, limit: Duration) -> Option<SmbNames> {
    let work = async {
        tcp.write_all(&negotiate_request()).await.ok()?;
        let reply = read_message(&mut tcp).await?;
        let (command, status) = response_header(&reply)?;
        if command != COMMAND_NEGOTIATE || status != 0 {
            return None;
        }
        tcp.write_all(&session_setup_request()).await.ok()?;
        let reply = read_message(&mut tcp).await?;
        names_from_token(session_setup_token(&reply)?)
    };
    tokio::time::timeout(limit, work).await.ok().flatten()
}

/// The two responses an SMB server sends to `negotiate_request` and `session_setup_request`, with
/// these names in the challenge (used by tests' fake servers).
#[doc(hidden)]
pub fn sample_responses(netbios: &str, dns: &str) -> (Vec<u8>, Vec<u8>) {
    let response = |command: u16, status: u32, body: &[u8]| {
        let mut message = header(command, u64::from(command), 0);
        message[8..12].copy_from_slice(&status.to_le_bytes());
        message[16..20].copy_from_slice(&1u32.to_le_bytes());
        message.extend_from_slice(body);
        framed(message)
    };
    let mut negotiate = vec![65, 0, 1, 0, 0x02, 0x02, 0, 0];
    negotiate.extend_from_slice(&[0u8; 56]);
    let challenge = sample_challenge(netbios, dns);
    // A NegTokenResp-like wrapper; the parser only looks for the NTLMSSP signature.
    let mut token = vec![0xA1, 0x81, 0x00, 0x30, 0x81, 0x00, 0xA2, 0x81, 0x00, 0x04, 0x81, challenge.len() as u8];
    token.extend_from_slice(&challenge);
    let mut setup = vec![9, 0, 0, 0];
    setup.extend_from_slice(&72u16.to_le_bytes());
    setup.extend_from_slice(&(token.len() as u16).to_le_bytes());
    setup.extend_from_slice(&token);
    (response(COMMAND_NEGOTIATE, 0, &negotiate), response(COMMAND_SESSION_SETUP, STATUS_MORE_PROCESSING_REQUIRED, &setup))
}

#[doc(hidden)]
pub fn sample_challenge(netbios: &str, dns: &str) -> Vec<u8> {
    let encode = |s: &str| s.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
    let mut info = Vec::new();
    for (id, value) in [(2u16, encode("WORKGROUP")), (1, encode(netbios)), (4, encode("local")), (3, encode(dns))] {
        info.extend_from_slice(&id.to_le_bytes());
        info.extend_from_slice(&(value.len() as u16).to_le_bytes());
        info.extend_from_slice(&value);
    }
    info.extend_from_slice(&[0, 0, 0, 0]);
    let target = encode("WORKGROUP");
    let mut out = Vec::new();
    out.extend_from_slice(NTLMSSP);
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(target.len() as u16).to_le_bytes());
    out.extend_from_slice(&(target.len() as u16).to_le_bytes());
    out.extend_from_slice(&56u32.to_le_bytes());
    out.extend_from_slice(&0xE289_8215u32.to_le_bytes());
    out.extend_from_slice(&[0x11; 8]); // ServerChallenge
    out.extend_from_slice(&[0; 8]); // Reserved
    out.extend_from_slice(&(info.len() as u16).to_le_bytes());
    out.extend_from_slice(&(info.len() as u16).to_le_bytes());
    out.extend_from_slice(&(56 + target.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 8]); // Version
    out.extend_from_slice(&target);
    out.extend_from_slice(&info);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_well_formed_and_carry_no_credentials() {
        let negotiate = negotiate_request();
        assert_eq!(usize::from(negotiate[3]) + 4, negotiate.len());
        assert_eq!(&negotiate[4..8], b"\xFESMB");
        assert_eq!(negotiate.len(), 4 + 64 + 36 + 8);
        let setup = session_setup_request();
        assert_eq!(usize::from(setup[3]) + 4, setup.len());
        let token = &setup[4 + 88..];
        assert_eq!(token, spnego_negotiate().as_slice());
        assert_eq!(token[0], 0x60);
        assert_eq!(usize::from(token[1]) + 2, token.len(), "the DER lengths add up");
        // The NTLM message is a NEGOTIATE (type 1) with no domain or workstation.
        let ntlm = &token[token.len() - 32..];
        assert_eq!(&ntlm[..12], b"NTLMSSP\0\x01\0\0\0");
        assert_eq!(u16::from_le_bytes([ntlm[16], ntlm[17]]), 0);
        assert_eq!(u16::from_le_bytes([ntlm[24], ntlm[25]]), 0);
    }

    #[test]
    fn reads_names_from_a_challenge() {
        let (_, setup) = sample_responses("STUDIO-MAC", "Studio-Mac.local");
        let names = names_from_token(session_setup_token(&setup[4..]).unwrap()).unwrap();
        assert_eq!(names.netbios.as_deref(), Some("STUDIO-MAC"));
        assert_eq!(names.dns.as_deref(), Some("Studio-Mac.local"));
        assert_eq!(names.best().as_deref(), Some("Studio-Mac.local"));
        // A bare (not SPNEGO-wrapped) challenge works too.
        let bare = sample_challenge("PC-01", "");
        assert_eq!(names_from_token(&bare), Some(SmbNames { netbios: Some("PC-01".into()), dns: None }));
    }

    #[test]
    fn hostile_challenges_do_not_panic() {
        let good = sample_challenge("PC-01", "pc-01.example");
        for cut in 0..good.len() {
            let _ = names_from_token(&good[..cut]);
        }
        // TargetInfo offset and length pointing far outside the message.
        let mut bad = good.clone();
        bad[40..42].copy_from_slice(&u16::MAX.to_le_bytes());
        bad[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(names_from_token(&bad), None);
        // An AV pair longer than what is left.
        let mut bad = good.clone();
        let info = 56 + 18;
        bad[info + 2..info + 4].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(names_from_token(&bad), None);
        // A huge name is cut.
        let long = sample_challenge(&"A".repeat(2000), "");
        assert_eq!(names_from_token(&long).unwrap().netbios.unwrap().len(), MAX_NAME_BYTES / 2);
        // Not a session setup response, wrong status, or a lying buffer offset.
        let (negotiate, setup) = sample_responses("A", "b");
        assert_eq!(session_setup_token(&negotiate[4..]), None);
        let mut wrong = setup[4..].to_vec();
        wrong[8..12].copy_from_slice(&0xC000_006Du32.to_le_bytes());
        assert_eq!(session_setup_token(&wrong), None);
        let mut lying = setup[4..].to_vec();
        lying[70..72].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(session_setup_token(&lying), None);
    }
}
