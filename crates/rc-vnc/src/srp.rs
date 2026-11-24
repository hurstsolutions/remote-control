//! Apple Screen Sharing's SRP sign-in: SRP-6a over an RFC 5054 group (only those are accepted;
//! macOS sends the 4096-bit group, g = 5), SHA-512, password stretched with PBKDF2-HMAC-SHA512.
//! Unlike type 30, the Mac has to prove it knows the account's password verifier, so a man in the
//! middle cannot impersonate it or learn the password. Two security types carry it: 33 (the SRP
//! messages inside an "RSA1" envelope; what Apple's own viewer tries first) and 36 (the same
//! messages in clear).
//!
//! SRP messages (each a `u32` length then fields; field kinds: `u8`, big number = `u16` length +
//! bytes, opaque = `u8` length + bytes, string = `u16` length + bytes, `u64`):
//!
//! 1. client: string "" , string username, string "", opaque ""
//! 2. server: u8 0, N, g, opaque salt, B, u64 PBKDF2 iterations, string options
//! 3. client: A, opaque M1, string options (echoed), opaque 16 random bytes
//! 4. server: opaque M2, opaque server random, string "", u32 0
//!
//! then the ordinary SecurityResult. Big numbers from the Mac may carry a leading zero byte
//! (N is normalised before the group check).
//!
//! Type 33 (all integers big-endian unless noted). A client envelope is `u32 total` (bytes after
//! it), `01 00` (version), `"RSA1"`, `u16 kind`, `u16 aux` (length of the meaningful body), body:
//!
//! * kind 0, key request: `00 00 00 0a 01 00 "RSA1" 00 00 00 00`. The Mac answers `u32 len`,
//!   `00 01 00 00`, `u16 n`, n bytes of DER `SubjectPublicKeyInfo` (RSA, 2048 bits on macOS),
//!   and a zero byte. The key is not authenticated; that is fine because M2 still proves the
//!   Mac knows the verifier.
//! * kind 2, message 1: aux = 256 (the ciphertext length), body = message 1 (with its `u32`
//!   length) encrypted with RSA PKCS#1 v1.5, zero-padded to 640 bytes (total 650, as Apple's
//!   viewer sends it).
//! * kind 2, message 3 in clear: aux = length of message 3 including its `u32` length, body =
//!   message 3 (with its `u32` length), zero-padded so the total is 1076 (Apple's viewer's size).
//!
//! The Mac sends messages 2 and 4 as `u32 len`, then a header `u8 step, u32 x, u32 payload_len`
//! (x = payload_len + 4), then the SRP message without its own `u32` length; message 4 is followed
//! by the SecurityResult. If it cannot decrypt message 1 it sends its key again instead.
//! Because neither source was a capture we could check ourselves, two other layouts are also
//! accepted (a 6-byte header `u32, u16 n`, and fixed offsets with the control byte at 12 and a
//! 512-byte N without a length); whatever the layout, the group check below still applies.
//!
//! Math (all numbers padded to the length of N where noted):
//!
//! ```text
//! P' = PBKDF2-HMAC-SHA512(password, salt, iterations, 128)
//! x  = H(salt || H(":" || P'))          (empty identity; the username travels in message 1)
//! k  = H(N || PAD(g))      u = H(PAD(A) || PAD(B))
//! S  = (B - k*g^x)^(a + u*x) mod N      K = H(PAD(S))
//! M1 = H((H(N) xor H(PAD(g))) || H("") || salt || PAD(A) || PAD(B) || K)
//! M2 = H(PAD(A) || M1 || K)
//! wrap key for the encrypted session's rekey = SHA-256(K)[0..16]
//! ```
//!
//! Sources: remotex `docs/apple-vnc-889.md` (message grammar and the type 33 envelope, MIT) and
//! the iShareScreen protocol notes and client (AGPL; read for protocol facts only, nothing
//! copied), whose type 33 SRP client is reported to work against macOS 15 and later. Type 36's
//! framing has not been captured by either: a Mac answered our type 36 message 1 with a zero
//! length, so type 33 is preferred whenever the Mac lists it.

use crate::error::{Result, VncError};
use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Largest SRP message we accept from the server.
pub(crate) const MAX_MESSAGE: u32 = 64 * 1024;
/// PBKDF2 iteration cap: a hostile server must not be able to stall us. At this cap the
/// stretch takes well under a second or two; it is checked before the work starts.
pub(crate) const MAX_ITERATIONS: u64 = 1_000_000;

// The only groups accepted: RFC 5054 Appendix A, 3072 bits and up, copied from the RFC text
// (checked against the RFC's own formula and SHA-256 digests in the tests). The server picks
// N and g, so anything else must be refused: a crafted group can make S predictable without
// the password (e.g. N = 2^1024, B = 2, an even k gives S = 0), which would let an impostor
// pass as a verified Mac. macOS sends the 4096-bit group with g = 5.
/// RFC 5054 Appendix A, 3072-bit group (generator 5).
const RFC5054_3072: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);
/// RFC 5054 Appendix A, 4096-bit group (generator 5).
const RFC5054_4096: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);
/// RFC 5054 Appendix A, 6144-bit group (generator 5).
const RFC5054_6144: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD",
    "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6",
    "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C",
    "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF",
);
/// RFC 5054 Appendix A, 8192-bit group (generator 19).
const RFC5054_8192: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6",
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD",
    "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B",
    "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6",
    "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA",
    "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C",
    "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4",
    "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568",
    "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B",
    "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36",
    "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92",
    "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71",
    "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
);

/// (N as hex, g) of every accepted group, smallest first.
const GROUPS: [(&str, u8); 4] = [(RFC5054_3072, 5), (RFC5054_4096, 5), (RFC5054_6144, 5), (RFC5054_8192, 19)];

fn hex_eq(bytes: &[u8], hex: &str) -> bool {
    bytes.len() * 2 == hex.len()
        && bytes.iter().zip(hex.as_bytes().chunks_exact(2)).all(|(b, h)| {
            std::str::from_utf8(h).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) == Some(*b)
        })
}

/// The bit size of the RFC 5054 group (N, g) is, if it is one we accept. `g` may carry
/// leading zero bytes; `N` must be exactly the group's bytes.
fn known_group(n: &[u8], g: &[u8]) -> Option<usize> {
    let g_start = g.iter().position(|&b| b != 0).unwrap_or(g.len());
    let g = &g[g_start..];
    GROUPS.iter().find(|(hex, gen)| g == [*gen] && hex_eq(n, hex)).map(|(hex, _)| hex.len() * 4)
}

/// The server's challenge (message 2).
#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    pub n: Vec<u8>,
    pub g: Vec<u8>,
    pub salt: Vec<u8>,
    pub b: Vec<u8>,
    pub iterations: u64,
    pub options: Vec<u8>,
}

/// What the client sends and keeps after the challenge. All secret except `a_padded`.
pub(crate) struct Proof {
    pub a_padded: Vec<u8>,
    pub m1: Vec<u8>,
    expected_m2: Vec<u8>,
    pub wrap_key: Zeroizing<[u8; 16]>,
}

impl Proof {
    /// Whether the server's M2 is the expected one (constant time).
    pub(crate) fn server_proof_matches(&self, m2: &[u8]) -> bool {
        m2.len() == self.expected_m2.len() && bool::from(m2.ct_eq(&self.expected_m2))
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(VncError::Protocol(format!("SRP: message ends inside the {what}")));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }
    fn u16(&mut self, what: &str) -> Result<usize> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn big(&mut self, what: &str) -> Result<&'a [u8]> {
        let n = self.u16(what)?;
        self.take(n, what)
    }
    fn opaque(&mut self, what: &str) -> Result<&'a [u8]> {
        let n = self.u8(what)? as usize;
        self.take(n, what)
    }
    fn u64(&mut self, what: &str) -> Result<u64> {
        let b = self.take(8, what)?;
        Ok(u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s);
}

fn put_opaque(out: &mut Vec<u8>, s: &[u8]) {
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

fn with_length(body: Vec<u8>) -> Vec<u8> {
    let mut m = (body.len() as u32).to_be_bytes().to_vec();
    m.extend(body);
    m
}

/// Message 1, with its `u32` length.
pub(crate) fn identity_message(username: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"");
    put_string(&mut b, &username.as_bytes()[..username.len().min(u16::MAX as usize)]);
    put_string(&mut b, b"");
    put_opaque(&mut b, b"");
    with_length(b)
}

/// Parse message 2 (the body after its `u32` length).
pub(crate) fn parse_challenge(body: &[u8]) -> Result<Challenge> {
    let mut c = Cursor(body);
    let control = c.u8("control byte")?;
    if control != 0 {
        return Err(VncError::Protocol(format!("SRP: challenge starts with {control:#04x}, expected 0")));
    }
    let n = c.big("modulus N")?;
    challenge_after_n(c, n)
}

/// The rest of message 2 after N.
fn challenge_after_n(mut c: Cursor<'_>, n: &[u8]) -> Result<Challenge> {
    // The Mac may send N with a leading zero byte (a positive-integer encoding); the group check
    // and the hashes use the plain bytes.
    let n = n[n.iter().position(|&b| b != 0).unwrap_or(n.len())..].to_vec();
    let g = c.big("generator g")?.to_vec();
    let salt = c.opaque("salt")?.to_vec();
    let b = c.big("server public value B")?.to_vec();
    let iterations = c.u64("iteration count")?;
    let options_len = c.u16("options")?;
    let options = c.take(options_len, "options")?.to_vec();
    if !c.0.is_empty() {
        tracing::debug!(extra = c.0.len(), "SRP: trailing bytes after the challenge (ignored)");
    }
    Ok(Challenge { n, g, salt, b, iterations, options })
}

/// Message 3, with its `u32` length.
pub(crate) fn proof_message(proof: &Proof, options: &[u8], client_random: &[u8; 16]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, &proof.a_padded); // a big number has the same framing as a string
    put_opaque(&mut b, &proof.m1);
    put_string(&mut b, options);
    put_opaque(&mut b, client_random);
    with_length(b)
}

/// Parse message 4 (after its `u32` length); returns M2.
pub(crate) fn parse_final(body: &[u8]) -> Result<Vec<u8>> {
    let mut c = Cursor(body);
    Ok(c.opaque("server proof M2")?.to_vec())
}

// ---- Type 33: the RSA1 envelope ----

/// Largest RSA key reply accepted (a 4096-bit key's DER is about 550 bytes).
pub(crate) const MAX_RSA_KEY_REPLY: u32 = 4096;
/// RSA key sizes accepted from the Mac (macOS uses 2048).
pub(crate) const RSA_BITS: std::ops::RangeInclusive<usize> = 2048..=4096;
/// Envelope sizes Apple's viewer sends (bytes after the leading `u32`).
const RSA1_IDENTITY_TOTAL: usize = 650;
const RSA1_PROOF_TOTAL: usize = 1076;
const RSA1_KIND_KEY_REQUEST: u16 = 0;
const RSA1_KIND_SRP: u16 = 2;

/// A client envelope with its `u32` length, zero-padded to `min_total` bytes after the length.
fn rsa1_envelope(kind: u16, aux: usize, body: &[u8], min_total: usize) -> Result<Vec<u8>> {
    let aux = u16::try_from(aux).map_err(|_| VncError::Other("SRP: message too long for the RSA1 envelope".into()))?;
    let mut m = Vec::with_capacity(4 + min_total.max(10 + body.len()));
    m.extend_from_slice(&[0; 4]);
    m.extend_from_slice(&[1, 0]);
    m.extend_from_slice(b"RSA1");
    m.extend_from_slice(&kind.to_be_bytes());
    m.extend_from_slice(&aux.to_be_bytes());
    m.extend_from_slice(body);
    if m.len() - 4 < min_total {
        m.resize(4 + min_total, 0);
    }
    let total = (m.len() - 4) as u32;
    m[..4].copy_from_slice(&total.to_be_bytes());
    Ok(m)
}

/// Kind 0: ask for the Mac's RSA public key (14 bytes, after the selector byte).
pub(crate) fn rsa1_key_request() -> Vec<u8> {
    rsa1_envelope(RSA1_KIND_KEY_REQUEST, 0, &[], 0).expect("empty envelope")
}

/// The Mac's RSA public key, for PKCS#1 v1.5 encryption of message 1.
pub(crate) struct MacRsaKey(aws_lc_rs::rsa::Pkcs1PublicEncryptingKey);

impl MacRsaKey {
    pub(crate) fn bits(&self) -> usize {
        self.0.key_size_bits()
    }
}

/// Parse the reply to the key request (the body after its `u32` length): `00 01 00 00`,
/// `u16 n`, n bytes of DER `SubjectPublicKeyInfo`, a trailing zero byte.
pub(crate) fn parse_rsa_key_reply(body: &[u8]) -> Result<MacRsaKey> {
    let mut c = Cursor(body);
    let prefix = c.take(4, "RSA key reply header")?;
    if prefix != [0, 1, 0, 0] {
        tracing::debug!(prefix = %hex_bytes(prefix), "SRP: unexpected RSA key reply header (continuing)");
    }
    let der = c.big("RSA public key")?;
    if c.0.len() > 1 {
        tracing::debug!(extra = c.0.len(), "SRP: trailing bytes after the RSA key (ignored)");
    }
    let key = aws_lc_rs::rsa::PublicEncryptingKey::from_der(der)
        .map_err(|e| VncError::Protocol(format!("SRP: the Mac's RSA public key could not be read ({e})")))?;
    let bits = key.key_size_bits();
    if !RSA_BITS.contains(&bits) {
        return Err(VncError::Security(format!(
            "SRP: the Mac's RSA key has {bits} bits (accepted: {} to {})",
            RSA_BITS.start(),
            RSA_BITS.end()
        )));
    }
    let key = aws_lc_rs::rsa::Pkcs1PublicEncryptingKey::new(key)
        .map_err(|_| VncError::Protocol("SRP: the Mac's RSA key cannot be used for encryption".into()))?;
    Ok(MacRsaKey(key))
}

/// Kind 2 with message 1 encrypted to the Mac's key, with its `u32` length.
pub(crate) fn rsa1_identity_packet(key: &MacRsaKey, username: &str) -> Result<Vec<u8>> {
    let plain = identity_message(username);
    if plain.len() > key.0.max_plaintext_size() {
        return Err(VncError::Auth(format!(
            "the username is too long for Apple's sign-in ({} bytes; at most {})",
            username.len(),
            key.0.max_plaintext_size() - (plain.len() - username.len())
        )));
    }
    let mut ct = vec![0u8; key.0.ciphertext_size()];
    let ct_len = key
        .0
        .encrypt(&plain, &mut ct)
        .map_err(|_| VncError::Other("SRP: RSA encryption of the sign-in request failed".into()))?
        .len();
    ct.truncate(ct_len);
    rsa1_envelope(RSA1_KIND_SRP, ct.len(), &ct, RSA1_IDENTITY_TOTAL)
}

/// Kind 2 with message 3 in clear, with its `u32` length.
pub(crate) fn rsa1_proof_packet(proof: &Proof, options: &[u8], client_random: &[u8; 16]) -> Result<Vec<u8>> {
    let inner = proof_message(proof, options, client_random);
    rsa1_envelope(RSA1_KIND_SRP, inner.len(), &inner, RSA1_PROOF_TOTAL)
}

/// The SRP message inside one of the Mac's type 33 replies (the body after its `u32` length),
/// and the name of the layout that matched (for the log).
fn rsa1_payload(body: &[u8]) -> (&[u8], &'static str) {
    let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if body.len() >= 9 {
        let (x, len) = (be32(&body[1..5]), be32(&body[5..9]));
        if x == len.wrapping_add(4) && len <= body.len() - 9 {
            return (&body[9..9 + len], "step, x, length");
        }
    }
    if body.len() >= 6 && body[..4] == [0, 0, 0, 2] {
        let len = u16::from_be_bytes([body[4], body[5]]) as usize;
        if len > 0 && len <= body.len() - 6 {
            return (&body[6..6 + len], "u32, u16 length");
        }
    }
    (body, "no header")
}

/// Parse message 2 from a type 33 reply (the body after its `u32` length).
pub(crate) fn parse_rsa1_challenge(body: &[u8]) -> Result<Challenge> {
    let (payload, layout) = rsa1_payload(body);
    let first = match parse_challenge(payload) {
        Ok(ch) => {
            tracing::debug!(layout, header = %hex_bytes(&body[..body.len() - payload.len()]), "SRP: type 33 challenge layout");
            return Ok(ch);
        }
        Err(e) => e,
    };
    // Fixed offsets as another client reads them: control byte at 12, then a 512-byte N with no
    // length of its own.
    if body.len() > 13 + 512 && body[12] == 0 {
        if let Ok(ch) = challenge_after_n(Cursor(&body[13 + 512..]), &body[13..13 + 512]) {
            tracing::debug!(header = %hex_bytes(&body[..12]), "SRP: type 33 challenge layout: fixed offsets");
            return Ok(ch);
        }
    }
    Err(first)
}

/// Parse message 4 from a type 33 reply (the body after its `u32` length); returns M2.
pub(crate) fn parse_rsa1_final(body: &[u8]) -> Result<Vec<u8>> {
    let (payload, layout) = rsa1_payload(body);
    tracing::debug!(layout, "SRP: type 33 server proof layout");
    parse_final(payload)
}

/// Lowercase hex, for diagnostics of public protocol bytes only.
pub(crate) fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn pad(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(b.len())];
    out.extend_from_slice(&b[b.len().saturating_sub(len)..]);
    out
}

fn h(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = Sha512::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().to_vec()
}

/// Refuse a challenge before any expensive work: only the RFC 5054 groups, a bounded PBKDF2
/// iteration count, and a usable B. Called before the PBKDF2 work is handed to a blocking
/// thread (which cannot be cancelled once started), and again by [`client_proof_with`].
pub(crate) fn check_challenge(ch: &Challenge) -> Result<()> {
    let Some(_bits) = known_group(&ch.n, &ch.g) else {
        let g = BigUint::from_bytes_be(&ch.g);
        return Err(VncError::Security(format!(
            "the Mac offered an unknown SRP group ({} bits, generator {g}); only the RFC 5054 groups of 3072 to \
             8192 bits are accepted, because a server-chosen group can let an impostor pass the sign-in without \
             the password",
            ch.n.len() * 8
        )));
    };
    if ch.iterations == 0 || ch.iterations > MAX_ITERATIONS {
        return Err(VncError::Security(format!(
            "SRP: the server asks for {} PBKDF2 iterations (accepted: 1 to {MAX_ITERATIONS})",
            ch.iterations
        )));
    }
    let n = BigUint::from_bytes_be(&ch.n);
    let b = BigUint::from_bytes_be(&ch.b);
    if b >= n || b == BigUint::from(0u8) {
        return Err(VncError::Security("SRP: the server sent an invalid public value B (not in 1..N-1)".into()));
    }
    Ok(())
}

/// Run the client side of SRP-6a with a caller-supplied private exponent (for tests).
pub(crate) fn client_proof_with(ch: &Challenge, password: &str, a_private: &[u8]) -> Result<Proof> {
    check_challenge(ch)?;
    let len = ch.n.len();
    let n = BigUint::from_bytes_be(&ch.n);
    let g = BigUint::from_bytes_be(&ch.g);
    let b = BigUint::from_bytes_be(&ch.b);
    let zero = BigUint::from(0u8);
    let g_pad = pad(&g, len);
    let b_pad = pad(&b, len);

    let mut stretched = Zeroizing::new([0u8; 128]);
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &ch.salt, ch.iterations as u32, stretched.as_mut());
    let inner = Zeroizing::new(h(&[b":", stretched.as_ref()]));
    let x = BigUint::from_bytes_be(&Zeroizing::new(h(&[&ch.salt, &inner])));
    let k = BigUint::from_bytes_be(&h(&[&ch.n, &g_pad]));

    let a = BigUint::from_bytes_be(a_private);
    let big_a = g.modpow(&a, &n);
    if big_a == zero {
        return Err(VncError::Other("SRP: degenerate private value".into()));
    }
    let a_pad = pad(&big_a, len);
    let u = BigUint::from_bytes_be(&h(&[&a_pad, &b_pad]));
    if u == zero {
        return Err(VncError::Security("SRP: the server's public value gives u = 0".into()));
    }
    let gx = g.modpow(&x, &n);
    let kgx = (&k * &gx) % &n;
    let base = (&b + &n - kgx) % &n;
    let s = base.modpow(&(&a + &u * &x), &n);
    let key = Zeroizing::new(h(&[&Zeroizing::new(pad(&s, len))]));

    let hn = h(&[&ch.n]);
    let hg = h(&[&g_pad]);
    let xor: Vec<u8> = hn.iter().zip(&hg).map(|(p, q)| p ^ q).collect();
    let m1 = h(&[&xor, &h(&[b""]), &ch.salt, &a_pad, &b_pad, &key]);
    let expected_m2 = h(&[&a_pad, &m1, &key]);
    let wrap = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(key.as_slice())));
    let mut wrap_key = Zeroizing::new([0u8; 16]);
    wrap_key.copy_from_slice(&wrap[..16]);
    Ok(Proof { a_padded: a_pad, m1, expected_m2, wrap_key })
}

/// [`client_proof_with`] using a random 64-byte private exponent.
pub(crate) fn client_proof(ch: &Challenge, password: &str) -> Result<Proof> {
    let mut a = Zeroizing::new([0u8; 64]);
    getrandom::fill(a.as_mut())
        .map_err(|e| VncError::Other(format!("could not get random bytes from the OS: {e}")))?;
    client_proof_with(ch, password, a.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{hex, unhex};

    /// Inputs of the known-answer vector (see `KAT_*`).
    fn kat_challenge() -> Challenge {
        Challenge {
            n: unhex(RFC5054_4096),
            g: vec![5],
            salt: (0..32u8).collect(),
            b: unhex(KAT_B),
            iterations: 1000,
            options: b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2".to_vec(),
        }
    }

    /// Computed independently in Python (hashlib + pow, no Rust involved) from the formulas in
    /// the module docs: N = the RFC 5054 4096-bit group (as macOS uses), g = 5, salt = 00..1f,
    /// password "p@ss wörd", 1000 iterations, server private b = 0x77 * 40 bytes, client
    /// private a = 0x42 * 64 bytes. B = k*g^x + g^b mod N.
    const KAT_B: &str = concat!(
        "2a5caaba40edbcedee8b7f70bcbcc64d46e562ed2f8ebc00762d184915abcccad536ec5d4cc53764aebbb208059de654",
        "f7466638430fc01e927948ad87309aa48e92bd1b29db4216a9ab78f9be5df2d19de76f6a60a9175659c5bc03ebffbe72",
        "b232b0e4caea451f6d06dc6fccad50cb173274e9daddc0daf6fcaacd86b86dcd0b65b754d82e450a4415768b429ee480",
        "5c6340f4d00e90c5f0be42e337955b7e392dbf71c4ced6dc2a679fd241e7206ab12a732e44f3d6f6f089834a70e9b5ac",
        "5b97add53b5916e8f9c4108609de6afb0b452bb61e1f89e90a85282a1e35bd76630422cdf174c49e3354fb826c8819a6",
        "4598e028da796bed20d2e99d56a72b0fe9e5f01a81cc93b97b5c57680c35f2463776e5a7bc65224e1680af8820d5b545",
        "e5c44d0012d6113f541cb2f33e73bb4d50e0fa52adcf7b6cdadd19ffc121fb8eba55a333359a14db582a827da576e846",
        "0f00e0d23ea41930fa35a6c4fc20e1038d88f0106e3275e9598cfbc74f2dd22a6b7670f1cdc6724eee4585524d883800",
        "6413a627c597fbb8dd5f56bbc837be0bfca9bb47b894ba8f4b731accba4e0f954ca1dd19b6a56de87ba15e977b0ba936",
        "57217abd522af0490c8f6c263aa9a06c5c127592dad3fc3354d8612b550867466af3a90ce0a3e7aaeb1a8eec8096e69a",
        "073fee7c81104ca09301b65b6540376bb9b4fb21fec04a92797373f4fc885ebe",
    );
    const KAT_A: &str = concat!(
        "af5892469acba05a1410b36321b748d6579e615c409fe8583ac9ec42a79ac5f5d58d93e6a804423f3292da72e8c33e43",
        "9bf7025ae83922f316577183543d161ea1a1faf59ad336b26a5f4c5722820d3e4ffecbc8abbe01e77b9ac7cd53b7f897",
        "cdad157d813401d0a402a8f262e23861738801ae776f3b2de8e3e0ed714714fd0458b4c5743228631168ea82b6ed6ee0",
        "5cbb574b1fbe36a082a041803d8da90b0bc6aedb280c66e70477823d38f5c601d3ea230765bb19b2b8c198c4b70a2b52",
        "b02453fb7550022ab193fb713f4d758f72983710f92989ea457a03ae78780e519e3c17a429b47aca8f6140fff9546452",
        "21919aae05c44f1604965acbd8c9eddc1afe1ffb3165cbcdd8264247b8f44718903bb2275f7f3aeee99580f90a8a7c92",
        "6a0f8468e367dc215f15f0bd1cee25e607d33fe3b91a6881f37037bc41abd1201b0a8a1ce5687b2bdf4adf908bfdcc64",
        "4dd5823bb2842705cbea2d42489fa7745d0c061bb254ff8f8d57ca77062e76989667cab87ad40ed8e17261095230f091",
        "602df886b335067196aa9996543c41b6a81352c191e889898d5c9170e228e0668f178f1b7ccd3e278935dbe635f10bd1",
        "b9f0e23275e9fe1f9cd04bc3a108d0d77c5b4b55728b15f9058e1d7883f54174d27b827e05e33c360caa5ef4a3a4e146",
        "f2f63e0d588b29f0bbc80737e75d4410d39d06f6a1153c0709c121ae41bfda39",
    );
    const KAT_M1: &str = concat!(
        "de4deda1cb00f531ac0971317fa50d9116aaf3ff0a25db8ee94cee6c33f741475d1c3292676a27615eeed855d270b554",
        "6400c592d4de2a618919f877c4ef2a40",
    );
    const KAT_M2: &str = concat!(
        "312dfe754b9a16c0a9a0835dfa677203b69d73b97331fb40e2562043b15353dff700405c2dafcd120cceffad1cf0f366",
        "bca8d9dae33d3ff6043bb63a636153a7",
    );
    const KAT_WRAP: &str = "09d312f308f8608dc79196e2213bcf6a";

    #[test]
    fn known_answer_vector() {
        let p = client_proof_with(&kat_challenge(), "p@ss wörd", &[0x42; 64]).unwrap();
        assert_eq!(hex(&p.a_padded), KAT_A);
        assert_eq!(hex(&p.m1), KAT_M1);
        assert_eq!(hex(&p.expected_m2), KAT_M2);
        assert!(p.server_proof_matches(&unhex(KAT_M2)));
        let mut bad = unhex(KAT_M2);
        bad[63] ^= 1;
        assert!(!p.server_proof_matches(&bad));
        assert!(!p.server_proof_matches(&bad[..32]));
        assert_eq!(hex(p.wrap_key.as_ref()), KAT_WRAP);
        // A different password gives a different proof.
        let q = client_proof_with(&kat_challenge(), "wrong", &[0x42; 64]).unwrap();
        assert_ne!(p.m1, q.m1);
    }

    #[test]
    fn messages_round_trip() {
        let id = identity_message("alice");
        assert_eq!(id, [0, 0, 0, 12, 0, 0, 0, 5, b'a', b'l', b'i', b'c', b'e', 0, 0, 0]);
        let ch = kat_challenge();
        let mut body = vec![0];
        put_string(&mut body, &ch.n);
        put_string(&mut body, &ch.g);
        put_opaque(&mut body, &ch.salt);
        put_string(&mut body, &ch.b);
        body.extend_from_slice(&ch.iterations.to_be_bytes());
        put_string(&mut body, &ch.options);
        let parsed = parse_challenge(&body).unwrap();
        assert_eq!((parsed.n, parsed.g, parsed.salt, parsed.b), (ch.n, ch.g, ch.salt, ch.b));
        assert_eq!((parsed.iterations, parsed.options), (ch.iterations, ch.options));
        assert!(parse_challenge(&body[..body.len() - 1]).is_err());
        assert!(parse_challenge(&[1]).is_err());
        let mut fin = vec![3, 9, 8, 7, 1, 0];
        fin.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_final(&fin).unwrap(), [9, 8, 7]);
    }

    #[test]
    fn hostile_parameters_are_refused() {
        let refused = |ch: &Challenge| matches!(client_proof_with(ch, "p", &[1; 64]), Err(VncError::Security(_)));
        let mut ch = kat_challenge();
        ch.iterations = MAX_ITERATIONS + 1;
        assert!(refused(&ch));
        let mut ch = kat_challenge();
        ch.iterations = 0;
        assert!(refused(&ch));
        for b in [vec![0u8], unhex(RFC5054_4096), vec![0xff; 513]] {
            let mut ch = kat_challenge();
            ch.b = b; // B = 0, B = N, B > N
            assert!(refused(&ch));
        }
        let mut ch = kat_challenge();
        ch.n = vec![0xff; 32]; // 256-bit group
        assert!(refused(&ch));
    }

    /// A Mac's RSA key pair (test-only) and its public key as the Mac's kind 0 reply body.
    fn mac_rsa_key() -> (aws_lc_rs::rsa::PrivateDecryptingKey, Vec<u8>) {
        use aws_lc_rs::encoding::AsDer;
        let private = aws_lc_rs::rsa::PrivateDecryptingKey::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der = private.public_key().as_der().unwrap();
        let der = der.as_ref();
        let mut reply = vec![0, 1, 0, 0];
        reply.extend_from_slice(&(der.len() as u16).to_be_bytes());
        reply.extend_from_slice(der);
        reply.push(0);
        (private, reply)
    }

    /// The challenge of `kat_challenge` as message 2 without its `u32` length, N with a leading
    /// zero byte as the Mac may send it.
    fn challenge_body(ch: &Challenge, zero_before_n: bool) -> Vec<u8> {
        let mut body = vec![0];
        let mut n = if zero_before_n { vec![0] } else { vec![] };
        n.extend_from_slice(&ch.n);
        put_string(&mut body, &n);
        put_string(&mut body, &ch.g);
        put_opaque(&mut body, &ch.salt);
        put_string(&mut body, &ch.b);
        body.extend_from_slice(&ch.iterations.to_be_bytes());
        put_string(&mut body, &ch.options);
        body
    }

    /// The Mac's type 33 reply header: u8 step, u32 x = len + 4, u32 len.
    fn with_rsa1_header(payload: &[u8]) -> Vec<u8> {
        let mut m = vec![1];
        m.extend_from_slice(&(payload.len() as u32 + 4).to_be_bytes());
        m.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        m.extend_from_slice(payload);
        m
    }

    #[test]
    fn rsa1_key_request_bytes() {
        assert_eq!(rsa1_key_request(), [0, 0, 0, 10, 1, 0, b'R', b'S', b'A', b'1', 0, 0, 0, 0]);
    }

    #[test]
    fn rsa1_key_reply_and_identity_packet() {
        let (private, reply) = mac_rsa_key();
        let key = parse_rsa_key_reply(&reply).unwrap();
        assert_eq!(key.bits(), 2048);
        // Without the trailing zero byte (as when the Mac re-sends it) too.
        assert!(parse_rsa_key_reply(&reply[..reply.len() - 1]).is_ok());
        let packet = rsa1_identity_packet(&key, "alice").unwrap();
        assert_eq!(packet.len(), 4 + 650);
        assert_eq!(&packet[..14], &[0, 0, 2, 0x8a, 1, 0, b'R', b'S', b'A', b'1', 0, 2, 1, 0]);
        assert!(packet[14 + 256..].iter().all(|&b| b == 0), "zero padding after the ciphertext");
        let decrypter = aws_lc_rs::rsa::Pkcs1PrivateDecryptingKey::new(private).unwrap();
        let mut out = vec![0u8; 256];
        let plain = decrypter.decrypt(&packet[14..14 + 256], &mut out).unwrap();
        assert_eq!(plain, identity_message("alice").as_slice());
        // A fresh random padding each time.
        assert_ne!(rsa1_identity_packet(&key, "alice").unwrap(), packet);
        // A name that cannot fit in one RSA block is an error, not a truncation.
        assert!(matches!(rsa1_identity_packet(&key, &"n".repeat(240)), Err(VncError::Auth(_))));
    }

    #[test]
    fn rsa1_key_reply_is_bounded_and_checked() {
        let (_, reply) = mac_rsa_key();
        // n larger than what follows.
        let mut long = reply.clone();
        long[4..6].copy_from_slice(&((reply.len() - 5) as u16).to_be_bytes());
        assert!(matches!(parse_rsa_key_reply(&long), Err(VncError::Protocol(_))));
        assert!(parse_rsa_key_reply(&reply[..5]).is_err());
        assert!(parse_rsa_key_reply(&[0, 1, 0, 0, 0, 3, 1, 2, 3]).is_err());
        // A 1024-bit key is refused (here by the key size check or by the parser itself).
        let der = unhex(RSA_1024_DER);
        let mut small = vec![0, 1, 0, 0];
        small.extend_from_slice(&(der.len() as u16).to_be_bytes());
        small.extend_from_slice(&der);
        assert!(parse_rsa_key_reply(&small).is_err());
    }

    /// A 1024-bit RSA public key (SubjectPublicKeyInfo DER), generated with openssl for this test.
    const RSA_1024_DER: &str = concat!(
        "30819f300d06092a864886f70d010101050003818d0030818902818100b90877b78b5b10b25cf5575b90bf8294",
        "4a10d63db1a166a5bd1b9f6b9712f5febf052717b94f4647ccf7c9cab61a2aba884bb6b0ce26fb3dbb7356e52b",
        "10ee481f58b2c02aa9c24759f270d4921b7630b854a51e7da5df8378f5a93e090491eaed4bd17032113a328347",
        "16569d17074be0d647deece1892e43b8b54aca1230e10203010001",
    );

    #[test]
    fn rsa1_challenge_layouts() {
        let ch = kat_challenge();
        let check = |parsed: Challenge| {
            assert_eq!((&parsed.n, &parsed.g, &parsed.salt, &parsed.b), (&ch.n, &ch.g, &ch.salt, &ch.b));
            assert_eq!((parsed.iterations, &parsed.options), (ch.iterations, &ch.options));
            assert!(check_challenge(&parsed).is_ok());
        };
        // The documented layout, N with and without the leading zero.
        for zero in [true, false] {
            let body = with_rsa1_header(&challenge_body(&ch, zero));
            check(parse_rsa1_challenge(&body).unwrap());
        }
        // A 1165-byte challenge (the size reported for macOS) has its control byte at 9 and
        // a zero at 12: the first byte of a 513-byte N.
        let body = with_rsa1_header(&challenge_body(&ch, true));
        assert_eq!((body.len(), body[9], &body[10..12], body[12]), (1165, 0, &[2u8, 1][..], 0));
        // The 6-byte header (u32 2, u16 length).
        let payload = challenge_body(&ch, false);
        let mut body = vec![0, 0, 0, 2];
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(&payload);
        check(parse_rsa1_challenge(&body).unwrap());
        // Fixed offsets: 12 header bytes, control byte, N without its length.
        let mut body = vec![0xee; 12];
        body.push(0);
        body.extend_from_slice(&ch.n);
        body.extend_from_slice(&challenge_body(&ch, false)[3 + ch.n.len()..]);
        check(parse_rsa1_challenge(&body).unwrap());
        // Garbage is an error, and an unknown group still fails the group check.
        assert!(parse_rsa1_challenge(&[0, 1, 0, 0, 1, 0]).is_err());
        let mut odd = ch.clone();
        odd.n[100] ^= 1;
        let parsed = parse_rsa1_challenge(&with_rsa1_header(&challenge_body(&odd, true))).unwrap();
        assert!(matches!(check_challenge(&parsed), Err(VncError::Security(_))));
    }

    #[test]
    fn rsa1_proof_packet_and_final() {
        let ch = kat_challenge();
        let p = client_proof_with(&ch, "p@ss wörd", &[0x42; 64]).unwrap();
        let random = [0x5c; 16];
        let packet = rsa1_proof_packet(&p, &ch.options, &random).unwrap();
        let inner = proof_message(&p, &ch.options, &random);
        assert_eq!(packet.len(), 4 + 1076);
        assert_eq!(&packet[..12], &[0, 0, 4, 0x34, 1, 0, b'R', b'S', b'A', b'1', 0, 2]);
        assert_eq!(u16::from_be_bytes([packet[12], packet[13]]) as usize, inner.len());
        // The capture's sizes: aux 682 = 678 + 4, then u32 678, then A's length 512.
        assert_eq!(&packet[12..20], &[0x02, 0xaa, 0, 0, 0x02, 0xa6, 0x02, 0x00]);
        assert_eq!(&packet[14..14 + inner.len()], inner.as_slice());
        assert!(packet[14 + inner.len()..].iter().all(|&b| b == 0));
        // Message 4 with the reply header.
        let mut fin = vec![64];
        fin.extend_from_slice(&unhex(KAT_M2));
        fin.push(16);
        fin.extend_from_slice(&[0xab; 16]);
        fin.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let m2 = parse_rsa1_final(&with_rsa1_header(&fin)).unwrap();
        assert!(p.server_proof_matches(&m2));
        assert!(p.server_proof_matches(&parse_rsa1_final(&fin).unwrap()));
    }

    /// SHA-256 of each group's big-endian bytes, computed in Python from the hex in the RFC 5054
    /// text (rfc-editor.org/rfc/rfc5054.txt, Appendix A). The same script checked every hex
    /// value against the RFC's formula 2^n - 2^(n-64) - 1 + 2^64 * ([2^(n-130) pi] + offset)
    /// and that N and (N-1)/2 are (probable) primes.
    #[test]
    fn group_constants_match_rfc_5054() {
        let digests = [
            (RFC5054_3072, 3072, "48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c"),
            (RFC5054_4096, 4096, "4ee95187682bcb230ad26a95205f6920e84708f6251b3894329b09ec23919e33"),
            (RFC5054_6144, 6144, "d1bfe6d0925ce7e4da262b62861514a7755e35831e429f343e7b864848657efd"),
            (RFC5054_8192, 8192, "39ab4feab950a3128fb71accb9fc3965d857012e081998a85996e3ea8b3c3bcf"),
        ];
        for (n, bits, digest) in digests {
            let bytes = unhex(n);
            assert_eq!(bytes.len() * 8, bits);
            assert_eq!(hex(&Sha256::digest(&bytes)), digest, "{bits}-bit group");
        }
        assert_eq!(GROUPS.map(|(_, g)| g), [5, 5, 5, 19]);
    }

    #[test]
    fn only_rfc_5054_groups_are_accepted() {
        let with = |n: Vec<u8>, g: Vec<u8>| Challenge { n, g, ..kat_challenge() };
        for (hex_n, g) in GROUPS {
            let mut ch = with(unhex(hex_n), vec![g]);
            ch.b = vec![2];
            assert!(check_challenge(&ch).is_ok(), "{} bits", hex_n.len() * 4);
            ch.g = vec![0, g]; // the same g with a leading zero byte
            assert!(check_challenge(&ch).is_ok());
        }
        let unknown = |ch: &Challenge| match check_challenge(ch) {
            Err(VncError::Security(m)) => m.starts_with("the Mac offered an unknown SRP group"),
            _ => false,
        };
        let n4096 = unhex(RFC5054_4096);
        assert!(unknown(&with(n4096.clone(), vec![2]))); // right N, wrong g
        assert!(unknown(&with(unhex(RFC5054_8192), vec![5]))); // the 8192-bit group's g is 19
        let mut flipped = n4096.clone();
        flipped[300] ^= 0x10;
        assert!(unknown(&with(flipped, vec![5])));
        let mut padded = vec![0];
        padded.extend_from_slice(&n4096);
        assert!(unknown(&with(padded, vec![5])));
        assert!(unknown(&with(vec![0xff; 512], vec![5]))); // 2^4096 - 1
        assert!(unknown(&with(unhex(crate::auth::tests::PRIME_1024), vec![2])));
    }

    /// Security audit round 2: an impostor without the password picked N = 2^1024, an odd g
    /// that makes k even, and B = 2, so S = 0 and the wrap key was the same for every
    /// password; it could then compute M2 and pass as a verified Mac. The group is now refused
    /// before anything is computed or sent.
    #[test]
    fn impostor_group_is_refused() {
        let len = 129;
        let mut n = vec![0u8; len];
        n[0] = 1;
        let mut g = 3u32;
        let g_pad = loop {
            let g_pad = pad(&BigUint::from(g), len);
            if h(&[&n, &g_pad])[63] & 1 == 0 {
                break g_pad;
            }
            g += 2;
        };
        let ch = Challenge {
            n,
            g: BigUint::from(g).to_bytes_be(),
            salt: vec![0x11; 16],
            b: vec![2],
            iterations: 1000,
            options: b"x".to_vec(),
        };
        // The old checks (size, top byte, 2 <= g < N, B mod N != 0) all passed for this group.
        assert_eq!(g_pad.len(), len);
        for pw in ["correct horse battery staple", "hunter2"] {
            match client_proof(&ch, pw) {
                Err(VncError::Security(m)) => assert!(m.starts_with("the Mac offered an unknown SRP group"), "{m}"),
                Err(e) => panic!("wrong error {e:?}"),
                Ok(_) => panic!("the impostor group was accepted"),
            }
        }
    }
}
