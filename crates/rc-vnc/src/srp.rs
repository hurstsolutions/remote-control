//! Apple Screen Sharing's SRP sign-in (security type 36): SRP-6a over the server's group
//! (RFC 5054 4096-bit, g = 5 on current macOS), SHA-512, password stretched with
//! PBKDF2-HMAC-SHA512. Unlike type 30, the Mac has to prove it knows the account's password
//! verifier, so a man in the middle cannot impersonate it or learn the password.
//!
//! Wire format (type 36 sends these in clear, each a `u32` length then fields; field kinds:
//! `u8`, big number = `u16` length + bytes, opaque = `u8` length + bytes, string = `u16`
//! length + bytes, `u64`):
//!
//! 1. client: string "" , string username, string "", opaque ""
//! 2. server: u8 0, N, g, opaque salt, B, u64 PBKDF2 iterations, string options
//! 3. client: A, opaque M1, string options (echoed), opaque 16 random bytes
//! 4. server: opaque M2, opaque server random, string "", u32 0
//!
//! then the ordinary SecurityResult. Math (all numbers padded to the length of N where noted):
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
//! Sources: remotex `docs/apple-vnc-889.md` (message grammar, MIT) and the iShareScreen protocol
//! notes and client (read for protocol facts only; nothing copied). Type 36's framing has not
//! been captured by either; type 33 carries the same SRP messages inside an RSA envelope and is
//! known to work with this math.

use crate::error::{Result, VncError};
use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};

/// Largest SRP message we accept from the server.
pub(crate) const MAX_MESSAGE: u32 = 64 * 1024;
/// PBKDF2 iteration cap: a hostile server must not be able to stall us for minutes.
pub(crate) const MAX_ITERATIONS: u64 = 5_000_000;
/// Smallest group we accept (bytes of N). macOS uses 512.
const MIN_N: usize = 128;
const MAX_N: usize = 1024;

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
    pub expected_m2: Vec<u8>,
    pub wrap_key: [u8; 16],
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
    let n = c.big("modulus N")?.to_vec();
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

/// Run the client side of SRP-6a with a caller-supplied private exponent (for tests).
pub(crate) fn client_proof_with(ch: &Challenge, password: &str, a_private: &[u8]) -> Result<Proof> {
    let len = ch.n.len();
    if !(MIN_N..=MAX_N).contains(&len) {
        return Err(VncError::Security(format!("SRP: the server's group is {} bits; refusing it", len * 8)));
    }
    if ch.iterations == 0 || ch.iterations > MAX_ITERATIONS {
        return Err(VncError::Security(format!(
            "SRP: the server asks for {} PBKDF2 iterations (accepted: 1 to {MAX_ITERATIONS})",
            ch.iterations
        )));
    }
    let n = BigUint::from_bytes_be(&ch.n);
    let g = BigUint::from_bytes_be(&ch.g);
    let b = BigUint::from_bytes_be(&ch.b);
    let zero = BigUint::from(0u8);
    if n.bits() < (len as u64 - 1) * 8 || g < BigUint::from(2u8) || g >= n {
        return Err(VncError::Security("SRP: the server sent invalid group parameters".into()));
    }
    if &b % &n == zero {
        return Err(VncError::Security("SRP: the server sent an invalid public value (B mod N = 0)".into()));
    }
    let g_pad = pad(&g, len);
    let b_pad = pad(&b, len);

    let mut stretched = [0u8; 128];
    pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &ch.salt, ch.iterations as u32, &mut stretched);
    let x = BigUint::from_bytes_be(&h(&[&ch.salt, &h(&[b":", &stretched])]));
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
    let base = ((&b % &n) + &n - kgx) % &n;
    let s = base.modpow(&(&a + &u * &x), &n);
    let key = h(&[&pad(&s, len)]);

    let hn = h(&[&ch.n]);
    let hg = h(&[&g_pad]);
    let xor: Vec<u8> = hn.iter().zip(&hg).map(|(p, q)| p ^ q).collect();
    let m1 = h(&[&xor, &h(&[b""]), &ch.salt, &a_pad, &b_pad, &key]);
    let expected_m2 = h(&[&a_pad, &m1, &key]);
    let wrap: [u8; 32] = Sha256::digest(&key).into();
    let wrap_key: [u8; 16] = wrap[..16].try_into().expect("16 bytes");
    Ok(Proof { a_padded: a_pad, m1, expected_m2, wrap_key })
}

/// [`client_proof_with`] using a random 64-byte private exponent.
pub(crate) fn client_proof(ch: &Challenge, password: &str) -> Result<Proof> {
    let mut a = [0u8; 64];
    getrandom::fill(&mut a).map_err(|e| VncError::Other(format!("could not get random bytes from the OS: {e}")))?;
    client_proof_with(ch, password, &a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{hex, unhex, PRIME_1024};

    /// Inputs of the known-answer vector (see `KAT_*`).
    fn kat_challenge() -> Challenge {
        Challenge {
            n: unhex(PRIME_1024),
            g: vec![5],
            salt: (0..32u8).collect(),
            b: unhex(KAT_B),
            iterations: 1000,
            options: b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2".to_vec(),
        }
    }

    /// Computed independently in Python (hashlib + pow, no Rust involved) from the formulas in
    /// the module docs: N = the 1024-bit RFC 2409 prime, g = 5, salt = 00..1f, password
    /// "p@ss wörd", 1000 iterations, server private b = 0x77 * 40 bytes, client private
    /// a = 0x42 * 64 bytes. B = k*g^x + g^b mod N.
    const KAT_B: &str =
        "7513ebacaf237f8f5d4715489ba863f37d985cb429ed5d63da245317a9f7a707065dcb314cc81021ccc31c47900a7b5c45498a7f676f065a8c722f0705144cc2f790635ee0b7756a048e2e72aa7d00c61ea0360f683342acfc6349093528f88c47f52bdd340f944967a3010af6b915a8438575877072e060ba1c846e57e0382a";
    const KAT_A: &str =
        "d693cdefe674752dc0d413437decc5e7735aa34b856df74ce0f3085ca6db1c9feac6e3fa955a1fb99e945fc7884d99af5e75d363f222801fa3c11dfd50300fef5c586766ef5d5bc689d7d8ddf9ad5362cad2568053b02b10b2ba907ab6fe34866913991ed3da286c49ecabad16d387b2728048e66b00273f5ffe856a99d21d9c";
    const KAT_M1: &str =
        "6e45696ba2a6980bdb2e9e083e11a27ec2124303e3e74cb5c32b328583ecd341666c872ab691a590a5376f670ab3bfeb9b7234361c70030f0bd39cf2f79ac0d5";
    const KAT_M2: &str =
        "164fcda4c37eb9dda8b5ddab1561f9a150e2dfc05682a0471453552230175f8e142127172b0213baa0d901202c16abd6a9f5ebd4cf323ee1b37b5a4e81555be4";
    const KAT_WRAP: &str = "d1f42949940ffbbd1f3d7864e5febd68";

    #[test]
    fn known_answer_vector() {
        let p = client_proof_with(&kat_challenge(), "p@ss wörd", &[0x42; 64]).unwrap();
        assert_eq!(hex(&p.a_padded), KAT_A);
        assert_eq!(hex(&p.m1), KAT_M1);
        assert_eq!(hex(&p.expected_m2), KAT_M2);
        assert_eq!(hex(&p.wrap_key), KAT_WRAP);
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
        let mut ch = kat_challenge();
        ch.iterations = MAX_ITERATIONS + 1;
        assert!(matches!(client_proof_with(&ch, "p", &[1; 64]), Err(VncError::Security(_))));
        let mut ch = kat_challenge();
        ch.b = ch.n.clone(); // B = N, so B mod N = 0
        assert!(matches!(client_proof_with(&ch, "p", &[1; 64]), Err(VncError::Security(_))));
        let mut ch = kat_challenge();
        ch.n = vec![0xff; 32]; // 256-bit group
        assert!(matches!(client_proof_with(&ch, "p", &[1; 64]), Err(VncError::Security(_))));
    }
}
