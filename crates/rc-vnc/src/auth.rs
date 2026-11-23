//! Authentication crypto: classic VNC DES challenge-response (security type 2) and Apple Remote
//! Desktop Diffie-Hellman + AES (security type 30).

use crate::error::{Result, VncError};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use md5::{Digest, Md5};
use num_bigint::BigUint;

/// Classic VNC authentication response.
///
/// The DES key is the first 8 bytes of the password (NUL padded) with the bits of every byte
/// reversed (the well-known VNC quirk); the 16-byte challenge is encrypted as two ECB blocks.
pub(crate) fn vnc_des_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.as_bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = des::Des::new(&key.into());
    let mut out = *challenge;
    for block in out.chunks_exact_mut(8) {
        let block: &mut [u8; 8] = block.try_into().expect("8-byte chunk");
        cipher.encrypt_block(block.into());
    }
    out
}

/// Left-pad a big-endian number to `len` bytes (or keep its low `len` bytes, which cannot
/// happen for values reduced modulo a `len`-byte prime).
fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if bytes.len() >= len {
        out.copy_from_slice(&bytes[bytes.len() - len..]);
    } else {
        out[len - bytes.len()..].copy_from_slice(bytes);
    }
    out
}

/// Copy `s` as a NUL-terminated C string into a 64-byte field (at most 63 bytes kept, as
/// libvncclient and Apple's own client do). Bytes after the NUL keep their random filler.
fn put_cstr(field: &mut [u8], s: &str) -> bool {
    let bytes = s.as_bytes();
    let n = bytes.len().min(field.len() - 1);
    field[..n].copy_from_slice(&bytes[..n]);
    field[n] = 0;
    n < bytes.len()
}

/// Apple Remote Desktop (type 30) response with caller-supplied randomness (for tests).
///
/// * `prime`, `server_pub`: big-endian, `key_len` bytes each, as received.
/// * `private`: our DH private key (big-endian bytes).
/// * `filler`: 128 random bytes that pad the credentials block.
///
/// Returns `ciphertext (128 bytes) || our public key (key_len bytes, left-padded)`, and the
/// AES key (MD5 of the shared secret). The key is also the wrap key for the encrypted session's
/// first rekey (see `crate::record::unwrap_rekey`); it is secret and must never be logged.
pub(crate) fn ard_response_with(
    generator: u16,
    prime: &[u8],
    server_pub: &[u8],
    username: &str,
    password: &str,
    private: &[u8],
    filler: [u8; 128],
) -> Result<ArdResponse> {
    let key_len = prime.len();
    let p = BigUint::from_bytes_be(prime);
    if p <= BigUint::from(2u8) {
        return Err(VncError::Protocol("Apple auth: server sent an invalid Diffie-Hellman prime".into()));
    }
    let g = BigUint::from(generator);
    let server_pub = BigUint::from_bytes_be(server_pub);
    let private = BigUint::from_bytes_be(private);

    let public = g.modpow(&private, &p);
    let shared = server_pub.modpow(&private, &p);

    // AES-128 key = MD5 of the shared secret, left-padded with zeros to the key length.
    let shared_bytes = left_pad(&shared.to_bytes_be(), key_len);
    let aes_key: [u8; 16] = Md5::digest(&shared_bytes).into();

    let mut block = filler;
    let user_trunc = put_cstr(&mut block[..64], username);
    let pass_trunc = put_cstr(&mut block[64..], password);
    if user_trunc || pass_trunc {
        tracing::warn!(
            username_truncated = user_trunc,
            password_truncated = pass_trunc,
            "Apple auth: username/password longer than 63 bytes was truncated"
        );
    }

    let cipher = aes::Aes128::new(&aes_key.into());
    for chunk in block.chunks_exact_mut(16) {
        let chunk: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        cipher.encrypt_block(chunk.into());
    }

    let mut out = Vec::with_capacity(128 + key_len);
    out.extend_from_slice(&block);
    out.extend_from_slice(&left_pad(&public.to_bytes_be(), key_len));
    Ok(ArdResponse { message: out, wrap_key: aes_key })
}

/// What type 30 sends, and the key it leaves behind.
pub(crate) struct ArdResponse {
    pub message: Vec<u8>,
    pub wrap_key: [u8; 16],
}

/// Apple Remote Desktop (type 30) response using OS randomness.
pub(crate) fn ard_response(
    generator: u16,
    prime: &[u8],
    server_pub: &[u8],
    username: &str,
    password: &str,
) -> Result<ArdResponse> {
    let mut private = vec![0u8; prime.len()];
    let mut filler = [0u8; 128];
    getrandom::fill(&mut private)
        .and_then(|_| getrandom::fill(&mut filler))
        .map_err(|e| VncError::Other(format!("could not get random bytes from the OS: {e}")))?;
    ard_response_with(generator, prime, server_pub, username, password, &private, filler)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use aes::cipher::BlockCipherDecrypt;

    #[test]
    fn des_known_vector() {
        // Independently computed with OpenSSL:
        //   key  = bit-reversed "password" = 0e86cece eef64e26
        //   echo 000102030405060708090a0b0c0d0e0f | xxd -r -p |
        //     openssl enc -des-ecb -K 0e86ceceeef64e26 -nopad -provider legacy -provider default
        let challenge: [u8; 16] = core::array::from_fn(|i| i as u8);
        let resp = vnc_des_response("password", &challenge);
        assert_eq!(hex(&resp), DES_VECTOR_PASSWORD);
        // Only the first 8 characters matter.
        assert_eq!(vnc_des_response("passwordXYZ", &challenge), resp);
        // Short passwords are NUL padded.
        assert_ne!(vnc_des_response("pass", &challenge), resp);
    }

    pub(crate) const DES_VECTOR_PASSWORD: &str = "b866924125c8eebb9debc1db61c538e2";

    pub(crate) fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// 1024-bit MODP prime (RFC 2409 Oakley group 2), the size macOS uses (key length 128).
    pub(crate) const PRIME_1024: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    /// The server half of ARD auth, written independently of the client code path: holds a DH
    /// private key, and decrypts a client response into (username, password).
    pub(crate) struct MockArdServer {
        pub generator: u16,
        pub prime: Vec<u8>,
        private: BigUint,
    }

    impl MockArdServer {
        pub fn new(private_seed: u8) -> Self {
            let prime = unhex(PRIME_1024);
            let private = BigUint::from_bytes_be(&[private_seed; 100]);
            MockArdServer { generator: 2, prime, private }
        }
        pub fn key_len(&self) -> usize {
            self.prime.len()
        }
        pub fn public_key(&self) -> Vec<u8> {
            let p = BigUint::from_bytes_be(&self.prime);
            left_pad(&BigUint::from(self.generator).modpow(&self.private, &p).to_bytes_be(), self.key_len())
        }
        /// The AES key (and rekey wrap key) for a client response.
        pub fn wrap_key(&self, response: &[u8]) -> [u8; 16] {
            let p = BigUint::from_bytes_be(&self.prime);
            let client_pub = BigUint::from_bytes_be(&response[128..]);
            let shared = client_pub.modpow(&self.private, &p).to_bytes_be();
            let mut padded = vec![0u8; self.key_len() - shared.len()];
            padded.extend_from_slice(&shared);
            Md5::digest(&padded).into()
        }
        /// `response` = 128 bytes ciphertext || client public key.
        pub fn decrypt(&self, response: &[u8]) -> (String, String) {
            assert_eq!(response.len(), 128 + self.key_len());
            let key = self.wrap_key(response);
            let cipher = aes::Aes128::new(&key.into());
            let mut plain = response[..128].to_vec();
            for chunk in plain.chunks_exact_mut(16) {
                let chunk: &mut [u8; 16] = chunk.try_into().unwrap();
                cipher.decrypt_block(chunk.into());
            }
            let cstr = |b: &[u8]| {
                let end = b.iter().position(|&c| c == 0).expect("NUL terminator");
                String::from_utf8(b[..end].to_vec()).unwrap()
            };
            (cstr(&plain[..64]), cstr(&plain[64..]))
        }
    }

    #[test]
    fn ard_round_trip() {
        let server = MockArdServer::new(0x5a);
        let ArdResponse { message: resp, wrap_key } =
            ard_response(2, &server.prime, &server.public_key(), "alice", "s3cret pw").unwrap();
        assert_eq!(resp.len(), 128 + 128);
        assert_eq!(server.decrypt(&resp), ("alice".to_string(), "s3cret pw".to_string()));
        assert_eq!(wrap_key, server.wrap_key(&resp));
    }

    #[test]
    fn ard_padding_and_truncation() {
        let server = MockArdServer::new(0x11);
        // Private key 1 => our public key is the generator itself (2), which must be left-padded
        // to the full key length; the shared secret is then the server's public key.
        let long_user = "u".repeat(80);
        let resp =
            ard_response_with(2, &server.prime, &server.public_key(), &long_user, "", &[1], [0xAA; 128])
                .unwrap()
                .message;
        assert_eq!(resp.len(), 256);
        assert!(resp[128..255].iter().all(|&b| b == 0));
        assert_eq!(resp[255], 2);
        let (u, p) = server.decrypt(&resp);
        assert_eq!(u, "u".repeat(63));
        assert_eq!(p, "");
    }

    #[test]
    fn ard_plaintext_layout_and_short_shared_secret() {
        // Tiny group so the shared secret is shorter than the key length and must be
        // left-padded before hashing: p = 0x0000_0000_0000_FFF1 (65521, prime) in 8 bytes, g = 2.
        let prime = [0, 0, 0, 0, 0, 0, 0xFF, 0xF1];
        let p = BigUint::from(65521u32);
        let server_priv = BigUint::from(1234u32);
        let server_pub = left_pad(&BigUint::from(2u8).modpow(&server_priv, &p).to_bytes_be(), 8);
        let filler: [u8; 128] = core::array::from_fn(|i| 0x80 | i as u8);
        let ArdResponse { message: resp, wrap_key } =
            ard_response_with(2, &prime, &server_pub, "bob", "pw", &[0x03, 0xE9], filler).unwrap();
        assert_eq!(resp.len(), 128 + 8);
        let client_pub = BigUint::from_bytes_be(&resp[128..]);
        assert_eq!(client_pub, BigUint::from(2u8).modpow(&BigUint::from(1001u32), &p));
        let shared = left_pad(&client_pub.modpow(&server_priv, &p).to_bytes_be(), 8);
        assert_eq!(&shared[..6], &[0; 6]);
        let key: [u8; 16] = Md5::digest(&shared).into();
        assert_eq!(wrap_key, key);
        let cipher = aes::Aes128::new(&key.into());
        let mut plain = resp[..128].to_vec();
        for chunk in plain.chunks_exact_mut(16) {
            let chunk: &mut [u8; 16] = chunk.try_into().unwrap();
            cipher.decrypt_block(chunk.into());
        }
        assert_eq!(&plain[..4], b"bob\0");
        assert_eq!(&plain[4..64], &filler[4..64]);
        assert_eq!(&plain[64..67], b"pw\0");
        assert_eq!(&plain[67..], &filler[67..]);
    }

    #[test]
    fn ard_rejects_bad_prime() {
        assert!(ard_response_with(2, &[0, 0], &[0, 5], "a", "b", &[3], [0; 128]).is_err());
    }
}
