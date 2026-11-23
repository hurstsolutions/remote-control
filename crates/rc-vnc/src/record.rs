//! Apple Screen Sharing's encrypted record layer (RFB 003.889).
//!
//! Once the Mac has sent its rekey (see `crate::apple`), every byte in both directions travels
//! inside records:
//!
//! ```text
//! wire       u16 ciphertext_len || ciphertext
//! plaintext  u16 body_len || body || filler || SHA1(u32_be(seq) || plaintext before the hash)
//!            filler_len = (-(2 + body_len + 20)) mod 16
//! ```
//!
//! * One AES-128-CBC chain per direction for the whole session: a record's last ciphertext block
//!   is the next record's IV. Both directions start from the key and IV of the rekey.
//! * One sequence counter per direction, starting at 0, never on the wire, only in the hash.
//! * Server to client, a large message spans consecutive records and is reassembled by
//!   concatenating their bodies, so the read side is simply a byte stream.
//! * Client to server, a record carries exactly one message (a Mac reads one message per record
//!   and drops anything after it). The write side therefore splits what it is given into RFB
//!   client messages and frames each on its own; a message too big for one record (a large
//!   clipboard) goes out as consecutive full records, which the Mac reassembles.
//!
//! [`RecordStream`] wraps the socket as an `AsyncRead + AsyncWrite`, so the session code above
//! it (the decoders included) is the same in cleartext and encrypted sessions. Nothing reaches
//! the reader before its record's integrity hash has been checked, and a failed check is
//! terminal.
//!
//! The record reader's state machine, the CBC/sequence handling and the length rules are
//! adapted from remotex (`src/vnc_record.rs`, <https://github.com/andrewtheguy/remotex>):
//!
//! > MIT License. Copyright (c) 2026 Andrew Chen.
//! > Permission is hereby granted, free of charge, to any person obtaining a copy of this
//! > software and associated documentation files (the "Software"), to deal in the Software
//! > without restriction, including without limitation the rights to use, copy, modify, merge,
//! > publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
//! > to whom the Software is furnished to do so, subject to the following conditions: The above
//! > copyright notice and this permission notice shall be included in all copies or substantial
//! > portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! > EXPRESS OR IMPLIED.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace, warn};

const BLOCK: usize = 16;
/// SHA-1 integrity hash at the end of every record's plaintext.
const TRAILER: usize = 20;
/// The `u16 body_len` at the front of every record's plaintext.
const BODY_LEN: usize = 2;
/// Length of the rekey body: `u32 generation`, then the wrapped key and IV.
pub(crate) const REKEY_LEN: usize = 4 + BLOCK + BLOCK;
/// Largest ciphertext the `u16` prefix can describe, rounded down to whole blocks (65,520).
pub(crate) const MAX_CIPHERTEXT: usize = (u16::MAX as usize / BLOCK) * BLOCK;
/// Largest body of one record (65,498).
pub(crate) const MAX_BODY: usize = MAX_CIPHERTEXT - BODY_LEN - TRAILER;
/// Ciphertext queued for the socket beyond which `poll_write` stops accepting more.
const HIGH_WATER: usize = 1 << 20;

/// Filler between a body and its hash: the least that makes the plaintext whole blocks.
const fn filler_len(body_len: usize) -> usize {
    (BLOCK - (BODY_LEN + body_len + TRAILER) % BLOCK) % BLOCK
}

/// Smallest legal record (an empty body): 32 bytes.
const MIN_CIPHERTEXT: usize = BODY_LEN + filler_len(0) + TRAILER;

/// The AES-128 key and IV installed by a rekey. Same starting values for both directions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Keys {
    pub key: [u8; BLOCK],
    pub iv: [u8; BLOCK],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str("Keys(<redacted>)")
    }
}

/// Recover the record layer's key and IV from a rekey body. The two halves are single
/// AES-128-ECB blocks under the wrap key (for type 30, MD5 of the DH shared secret), each
/// decrypted on its own. Returns the generation word too, for the log.
pub(crate) fn unwrap_rekey(wrap_key: &[u8; BLOCK], body: &[u8; REKEY_LEN]) -> (u32, Keys) {
    let cipher = Aes128::new(wrap_key.into());
    let generation = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let unwrap = |at: usize| {
        let mut block: [u8; BLOCK] = body[at..at + BLOCK].try_into().expect("16 bytes");
        cipher.decrypt_block((&mut block).into());
        block
    };
    (generation, Keys { key: unwrap(4), iv: unwrap(4 + BLOCK) })
}

/// An error raised by the record layer itself (integrity failure, malformed record, a client
/// message it cannot frame). Carried inside `io::Error` so the session can report it as a
/// security problem rather than as a dropped connection.
#[derive(Debug)]
pub(crate) struct RecordError(pub String);

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecordError {}

fn record_error(kind: io::ErrorKind, msg: impl Into<String>) -> io::Error {
    io::Error::new(kind, RecordError(msg.into()))
}

/// One direction's cipher, chaining block and record counter. Never reset.
struct Cbc {
    cipher: Aes128,
    chain: [u8; BLOCK],
    seq: u32,
}

impl Cbc {
    fn new(keys: Keys) -> Self {
        Cbc { cipher: Aes128::new(&keys.key.into()), chain: keys.iv, seq: 0 }
    }

    /// CBC-encrypt whole blocks in place, advancing the chain.
    fn encrypt(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(BLOCK) {
            let block: &mut [u8; BLOCK] = block.try_into().expect("16-byte chunk");
            for (b, c) in block.iter_mut().zip(self.chain) {
                *b ^= c;
            }
            self.cipher.encrypt_block(block.into());
            self.chain = *block;
        }
    }

    /// CBC-decrypt whole blocks in place, advancing the chain.
    fn decrypt(&mut self, data: &mut [u8]) {
        for block in data.chunks_exact_mut(BLOCK) {
            let block: &mut [u8; BLOCK] = block.try_into().expect("16-byte chunk");
            let ciphertext = *block;
            self.cipher.decrypt_block(block.into());
            for (b, c) in block.iter_mut().zip(self.chain) {
                *b ^= c;
            }
            self.chain = ciphertext;
        }
    }

    /// The integrity hash for a record whose plaintext before the hash is `covered`; consumes
    /// one sequence number.
    fn trailer(&mut self, covered: &[u8]) -> [u8; TRAILER] {
        let hash = trailer_at(self.seq, covered);
        self.seq = self.seq.wrapping_add(1);
        hash
    }
}

fn trailer_at(seq: u32, covered: &[u8]) -> [u8; TRAILER] {
    let mut h = Sha1::new();
    h.update(seq.to_be_bytes());
    h.update(covered);
    h.finalize().into()
}

/// Length of the RFB client-to-server message at the start of `b`, or `None` if more bytes
/// are needed to tell. Only the messages this client sends are known; anything else is an
/// internal error (it would be framed wrongly, and the Mac would misread the rest).
fn client_message_len(b: &[u8]) -> Result<Option<usize>, String> {
    let Some(&t) = b.first() else { return Ok(None) };
    let u16_at = |i: usize| b.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]]) as usize);
    let len = match t {
        0 => Some(20),                                  // SetPixelFormat
        2 => u16_at(2).map(|n| 4 + 4 * n),              // SetEncodings
        3 => Some(10),                                  // FramebufferUpdateRequest
        4 => Some(8),                                   // KeyEvent
        5 => Some(6),                                   // PointerEvent
        6 => b.get(4..8).map(|s| 8 + u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize), // ClientCutText
        0x0a => Some(4),                                // Apple SetMode
        0x21 => u16_at(2).map(|n| 4 + n),               // Apple ViewerInfo
        251 => b.get(6).map(|&n| 8 + 16 * n as usize),  // SetDesktopSize
        other => return Err(format!("internal error: cannot frame client message type {other} for the record layer")),
    };
    Ok(len)
}

/// Frames client messages into records.
struct Writer {
    cbc: Cbc,
    /// Plaintext not yet framed: the start of a message whose end has not been written yet.
    pending: Vec<u8>,
    /// Framed ciphertext not yet handed to the socket, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
}

impl Writer {
    /// Append one record carrying `body` to `out`.
    fn push_record(&mut self, body: &[u8]) {
        debug_assert!(body.len() <= MAX_BODY);
        let total = BODY_LEN + body.len() + filler_len(body.len()) + TRAILER;
        self.out.extend_from_slice(&(total as u16).to_be_bytes());
        let start = self.out.len();
        self.out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        self.out.extend_from_slice(body);
        // Zero filler: the Mac does not check it, and the CBC chain already randomises.
        self.out.resize(start + total - TRAILER, 0);
        let seq = self.cbc.seq;
        let hash = self.cbc.trailer(&self.out[start..]);
        self.out.extend_from_slice(&hash);
        self.cbc.encrypt(&mut self.out[start..]);
        trace!(seq, body = body.len(), ciphertext = total, "record layer: sent record");
    }

    /// Frame one whole message, in as many records as it needs (at least one).
    fn frame(&mut self, msg: &[u8]) {
        let mut rest = msg;
        loop {
            let (body, after) = rest.split_at(rest.len().min(MAX_BODY));
            self.push_record(body);
            rest = after;
            if rest.is_empty() {
                break;
            }
        }
        if msg.len() > MAX_BODY {
            debug!(bytes = msg.len(), records = msg.len().div_ceil(MAX_BODY), "record layer: large message split");
        }
    }

    /// Move every complete message from `pending` into records.
    fn frame_pending(&mut self) -> Result<(), String> {
        let mut at = 0;
        while let Some(len) = client_message_len(&self.pending[at..])? {
            if self.pending.len() - at < len {
                break;
            }
            let msg = std::mem::take(&mut self.pending);
            self.frame(&msg[at..at + len]);
            self.pending = msg;
            at += len;
        }
        self.pending.drain(..at);
        Ok(())
    }

    fn queued(&self) -> usize {
        self.out.len() - self.out_pos
    }
}

enum Phase {
    /// Reading the two outer length bytes.
    Len,
    /// Reading `len` bytes of ciphertext.
    Ciphertext { len: usize },
}

/// Reads records and yields the concatenation of their verified bodies.
struct Reader {
    cbc: Cbc,
    staging: Vec<u8>,
    filled: usize,
    phase: Phase,
    /// The verified body inside `staging` not yet handed upward.
    body: std::ops::Range<usize>,
    /// A record failed: terminal (reading on would re-decrypt and re-count the same bytes).
    failed: bool,
}

impl Reader {
    /// Decrypt and verify the record in `staging[..len]`, returning its body's range.
    /// `len` is a whole number of blocks and at least `MIN_CIPHERTEXT`.
    fn accept(&mut self, len: usize) -> io::Result<std::ops::Range<usize>> {
        self.cbc.decrypt(&mut self.staging[..len]);
        let covered = len - TRAILER;
        let seq = self.cbc.seq;
        let expected = self.cbc.trailer(&self.staging[..covered]);
        if self.staging[covered..len] != expected {
            let hint = miscounted(seq, &self.staging[..covered], &self.staging[covered..len]);
            warn!(seq, len, hint, "record layer: integrity check failed");
            return Err(record_error(
                io::ErrorKind::InvalidData,
                format!("encrypted record {seq} ({len} bytes) failed its integrity check{hint}"),
            ));
        }
        let body_len = u16::from_be_bytes([self.staging[0], self.staging[1]]) as usize;
        if BODY_LEN + body_len + TRAILER > len {
            return Err(record_error(
                io::ErrorKind::InvalidData,
                format!("encrypted record {seq} claims a {body_len}-byte body but is only {len} bytes"),
            ));
        }
        trace!(seq, body = body_len, ciphertext = len, "record layer: received record");
        Ok(BODY_LEN..BODY_LEN + body_len)
    }
}

/// For the error message: whether a failed record's hash fits a neighbouring sequence number,
/// which means it decrypted fine and only the count disagrees.
fn miscounted(seq: u32, covered: &[u8], trailer: &[u8]) -> &'static str {
    if trailer_at(seq.wrapping_sub(1), covered) == trailer {
        "; its hash matches the previous sequence number (the counts disagree)"
    } else if trailer_at(seq.wrapping_add(1), covered) == trailer {
        "; its hash matches the next sequence number (the counts disagree)"
    } else {
        ""
    }
}

/// Apple's record layer over a byte stream, as a byte stream.
///
/// Construct it around the stream right after the rekey has been read off it in cleartext.
/// The handshake reads unbuffered, so no record bytes can be stranded in a buffer.
pub(crate) struct RecordStream<S> {
    inner: S,
    rd: Reader,
    wr: Writer,
}

impl<S> RecordStream<S> {
    pub fn new(inner: S, keys: Keys) -> Self {
        RecordStream {
            inner,
            rd: Reader {
                cbc: Cbc::new(keys),
                staging: Vec::new(),
                filled: 0,
                phase: Phase::Len,
                body: 0..0,
                failed: false,
            },
            wr: Writer { cbc: Cbc::new(keys), pending: Vec::new(), out: Vec::new(), out_pos: 0 },
        }
    }
}

fn poll_fill<R: AsyncRead + Unpin>(inner: &mut R, cx: &mut Context<'_>, dst: &mut [u8]) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(dst);
    ready!(Pin::new(inner).poll_read(cx, &mut buf))?;
    Poll::Ready(Ok(buf.filled().len()))
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "the connection ended in the middle of an encrypted record")
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        let rd = &mut me.rd;
        if rd.failed {
            return Poll::Ready(Err(record_error(io::ErrorKind::InvalidData, "the encrypted record layer already failed")));
        }
        loop {
            // Verified bytes only.
            if !rd.body.is_empty() {
                let n = buf.remaining().min(rd.body.len());
                let from = rd.body.start;
                buf.put_slice(&rd.staging[from..from + n]);
                rd.body.start += n;
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            match rd.phase {
                Phase::Len => {
                    rd.staging.resize(BODY_LEN, 0);
                    let n = ready!(poll_fill(&mut me.inner, cx, &mut rd.staging[rd.filled..BODY_LEN]))?;
                    if n == 0 {
                        // Between records: an ordinary end of stream.
                        return if rd.filled == 0 { Poll::Ready(Ok(())) } else { Poll::Ready(Err(truncated())) };
                    }
                    rd.filled += n;
                    if rd.filled == BODY_LEN {
                        let len = u16::from_be_bytes([rd.staging[0], rd.staging[1]]) as usize;
                        if len < MIN_CIPHERTEXT || !len.is_multiple_of(BLOCK) {
                            rd.failed = true;
                            warn!(len, "record layer: malformed record length");
                            return Poll::Ready(Err(record_error(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "the server sent an encrypted record of {len} bytes, which is not a multiple of \
                                     {BLOCK} of at least {MIN_CIPHERTEXT}"
                                ),
                            )));
                        }
                        rd.staging.resize(len, 0);
                        rd.filled = 0;
                        rd.phase = Phase::Ciphertext { len };
                    }
                }
                Phase::Ciphertext { len } => {
                    let n = ready!(poll_fill(&mut me.inner, cx, &mut rd.staging[rd.filled..len]))?;
                    if n == 0 {
                        return Poll::Ready(Err(truncated()));
                    }
                    rd.filled += n;
                    if rd.filled == len {
                        rd.body = match rd.accept(len) {
                            Ok(body) => body,
                            Err(e) => {
                                rd.failed = true;
                                return Poll::Ready(Err(e));
                            }
                        };
                        rd.filled = 0;
                        rd.phase = Phase::Len;
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> RecordStream<S> {
    /// Write queued ciphertext to the socket until it is all gone (or the socket is busy).
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wr.out_pos < self.wr.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wr.out[self.wr.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wr.out_pos += n;
        }
        self.wr.out.clear();
        self.wr.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if me.wr.queued() >= HIGH_WATER {
            ready!(me.poll_drain(cx))?;
        }
        me.wr.pending.extend_from_slice(buf);
        if let Err(msg) = me.wr.frame_pending() {
            me.wr.pending.clear();
            return Poll::Ready(Err(record_error(io::ErrorKind::InvalidInput, msg)));
        }
        // Opportunistic: push what we can now; the rest goes on the next write or flush.
        if let Poll::Ready(Err(e)) = me.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        ready!(me.poll_drain(cx))?;
        if !me.wr.pending.is_empty() {
            // Not an error: the caller may still write the rest of the message. Every caller in
            // this crate writes whole messages, so this is only worth a note in the log.
            debug!(bytes = me.wr.pending.len(), "record layer: flush with a partial client message held back");
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        ready!(me.poll_drain(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{hex, unhex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn keys() -> Keys {
        Keys { key: *b"0123456789abcdef", iv: *b"fedcba9876543210" }
    }

    /// Frame `msgs` as the client would and return the wire bytes.
    fn frame_all(msgs: &[&[u8]]) -> Vec<u8> {
        let mut w = Writer { cbc: Cbc::new(keys()), pending: Vec::new(), out: Vec::new(), out_pos: 0 };
        for m in msgs {
            w.frame(m);
        }
        w.out
    }

    async fn read_all(wire: Vec<u8>, n: usize) -> io::Result<Vec<u8>> {
        let mut rs = RecordStream::new(std::io::Cursor::new(wire), keys());
        let mut got = vec![0u8; n];
        rs.read_exact(&mut got).await?;
        Ok(got)
    }

    #[test]
    fn filler_table() {
        // (-(2 + n + 20)) mod 16, written out by hand.
        for (body, filler) in [(0usize, 10usize), (1, 9), (10, 0), (11, 15), (14, 12), (16, 10), (26, 0), (300, 14)] {
            assert_eq!(filler_len(body), filler, "body {body}");
        }
        assert_eq!(MIN_CIPHERTEXT, 32);
        assert_eq!(MAX_CIPHERTEXT, 65_520);
        assert_eq!(MAX_BODY, 65_498);
    }

    /// Known-answer vectors computed independently with OpenSSL and sha1sum (no Rust code
    /// involved), for two consecutive records "ping" (seq 0) and "pong" (seq 1) under
    /// key "0123456789abcdef", IV "fedcba9876543210":
    ///
    /// ```sh
    /// p0=$(printf '0004'; printf ping | xxd -p; printf '%012d' 0)   # body_len, body, 6 B zero filler
    /// h0=$( (printf '00000000'; echo -n $p0) | xxd -r -p | sha1sum | cut -c1-40)
    /// echo -n $p0$h0 | xxd -r -p | openssl enc -aes-128-cbc -nopad \
    ///     -K 30313233343536373839616263646566 -iv 66656463626139383736353433323130 | xxd -p
    /// # record 1: same with seq 00000001, body "pong", IV = last ciphertext block of record 0
    /// ```
    const KAT_PING: &str = "b823ca4d56a923e21bf94b02c3763584a70e5aacd07c270420adf75dced4d9ca";
    const KAT_PONG: &str = "852516fbd36bc6c007a9089140dfb3093c6029426154e98af2b9a1f746e5333a";

    #[test]
    fn known_answer_records() {
        let wire = frame_all(&[b"ping", b"pong"]);
        assert_eq!(wire.len(), 2 * (2 + 32));
        assert_eq!(&wire[..2], &[0, 32]);
        assert_eq!(hex(&wire[2..34]), KAT_PING);
        assert_eq!(&wire[34..36], &[0, 32]);
        assert_eq!(hex(&wire[36..]), KAT_PONG);
    }

    #[test]
    fn known_answer_rekey_unwrap() {
        // openssl enc -aes-128-ecb -nopad -K <wrap> on the key and the IV, each one block.
        let wrap: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let mut body = [0u8; REKEY_LEN];
        body[..4].copy_from_slice(&1u32.to_be_bytes());
        body[4..20].copy_from_slice(&unhex(KAT_WRAPPED_KEY));
        body[20..].copy_from_slice(&unhex(KAT_WRAPPED_IV));
        let (generation, k) = unwrap_rekey(&wrap, &body);
        assert_eq!(generation, 1);
        assert_eq!(k, keys());
        // Swapping the halves swaps the results: each block is decrypted on its own (ECB).
        body[4..20].copy_from_slice(&unhex(KAT_WRAPPED_IV));
        body[20..].copy_from_slice(&unhex(KAT_WRAPPED_KEY));
        let (_, swapped) = unwrap_rekey(&wrap, &body);
        assert_eq!((swapped.key, swapped.iv), (keys().iv, keys().key));
    }
    const KAT_WRAPPED_KEY: &str = "281567ab2f4cf0d73d3198225b8b8393";
    const KAT_WRAPPED_IV: &str = "16d2c2de44a33d9259711187a8b20483";

    #[tokio::test]
    async fn round_trip_and_chain_carries_over() {
        let wire = frame_all(&[b"first", b"second"]);
        assert_eq!(read_all(wire.clone(), 11).await.unwrap(), b"firstsecond");
        // The second record alone, through a fresh chain, must fail.
        let second = wire[2 + 32..].to_vec();
        let err = read_all(second, 1).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tampered_record_yields_nothing_and_is_terminal() {
        let mut wire = frame_all(&[b"payload"]);
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut rs = RecordStream::new(std::io::Cursor::new(wire), keys());
        let mut got = [0u8; 7];
        let err = rs.read_exact(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.get_ref().unwrap().downcast_ref::<RecordError>().is_some());
        assert!(err.to_string().contains("integrity"), "{err}");
        assert_eq!(got, [0; 7]);
        let err = rs.read_u8().await.unwrap_err();
        assert!(err.to_string().contains("already failed"), "{err}");
    }

    #[tokio::test]
    async fn sequence_number_is_in_the_hash() {
        let mut w = Writer { cbc: Cbc::new(keys()), pending: Vec::new(), out: Vec::new(), out_pos: 0 };
        w.frame(b"first");
        w.cbc.seq = 0; // a sender that counts wrong
        w.frame(b"second");
        let err = read_all(w.out, 11).await.unwrap_err();
        assert!(err.to_string().contains("record 1"), "{err}");
        assert!(err.to_string().contains("previous sequence number"), "{err}");
    }

    #[tokio::test]
    async fn malformed_lengths_are_refused() {
        for len in [0u16, 16, 17, 33] {
            let mut wire = len.to_be_bytes().to_vec();
            wire.resize(2 + 64, 0);
            let err = read_all(wire, 1).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "len {len}");
        }
    }

    #[tokio::test]
    async fn clean_eof_between_records_but_not_inside_one() {
        let wire = frame_all(&[b"hi"]);
        let mut rs = RecordStream::new(std::io::Cursor::new(wire.clone()), keys());
        let mut got = Vec::new();
        rs.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hi");
        let cut = wire[..wire.len() - 4].to_vec();
        let mut rs = RecordStream::new(std::io::Cursor::new(cut), keys());
        let err = rs.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Yields one byte per poll, like a busy socket.
    struct Trickle<R>(R);
    impl<R: AsyncRead + Unpin> AsyncRead for Trickle<R> {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let mut one = [0u8; 1];
            let n = ready!(poll_fill(&mut self.0, cx, &mut one))?;
            buf.put_slice(&one[..n]);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn large_message_spans_records_and_reassembles_byte_by_byte() {
        let blob: Vec<u8> = (0..2 * MAX_BODY + 5).map(|i| (i % 251) as u8).collect();
        let mut wire = frame_all(&[&blob, b"next"]);
        let mut lens = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            let len = u16::from_be_bytes([wire[at], wire[at + 1]]) as usize;
            lens.push(len);
            at += 2 + len;
        }
        assert_eq!(lens, [MAX_CIPHERTEXT, MAX_CIPHERTEXT, 32, 32]);
        let mut rs = RecordStream::new(Trickle(std::io::Cursor::new(std::mem::take(&mut wire))), keys());
        let mut got = vec![0u8; blob.len() + 4];
        rs.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[..blob.len()], &blob[..]);
        assert_eq!(&got[blob.len()..], b"next");
    }

    #[test]
    fn client_message_lengths() {
        assert_eq!(client_message_len(&[]), Ok(None));
        assert_eq!(client_message_len(&[0]), Ok(Some(20)));
        assert_eq!(client_message_len(&[2, 0]), Ok(None));
        assert_eq!(client_message_len(&[2, 0, 0, 3]), Ok(Some(16)));
        assert_eq!(client_message_len(&[3]), Ok(Some(10)));
        assert_eq!(client_message_len(&[4]), Ok(Some(8)));
        assert_eq!(client_message_len(&[5]), Ok(Some(6)));
        assert_eq!(client_message_len(&[6, 0, 0, 0, 0, 1, 0]), Ok(None));
        assert_eq!(client_message_len(&[6, 0, 0, 0, 0, 1, 0, 0]), Ok(Some(8 + 65536)));
        assert_eq!(client_message_len(&[251, 0, 0, 1, 0, 1]), Ok(None));
        assert_eq!(client_message_len(&[251, 0, 0, 1, 0, 1, 2]), Ok(Some(40)));
        assert_eq!(client_message_len(&[0x21, 0, 0, 62]), Ok(Some(66)));
        assert!(client_message_len(&[99]).is_err());
    }

    /// The writer splits a batch of messages into one record each, whatever the write
    /// boundaries, and holds back a partial message until the rest arrives.
    #[tokio::test]
    async fn writes_are_split_into_one_record_per_message() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let mut rs = RecordStream::new(a, keys());
        let pointer = [5u8, 1, 0, 10, 0, 20];
        let key = [4u8, 1, 0, 0, 0, 0, 0, 0x61];
        let mut batch = pointer.to_vec();
        batch.extend_from_slice(&key);
        batch.extend_from_slice(&[3, 1, 0]); // first 3 bytes of an update request
        rs.write_all(&batch).await.unwrap();
        rs.flush().await.unwrap();
        rs.write_all(&[0, 0, 0, 0, 4, 0, 3]).await.unwrap();
        rs.flush().await.unwrap();
        drop(rs);
        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();

        // Decrypt record by record with an independent reader over the client's direction.
        let mut cbc = Cbc::new(keys());
        let mut bodies = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            let len = u16::from_be_bytes([wire[at], wire[at + 1]]) as usize;
            let mut rec = wire[at + 2..at + 2 + len].to_vec();
            cbc.decrypt(&mut rec);
            let expect = cbc.trailer(&rec[..len - TRAILER]);
            assert_eq!(&rec[len - TRAILER..], &expect);
            let n = u16::from_be_bytes([rec[0], rec[1]]) as usize;
            bodies.push(rec[2..2 + n].to_vec());
            at += 2 + len;
        }
        assert_eq!(bodies, vec![pointer.to_vec(), key.to_vec(), vec![3, 1, 0, 0, 0, 0, 0, 4, 0, 3]]);
    }

    #[tokio::test]
    async fn unknown_client_message_is_an_error() {
        let (a, _b) = tokio::io::duplex(1024);
        let mut rs = RecordStream::new(a, keys());
        let err = rs.write_all(&[200, 1, 2, 3]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
