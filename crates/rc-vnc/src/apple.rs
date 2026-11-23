//! Apple Screen Sharing specifics of RFB 003.889: the extended ServerInit, the cleartext prelude
//! that asks for encryption, the rekey that delivers the record-layer keys, and the metadata
//! encodings and messages a Mac may send.
//!
//! Sources: measurements published by remotex (MIT, `docs/apple-vnc-889.md`,
//! <https://github.com/andrewtheguy/remotex>) cross-checked against the iShareScreen protocol
//! notes (read for protocol facts only). The ViewerInfo bytes below are the measured form
//! remotex sends (MIT notice in `crate::record`), with one capability bit cleared (see
//! [`viewer_info`]).
//!
//! The setup, after type 30 authentication succeeded:
//!
//! 1. ClientInit `0x80 | shared`: `0x80` asks for the extended ServerInit.
//! 2. ServerInit; its "name" starts with 22 bytes of structure ([`ExtendedInit`]).
//! 3. Cleartext prelude, written back to back: ViewerInfo, SetEncryption command 1 (start, AES-128),
//!    SetEncryption command 2 (decrypt what the client sends from now on).
//! 4. The Mac answers with a FramebufferUpdate holding one 0x0 rectangle of encoding 0x44f, whose
//!    36-byte body wraps the key and IV under the authentication's wrap key. A MiscStatus or Bell
//!    may come first. Everything after that rectangle, both ways, is records.
//!
//! Stage 2 (SRP, security type 36, and type 33) slots in by producing a different wrap key; the
//! steps above stay the same.

use crate::error::{Result, VncError};
use crate::record::{self, Keys, REKEY_LEN};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, info, warn};

/// Rekey: the record layer's key and IV, as a rectangle.
pub(crate) const ENC_REKEY: i32 = 0x44f;
/// Pointer position, in the rectangle header, no payload.
pub(crate) const ENC_CURSOR_POS: i32 = 0x44c;
/// Older display list: 10-byte header (count at bytes 8..10), then 0x1c bytes per screen.
pub(crate) const ENC_DISPLAY_INFO: i32 = 0x44d;
/// Cursor cache: `u32 id, u32 compressed_len, zlib(w*h*4 BGRX + w*h alpha)`; length 0 selects.
pub(crate) const ENC_CURSOR_IMAGE: i32 = 0x450;
/// Display layout: `u16` length of what follows, then the layout.
pub(crate) const ENC_DISPLAY_LAYOUT: i32 = 0x451;
/// Vendor keysyms, keyboard input source, device info: each a `u16` length then the payload.
pub(crate) const ENC_VENDOR_KEYSYMS: i32 = 0x453;
pub(crate) const ENC_KEYBOARD_SOURCE: i32 = 0x455;
pub(crate) const ENC_DEVICE_INFO: i32 = 0x456;
/// Media-stream messages (High Performance mode): `u16` length then the payload.
pub(crate) const ENC_MEDIA_STREAM: i32 = 0x3f2;

/// Server message: MiscStatus, `14 00 <u16 len = 4> 00 01 <u16 command>`.
pub(crate) const MSG_MISC_STATUS: u8 = 0x14;
/// Client messages that matter here.
const MSG_SET_ENCRYPTION: u8 = 0x12;
const MSG_VIEWER_INFO: u8 = 0x21;

/// ClientInit flag asking for the extended ServerInit.
pub(crate) const CLIENT_INIT_EXTENDED: u8 = 0x80;
/// Bytes of structure at the start of the extended ServerInit's name field.
const EXTENDED_NAME_PREFIX: usize = 22;

/// What the extended ServerInit says before the desktop name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtendedInit {
    pub flags: u32,
    /// Client message types the Mac accepts, one bit each, most significant bit first.
    pub commands: [u8; 16],
}

impl ExtendedInit {
    pub fn accepts(&self, msg: u8) -> bool {
        self.commands.get(usize::from(msg >> 3)).is_some_and(|b| (b >> (7 - (msg & 7))) & 1 == 1)
    }
    pub fn accepts_set_encryption(&self) -> bool {
        self.accepts(MSG_SET_ENCRYPTION)
    }
    pub fn observe_only(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

/// Split the extended ServerInit's name field into its structure and the UTF-8 name. `None` if
/// the field is too short to hold the structure (then it is treated as a plain name).
pub(crate) fn split_extended_name(raw: &[u8]) -> Option<(ExtendedInit, &[u8])> {
    if raw.len() < EXTENDED_NAME_PREFIX {
        return None;
    }
    // u16 (zero), u32 flags, 16-byte command bitmap.
    let flags = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]);
    let commands: [u8; 16] = raw[6..22].try_into().expect("16 bytes");
    Some((ExtendedInit { flags, commands }, &raw[EXTENDED_NAME_PREFIX..]))
}

/// ViewerInfo (0x21): 4-byte header and a 62-byte body of numbers. A mis-sized body makes the
/// Mac swallow the next message, so the size is fixed.
///
/// Body: u16 application class 1, u32 application id 2 (Screen Sharing), u32 x3 application
/// version 6.1.0, u32 x3 OS version 26.6.2, then 32 bytes: the server message types this viewer
/// handles, most significant bit first. Apple's viewer sets bits 0, 2, 3, 20, 21, 30, 31, 32,
/// 35, 81. We clear bit 21 (accessibility messages, which we could not parse). Bit 20 lets the
/// Mac send MiscStatus, which the session skips.
pub(crate) fn viewer_info() -> [u8; 66] {
    let mut m = [0u8; 66];
    m[0] = MSG_VIEWER_INFO;
    m[2..4].copy_from_slice(&62u16.to_be_bytes());
    m[4..6].copy_from_slice(&1u16.to_be_bytes());
    m[6..10].copy_from_slice(&2u32.to_be_bytes());
    for (at, v) in [(10, 6u32), (14, 1), (18, 0), (22, 26), (26, 6), (30, 2)] {
        m[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }
    m[34] = 0xb0; // types 0, 2, 3
    m[36] = 0x08; // type 20 (MiscStatus); Apple's viewer also sets 21 (0x04)
    m[37] = 0x03; // types 30, 31
    m[38] = 0x90; // types 32, 35
    m[44] = 0x40; // type 81
    m
}

/// SetEncryption command 1: start, method list [1] (AES-128). Sent verbatim as measured.
pub(crate) const SET_ENCRYPTION_START: [u8; 12] = [0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1];
/// SetEncryption command 2, value 1: decrypt everything the client sends from now on.
pub(crate) const SET_ENCRYPTION_DECRYPT_INBOUND: [u8; 8] = [0x12, 0, 0, 2, 0, 1, 0, 0];

/// The whole cleartext prelude, in the order Apple's viewer sends it.
pub(crate) fn prelude() -> Vec<u8> {
    let mut m = viewer_info().to_vec();
    m.extend_from_slice(&SET_ENCRYPTION_START);
    m.extend_from_slice(&SET_ENCRYPTION_DECRYPT_INBOUND);
    m
}

async fn discard<R: AsyncRead + Unpin>(r: &mut R, n: u64) -> Result<()> {
    let got = tokio::io::copy(&mut r.take(n), &mut tokio::io::sink()).await?;
    if got != n {
        return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(())
}

/// Read and log a MiscStatus after its type byte.
pub(crate) async fn skip_misc_status<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let _pad = r.read_u8().await?;
    let len = r.read_u16().await?;
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    let command = (len == 4).then(|| u16::from_be_bytes([body[2], body[3]]));
    match command {
        Some(1) => info!("Mac: the user at the Mac is ending the screen sharing session"),
        Some(cmd) => debug!(command = cmd, "Mac: MiscStatus (skipped)"),
        None => debug!(len, "Mac: MiscStatus with an unexpected length (skipped)"),
    }
    Ok(())
}

/// Read cleartext server messages until the rekey arrives; return the record-layer keys.
///
/// Nothing we asked for can come first (no pixel format, encodings or update request have been
/// sent). What a Mac may send unbidden here is Bell, MiscStatus and, conceivably, clipboard
/// text; those are stepped over by their own framing. Anything else means the stream is not
/// what we expect, and is named in the error.
pub(crate) async fn await_rekey<R: AsyncRead + Unpin>(r: &mut R, wrap_key: &[u8; 16]) -> Result<Keys> {
    let mut skipped = 0u32;
    loop {
        let msg = r.read_u8().await?;
        match msg {
            0 => {
                let _pad = r.read_u8().await?;
                let rects = r.read_u16().await?;
                if rects == 0 {
                    debug!("encryption setup: empty FramebufferUpdate before the rekey (skipped)");
                    continue;
                }
                let x = r.read_u16().await?;
                let y = r.read_u16().await?;
                let w = r.read_u16().await?;
                let h = r.read_u16().await?;
                let enc = r.read_i32().await?;
                if enc != ENC_REKEY {
                    warn!(encoding = enc, x, y, w, h, rects, "encryption setup: expected the rekey rectangle");
                    return Err(VncError::Security(format!(
                        "the Mac sent a rectangle of encoding {enc} ({enc:#x}) instead of the encryption key \
                         (encoding 0x44f)"
                    )));
                }
                let mut body = [0u8; REKEY_LEN];
                r.read_exact(&mut body).await?;
                if rects != 1 {
                    // Everything after the rekey rectangle is already encrypted; we cannot parse it
                    // as part of this update.
                    return Err(VncError::Security(format!(
                        "the Mac put {} more rectangle(s) after the encryption key in the same update",
                        rects - 1
                    )));
                }
                let (generation, keys) = record::unwrap_rekey(wrap_key, &body);
                debug!(generation, x, y, w, h, skipped_messages = skipped, "encryption setup: rekey received");
                return Ok(keys);
            }
            2 => {
                debug!("encryption setup: Bell before the rekey (skipped)");
            }
            3 => {
                let mut pad = [0u8; 3];
                r.read_exact(&mut pad).await?;
                let len = r.read_u32().await?;
                if len > 64 * 1024 * 1024 {
                    return Err(VncError::Protocol(format!("implausible clipboard length {len}")));
                }
                discard(r, u64::from(len)).await?;
                debug!(bytes = len, "encryption setup: clipboard text before the rekey (skipped)");
            }
            MSG_MISC_STATUS => skip_misc_status(r).await?,
            other => {
                warn!(message_type = other, "encryption setup: unexpected server message before the rekey");
                return Err(VncError::Security(format!(
                    "the Mac sent message type {other} ({other:#04x}) instead of the encryption key"
                )));
            }
        }
        skipped += 1;
    }
}

/// Skip the payload of an Apple metadata rectangle (after its 12-byte header). Returns false
/// for an encoding that is not one of these.
pub(crate) async fn skip_metadata<R: AsyncRead + Unpin>(r: &mut R, enc: i32) -> Result<bool> {
    match enc {
        ENC_CURSOR_POS => {}
        ENC_DISPLAY_INFO => {
            let mut head = [0u8; 10];
            r.read_exact(&mut head).await?;
            let count = u64::from(u16::from_be_bytes([head[8], head[9]]));
            discard(r, count * 0x1c).await?;
        }
        ENC_DISPLAY_LAYOUT | ENC_VENDOR_KEYSYMS | ENC_KEYBOARD_SOURCE | ENC_DEVICE_INFO | ENC_MEDIA_STREAM => {
            // The u16 counts the bytes after itself.
            let len = r.read_u16().await?;
            discard(r, u64::from(len)).await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_info_is_66_bytes_with_a_62_byte_body() {
        let v = viewer_info();
        assert_eq!(v.len(), 66);
        assert_eq!(&v[..4], &[0x21, 0, 0, 62]);
        // Capability bits, most significant first: MiscStatus (20) on, accessibility (21) off.
        let bit = |t: usize| (v[34 + t / 8] >> (7 - t % 8)) & 1;
        for t in [0, 2, 3, 20, 30, 31, 32, 35, 81] {
            assert_eq!(bit(t), 1, "type {t}");
        }
        assert_eq!(bit(21), 0);
        assert_eq!(bit(1), 0);
    }

    #[test]
    fn prelude_bytes() {
        let p = prelude();
        assert_eq!(p.len(), 66 + 12 + 8);
        assert_eq!(&p[66..], &[0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0x12, 0, 0, 2, 0, 1, 0, 0]);
    }

    #[test]
    fn extended_server_init_name() {
        // The bitmap a measured Mac sends: bf f6 e7 2f ec, then zeros.
        let mut raw = vec![0, 0, 0, 0, 0, 0x12];
        raw.extend_from_slice(&[0xbf, 0xf6, 0xe7, 0x2f, 0xec]);
        raw.extend_from_slice(&[0; 11]);
        raw.extend_from_slice("Zoë’s Mac".as_bytes());
        let (ext, name) = split_extended_name(&raw).unwrap();
        assert_eq!(ext.flags, 0x12);
        assert!(!ext.observe_only());
        assert!(ext.accepts_set_encryption());
        assert!(ext.accepts(0x21));
        assert!(ext.accepts(0x1d));
        assert!(!ext.accepts(0x13));
        assert_eq!(name, "Zoë’s Mac".as_bytes());
        assert!(split_extended_name(b"short").is_none());
    }

    #[tokio::test]
    async fn rekey_after_misc_status_and_bell() {
        let wrap = [7u8; 16];
        let keys = Keys { key: [1; 16], iv: [2; 16] };
        let cipher = <aes::Aes128 as aes::cipher::KeyInit>::new(&wrap.into());
        let wrapped = |mut b: [u8; 16]| {
            aes::cipher::BlockCipherEncrypt::encrypt_block(&cipher, (&mut b).into());
            b
        };
        let mut wire = vec![0x14, 0, 0, 4, 0, 1, 0, 2, 2, 0, 0, 0, 0];
        wire.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x4f, 0, 0, 0, 1]);
        wire.extend_from_slice(&wrapped(keys.key));
        wire.extend_from_slice(&wrapped(keys.iv));
        wire.push(0xAA); // first byte of the record layer: must stay unread
        let mut r: &[u8] = &wire;
        assert_eq!(await_rekey(&mut r, &wrap).await.unwrap(), keys);
        assert_eq!(r, &[0xAA]);
    }

    #[tokio::test]
    async fn anything_else_before_the_rekey_is_refused() {
        let mut r: &[u8] = &[0, 0, 0, 1, 0, 0, 0, 0, 0, 4, 0, 4, 0, 0, 0, 0];
        assert!(matches!(await_rekey(&mut r, &[0; 16]).await, Err(VncError::Security(_))));
        let mut r: &[u8] = &[0x99];
        assert!(matches!(await_rekey(&mut r, &[0; 16]).await, Err(VncError::Security(_))));
    }
}
