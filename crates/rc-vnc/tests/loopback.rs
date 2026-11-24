//! Public-API tests against an in-process mock RFB server on a loopback socket (ephemeral port).
//! The server half (auth crypto and every encoder) is written here independently of the client
//! code, serves a synthetic framebuffer, and the test compares what the client reconstructs.

#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use flate2::{Compress, Compression, FlushCompress};
use md5::{Digest, Md5};
use num_bigint::BigUint;
use rc_types::{session_channels, ErrorKind, SessionEvent, SessionInput};
use rc_vnc::VncConfig;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const W: usize = 150;
const H: usize = 100;
const T: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Sec {
    None,
    Vnc,
    Ard,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Enc {
    Raw,
    Rre,
    Hextile,
    Zlib,
    Zrle,
    Tight,
}

/// Synthetic picture as RGB triples: a gradient with solid blocks whose red and blue differ
/// strongly (so a channel swap cannot pass), plus a flat region.
fn picture() -> Vec<[u8; 3]> {
    let mut img = Vec::with_capacity(W * H);
    for y in 0..H {
        for x in 0..W {
            let p = if y < 20 {
                [200, 40, 10] // flat orange-red band
            } else if (30..60).contains(&y) && (10..50).contains(&x) {
                [255, 0, 0]
            } else if (30..60).contains(&y) && (60..100).contains(&x) {
                [0, 0, 255]
            } else if (30..60).contains(&y) && (110..140).contains(&x) {
                [0, 255, 0]
            } else if y >= 80 {
                [if (x / 3) % 2 == 0 { 255 } else { 0 }, 255, 255] // stripes: 2 colours
            } else {
                [(x * 255 / W) as u8, (y * 255 / H) as u8, 128]
            };
            img.push(p);
        }
    }
    img
}

/// Wire PIXEL for the client's requested format: B, G, R, pad.
fn px(p: [u8; 3]) -> [u8; 4] {
    [p[2], p[1], p[0], 0]
}

struct Deflater(Compress);
impl Deflater {
    fn new() -> Self {
        Deflater(Compress::new(Compression::default(), true))
    }
    fn block(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() * 2 + 1024);
        self.0.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
        out
    }
}

fn rect_header(x: usize, y: usize, w: usize, h: usize, enc: i32) -> Vec<u8> {
    let mut m = Vec::new();
    for v in [x, y, w, h] {
        m.extend_from_slice(&(v as u16).to_be_bytes());
    }
    m.extend_from_slice(&enc.to_be_bytes());
    m
}

struct Encoder {
    img: Vec<[u8; 3]>,
    zlib: Deflater,
    zrle: Deflater,
    tight: [Deflater; 4],
}

impl Encoder {
    fn at(&self, x: usize, y: usize) -> [u8; 3] {
        self.img[y * W + x]
    }

    /// Horizontal runs inside a tile/rect as (x, y, len, colour), relative to (x0, y0).
    fn runs(&self, x0: usize, y0: usize, w: usize, h: usize) -> Vec<(usize, usize, usize, [u8; 3])> {
        let mut out = Vec::new();
        for y in 0..h {
            let mut x = 0;
            while x < w {
                let c = self.at(x0 + x, y0 + y);
                let mut n = 1;
                while x + n < w && self.at(x0 + x + n, y0 + y) == c {
                    n += 1;
                }
                out.push((x, y, n, c));
                x += n;
            }
        }
        out
    }

    /// Encode rows y0..y0+h of the full width as one or more rectangles; returns (count, bytes).
    fn encode(&mut self, enc: Enc, y0: usize, h: usize) -> (u16, Vec<u8>) {
        let mut m = Vec::new();
        match enc {
            Enc::Raw => {
                m.extend(rect_header(0, y0, W, h, 0));
                for y in y0..y0 + h {
                    for x in 0..W {
                        m.extend_from_slice(&px(self.at(x, y)));
                    }
                }
                (1, m)
            }
            Enc::Rre => {
                let bg = self.at(0, y0);
                let runs: Vec<_> = self.runs(0, y0, W, h).into_iter().filter(|r| r.3 != bg).collect();
                m.extend(rect_header(0, y0, W, h, 2));
                m.extend_from_slice(&(runs.len() as u32).to_be_bytes());
                m.extend_from_slice(&px(bg));
                for (x, y, n, c) in runs {
                    m.extend_from_slice(&px(c));
                    for v in [x, y, n, 1] {
                        m.extend_from_slice(&(v as u16).to_be_bytes());
                    }
                }
                (1, m)
            }
            Enc::Hextile => {
                m.extend(rect_header(0, y0, W, h, 5));
                let mut tile_no = 0;
                let mut last_bg = None;
                for ty in (0..h).step_by(16) {
                    let th = 16.min(h - ty);
                    for tx in (0..W).step_by(16) {
                        let tw = 16.min(W - tx);
                        tile_no += 1;
                        let runs = self.runs(tx, y0 + ty, tw, th);
                        let bg = runs[0].3;
                        let fg_runs: Vec<_> = runs.iter().filter(|r| r.3 != bg).collect();
                        let colours: std::collections::HashSet<_> = fg_runs.iter().map(|r| r.3).collect();
                        if tile_no % 5 == 0 || fg_runs.len() > 255 {
                            m.push(1); // raw
                            for y in 0..th {
                                for x in 0..tw {
                                    m.extend_from_slice(&px(self.at(tx + x, y0 + ty + y)));
                                }
                            }
                            last_bg = None; // be conservative after a raw tile
                            continue;
                        }
                        let mut flags = 0u8;
                        let mut body = Vec::new();
                        if last_bg != Some(bg) {
                            flags |= 2;
                            body.extend_from_slice(&px(bg));
                            last_bg = Some(bg);
                        }
                        if colours.len() == 1 {
                            // one foreground colour: monochrome subrects
                            flags |= 4 | 8;
                            body.extend_from_slice(&px(fg_runs[0].3));
                            body.push(fg_runs.len() as u8);
                            for r in &fg_runs {
                                body.push(((r.0 as u8) << 4) | r.1 as u8);
                                body.push(((r.2 - 1) as u8) << 4);
                            }
                        } else if !fg_runs.is_empty() {
                            flags |= 8 | 16;
                            body.push(fg_runs.len() as u8);
                            for r in &fg_runs {
                                body.extend_from_slice(&px(r.3));
                                body.push(((r.0 as u8) << 4) | r.1 as u8);
                                body.push(((r.2 - 1) as u8) << 4);
                            }
                        }
                        m.push(flags);
                        m.extend(body);
                    }
                }
                (1, m)
            }
            Enc::Zlib => {
                let mut raw = Vec::new();
                for y in y0..y0 + h {
                    for x in 0..W {
                        raw.extend_from_slice(&px(self.at(x, y)));
                    }
                }
                let comp = self.zlib.block(&raw);
                m.extend(rect_header(0, y0, W, h, 6));
                m.extend_from_slice(&(comp.len() as u32).to_be_bytes());
                m.extend(comp);
                (1, m)
            }
            Enc::Zrle => {
                let cpx = |p: [u8; 3]| [p[2], p[1], p[0]];
                let mut tiles = Vec::new();
                let mut tile_no = 0;
                for ty in (0..h).step_by(64) {
                    let th = 64.min(h - ty);
                    for tx in (0..W).step_by(64) {
                        let tw = 64.min(W - tx);
                        tile_no += 1;
                        let runs = self.runs(tx, y0 + ty, tw, th);
                        let mut palette: Vec<[u8; 3]> = Vec::new();
                        for r in &runs {
                            if !palette.contains(&r.3) {
                                palette.push(r.3);
                            }
                        }
                        if palette.len() == 1 {
                            tiles.push(1);
                            tiles.extend_from_slice(&cpx(palette[0]));
                        } else if palette.len() <= 16 && tile_no % 2 == 0 {
                            // packed palette
                            tiles.push(palette.len() as u8);
                            for p in &palette {
                                tiles.extend_from_slice(&cpx(*p));
                            }
                            let bits = match palette.len() {
                                2 => 1,
                                3..=4 => 2,
                                _ => 4,
                            };
                            for y in 0..th {
                                let mut acc = 0u32;
                                let mut nbits = 0;
                                for x in 0..tw {
                                    let idx =
                                        palette.iter().position(|p| *p == self.at(tx + x, y0 + ty + y)).unwrap() as u32;
                                    acc = (acc << bits) | idx;
                                    nbits += bits;
                                    if nbits == 8 {
                                        tiles.push(acc as u8);
                                        acc = 0;
                                        nbits = 0;
                                    }
                                }
                                if nbits > 0 {
                                    tiles.push((acc << (8 - nbits)) as u8);
                                }
                            }
                        } else if palette.len() <= 127 {
                            // palette RLE (runs do not wrap across rows here, which is allowed)
                            tiles.push(128 + palette.len() as u8);
                            for p in &palette {
                                tiles.extend_from_slice(&cpx(*p));
                            }
                            for r in &runs {
                                let idx = palette.iter().position(|p| *p == r.3).unwrap() as u8;
                                if r.2 == 1 {
                                    tiles.push(idx);
                                } else {
                                    tiles.push(idx | 0x80);
                                    let mut left = r.2 - 1;
                                    while left >= 255 {
                                        tiles.push(255);
                                        left -= 255;
                                    }
                                    tiles.push(left as u8);
                                }
                            }
                        } else if tile_no % 3 == 0 {
                            // plain RLE
                            tiles.push(128);
                            for r in &runs {
                                tiles.extend_from_slice(&cpx(r.3));
                                let mut left = r.2 - 1;
                                while left >= 255 {
                                    tiles.push(255);
                                    left -= 255;
                                }
                                tiles.push(left as u8);
                            }
                        } else {
                            tiles.push(0);
                            for y in 0..th {
                                for x in 0..tw {
                                    tiles.extend_from_slice(&cpx(self.at(tx + x, y0 + ty + y)));
                                }
                            }
                        }
                    }
                }
                let comp = self.zrle.block(&tiles);
                m.extend(rect_header(0, y0, W, h, 16));
                m.extend_from_slice(&(comp.len() as u32).to_be_bytes());
                m.extend(comp);
                (1, m)
            }
            Enc::Tight => {
                // Strips of 10 rows, cycling through every Tight method.
                let mut count = 0;
                for (i, sy) in (y0..y0 + h).step_by(10).enumerate() {
                    let sh = 10.min(y0 + h - sy);
                    count += 1;
                    m.extend(rect_header(0, sy, W, sh, 7));
                    let mut rgb: Vec<u8> = Vec::with_capacity(W * sh * 3);
                    for y in sy..sy + sh {
                        for x in 0..W {
                            rgb.extend_from_slice(&self.at(x, y));
                        }
                    }
                    let mut colours: Vec<[u8; 3]> = Vec::new();
                    for c in rgb.chunks(3) {
                        let c = [c[0], c[1], c[2]];
                        if !colours.contains(&c) {
                            colours.push(c);
                        }
                    }
                    let compact = |len: usize| {
                        let mut v = vec![(len & 0x7f) as u8];
                        if len > 0x7f {
                            v[0] |= 0x80;
                            v.push(((len >> 7) & 0x7f) as u8);
                            if len > 0x3fff {
                                v[1] |= 0x80;
                                v.push((len >> 14) as u8);
                            }
                        }
                        v
                    };
                    if colours.len() == 1 {
                        m.push(0x80); // fill
                        m.extend_from_slice(&colours[0]);
                    } else if colours.len() == 2 {
                        // mono palette on stream 1
                        m.extend_from_slice(&[0x50, 1, 1]);
                        m.extend_from_slice(&colours[0]);
                        m.extend_from_slice(&colours[1]);
                        let mut bits = Vec::new();
                        for row in rgb.chunks(W * 3) {
                            let mut line = vec![0u8; W.div_ceil(8)];
                            for (x, c) in row.chunks(3).enumerate() {
                                if c == colours[1] {
                                    line[x / 8] |= 0x80 >> (x % 8);
                                }
                            }
                            bits.extend(line);
                        }
                        let comp = self.tight[1].block(&bits);
                        m.extend(compact(comp.len()));
                        m.extend(comp);
                    } else if colours.len() <= 256 && i % 2 == 0 {
                        // indexed palette on stream 2
                        m.extend_from_slice(&[0x60, 1, (colours.len() - 1) as u8]);
                        for c in &colours {
                            m.extend_from_slice(c);
                        }
                        let idx: Vec<u8> = rgb
                            .chunks(3)
                            .map(|c| colours.iter().position(|p| p[..] == *c).unwrap() as u8)
                            .collect();
                        let comp = self.tight[2].block(&idx);
                        m.extend(compact(comp.len()));
                        m.extend(comp);
                    } else if i % 3 == 0 {
                        // gradient filter on stream 3
                        let get = |x: isize, y: isize, c: usize| -> i32 {
                            if x < 0 || y < 0 {
                                0
                            } else {
                                rgb[(y as usize * W + x as usize) * 3 + c] as i32
                            }
                        };
                        let mut res = Vec::with_capacity(rgb.len());
                        for y in 0..sh as isize {
                            for x in 0..W as isize {
                                for c in 0..3 {
                                    let pred = (get(x - 1, y, c) + get(x, y - 1, c) - get(x - 1, y - 1, c)).clamp(0, 255);
                                    res.push((get(x, y, c) - pred) as u8);
                                }
                            }
                        }
                        m.extend_from_slice(&[0x70, 2]);
                        let comp = self.tight[3].block(&res);
                        m.extend(compact(comp.len()));
                        m.extend(comp);
                    } else {
                        // copy filter on stream 0
                        m.push(0x00);
                        let comp = self.tight[0].block(&rgb);
                        m.extend(compact(comp.len()));
                        m.extend(comp);
                    }
                }
                (count, m)
            }
        }
    }
}

/// 1024-bit MODP prime (RFC 2409 group 2); macOS uses a 128-byte key.
const PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

fn pad_left(b: Vec<u8>, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len - b.len()];
    out.extend(b);
    out
}

/// Server side of security negotiation. Returns whether the credentials were right.
async fn authenticate(s: &mut TcpStream, sec: Sec, user: &str, pass: &str) -> bool {
    match sec {
        Sec::None => {
            s.write_all(&[1, 1]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 1);
            true
        }
        Sec::Vnc => {
            s.write_all(&[2, 2, 1]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 2);
            let challenge: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5c);
            s.write_all(&challenge).await.unwrap();
            let mut resp = [0u8; 16];
            s.read_exact(&mut resp).await.unwrap();
            // Decrypt with DES under the bit-reversed, NUL-padded, 8-byte password.
            let mut key = [0u8; 8];
            for (k, b) in key.iter_mut().zip(pass.bytes()) {
                *k = b.reverse_bits();
            }
            let des = des::Des::new(&key.into());
            for block in resp.chunks_exact_mut(8) {
                let block: &mut [u8; 8] = block.try_into().unwrap();
                des.decrypt_block(block.into());
            }
            resp == challenge
        }
        Sec::Ard => {
            // What a Mac offers: 30 plus Apple's newer types.
            s.write_all(&[4, 30, 33, 36, 35]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 30);
            let prime_bytes: Vec<u8> =
                (0..PRIME.len() / 2).map(|i| u8::from_str_radix(&PRIME[i * 2..i * 2 + 2], 16).unwrap()).collect();
            let p = BigUint::from_bytes_be(&prime_bytes);
            let private = BigUint::from_bytes_be(&[0x3c; 96]);
            let public = BigUint::from(2u8).modpow(&private, &p);
            let mut m = vec![0, 2, 0, 128];
            m.extend_from_slice(&prime_bytes);
            m.extend(pad_left(public.to_bytes_be(), 128));
            s.write_all(&m).await.unwrap();
            let mut resp = [0u8; 256];
            s.read_exact(&mut resp).await.unwrap();
            let client_pub = BigUint::from_bytes_be(&resp[128..]);
            let shared = pad_left(client_pub.modpow(&private, &p).to_bytes_be(), 128);
            let key: [u8; 16] = Md5::digest(&shared).into();
            let aes = aes::Aes128::new(&key.into());
            let mut plain = resp[..128].to_vec();
            for block in plain.chunks_exact_mut(16) {
                let block: &mut [u8; 16] = block.try_into().unwrap();
                aes.decrypt_block(block.into());
            }
            let cstr = |b: &[u8]| b.iter().position(|&c| c == 0).map(|n| b[..n].to_vec());
            cstr(&plain[..64]).as_deref() == Some(user.as_bytes())
                && cstr(&plain[64..]).as_deref() == Some(pass.as_bytes())
        }
    }
}

async fn skip(s: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

/// Read one client message; returns Some(incremental) for an update request, None otherwise.
async fn read_client_msg(s: &mut TcpStream) -> std::io::Result<Option<bool>> {
    let t = s.read_u8().await?;
    match t {
        0 => {
            let pf = skip(s, 19).await?;
            assert_eq!(pf[3..], [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
            Ok(None)
        }
        2 => {
            let h = skip(s, 3).await?;
            let n = u16::from_be_bytes([h[1], h[2]]) as usize;
            skip(s, n * 4).await?;
            Ok(None)
        }
        3 => Ok(Some(skip(s, 9).await?[0] != 0)),
        4 => skip(s, 7).await.map(|_| None),
        5 => skip(s, 5).await.map(|_| None),
        6 => {
            let h = skip(s, 7).await?;
            let n = u32::from_be_bytes([h[3], h[4], h[5], h[6]]) as usize;
            skip(s, n).await.map(|_| None)
        }
        other => panic!("mock server: unexpected client message {other}"),
    }
}

/// The mock server: handshake, then the picture in two updates (top 55 rows after the first
/// request, the rest after the next request) so persistent zlib streams are exercised.
async fn serve(mut s: TcpStream, sec: Sec, enc: Enc, user: &str, pass: &str) {
    s.write_all(if sec == Sec::Ard { b"RFB 003.889\n" } else { b"RFB 003.008\n" }).await.unwrap();
    let mut v = [0u8; 12];
    s.read_exact(&mut v).await.unwrap();
    assert_eq!(&v, b"RFB 003.008\n");
    if !authenticate(&mut s, sec, user, pass).await {
        let reason = b"Authentication failed (mock)";
        let mut m = vec![0, 0, 0, 1];
        m.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        m.extend_from_slice(reason);
        s.write_all(&m).await.unwrap();
        return;
    }
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    assert_eq!(s.read_u8().await.unwrap(), 1, "shared flag");
    let name = b"Mock Mac";
    let mut m = Vec::new();
    m.extend_from_slice(&(W as u16).to_be_bytes());
    m.extend_from_slice(&(H as u16).to_be_bytes());
    m.extend_from_slice(&[32, 32, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    m.extend_from_slice(&(name.len() as u32).to_be_bytes());
    m.extend_from_slice(name);
    s.write_all(&m).await.unwrap();

    let mut encoder = Encoder {
        img: picture(),
        zlib: Deflater::new(),
        zrle: Deflater::new(),
        tight: [Deflater::new(), Deflater::new(), Deflater::new(), Deflater::new()],
    };
    let mut parts = vec![(55, H - 55), (0, 55)]; // popped from the back
    loop {
        match read_client_msg(&mut s).await {
            Err(_) => return, // client went away
            Ok(Some(_)) => {
                if let Some((y0, h)) = parts.pop() {
                    let (count, body) = encoder.encode(enc, y0, h);
                    let mut m = vec![0, 0];
                    m.extend_from_slice(&count.to_be_bytes());
                    m.extend(body);
                    s.write_all(&m).await.unwrap();
                }
            }
            Ok(None) => {}
        }
    }
}

/// Run a client against the mock server and return the framebuffer it reconstructed.
async fn run_case(sec: Sec, enc: Enc) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        serve(s, sec, enc, "mockuser", "p@ss wörd").await;
    });
    let config = VncConfig {
        username: (sec == Sec::Ard).then(|| "mockuser".to_string()),
        password: (sec != Sec::None).then(|| "p@ss wörd".to_string().into()),
        ..Default::default()
    };
    let (io, mut handle) = session_channels();
    let client = tokio::spawn(async move { rc_vnc::connect_and_run("127.0.0.1", port, config, io).await });

    let mut fb = vec![0u8; W * H * 4];
    let mut covered = vec![false; W * H];
    let mut connected = false;
    while covered.iter().any(|c| !c) {
        let ev = tokio::time::timeout(T, handle.events.recv()).await.expect("timed out").expect("channel closed");
        match ev {
            SessionEvent::Status(_) => {}
            SessionEvent::Security { encrypted, .. } => assert!(!encrypted, "policy Off never encrypts"),
            SessionEvent::Connected { width, height, name } => {
                assert_eq!((width as usize, height as usize), (W, H));
                assert_eq!(name, "Mock Mac");
                connected = true;
            }
            SessionEvent::Frame { x, y, w, h, rgba } => {
                assert!(connected);
                let (x, y, w, h) = (x as usize, y as usize, w as usize, h as usize);
                assert_eq!(rgba.len(), w * h * 4);
                for row in 0..h {
                    let d = ((y + row) * W + x) * 4;
                    fb[d..d + w * 4].copy_from_slice(&rgba[row * w * 4..(row + 1) * w * 4]);
                    covered[(y + row) * W + x..(y + row) * W + x + w].fill(true);
                }
            }
            other => panic!("unexpected event {other:?}"),
        }
    }
    handle.input.send(SessionInput::Close).unwrap();
    loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => {
                assert!(error.is_none(), "{error:?}");
                break;
            }
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    }
    client.await.unwrap();
    server.await.unwrap();
    fb
}

fn assert_picture(fb: &[u8]) {
    let img = picture();
    for (i, p) in img.iter().enumerate() {
        let got = &fb[i * 4..i * 4 + 4];
        assert_eq!(got, [p[0], p[1], p[2], 255], "pixel ({}, {})", i % W, i / W);
    }
}

macro_rules! case {
    ($name:ident, $sec:expr, $enc:expr) => {
        #[tokio::test]
        async fn $name() {
            assert_picture(&run_case($sec, $enc).await);
        }
    };
}

case!(none_raw, Sec::None, Enc::Raw);
case!(none_rre, Sec::None, Enc::Rre);
case!(vnc_auth_hextile, Sec::Vnc, Enc::Hextile);
case!(vnc_auth_zlib, Sec::Vnc, Enc::Zlib);
case!(apple_auth_zrle, Sec::Ard, Enc::Zrle);
case!(apple_auth_tight, Sec::Ard, Enc::Tight);
case!(apple_auth_raw, Sec::Ard, Enc::Raw);

async fn expect_failure(sec: Sec, config: VncConfig) -> rc_types::SessionError {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        serve(s, sec, Enc::Raw, "mockuser", "right").await;
    });
    let (io, mut handle) = session_channels();
    let client = tokio::spawn(async move { rc_vnc::connect_and_run("127.0.0.1", port, config, io).await });
    let err = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error.expect("expected an error"),
            Some(SessionEvent::Connected { .. }) => panic!("must not connect"),
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    };
    client.await.unwrap();
    server.await.unwrap();
    err
}

#[tokio::test]
async fn wrong_vnc_password() {
    let cfg = VncConfig { password: Some(String::from("wrong").into()), ..Default::default() };
    let err = expect_failure(Sec::Vnc, cfg).await;
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    assert!(err.detail.contains("Authentication failed (mock)"), "{}", err.detail);
}

#[tokio::test]
async fn wrong_apple_password() {
    let cfg = VncConfig { username: Some("mockuser".into()), password: Some(String::from("wrong").into()), ..Default::default() };
    let err = expect_failure(Sec::Ard, cfg).await;
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    assert!(err.detail.contains("Authentication failed (mock)"), "{}", err.detail);
}

#[tokio::test]
async fn unreachable_port() {
    // Bind then drop to get a port that is very likely closed.
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (io, mut handle) = session_channels();
    rc_vnc::connect_and_run("127.0.0.1", port, VncConfig::default(), io).await;
    let mut last = None;
    while let Ok(ev) = handle.events.try_recv() {
        last = Some(ev);
    }
    match last {
        Some(SessionEvent::Closed { error: Some(e) }) => assert_eq!(e.kind, ErrorKind::Unreachable),
        other => panic!("unexpected {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Apple Screen Sharing's encrypted session (RFB 003.889, type 30, prelude, rekey, record layer).
// The server side is written here independently of the client's record layer.
// ---------------------------------------------------------------------------------------------

use aes::cipher::BlockCipherEncrypt;
use rc_vnc::{EncryptionPolicy, VncOptions, VncSecurity};
use sha1::Sha1;

/// One direction of the record layer, as the Mac keeps it.
struct RecCbc {
    aes: aes::Aes128,
    chain: [u8; 16],
    seq: u32,
}

impl RecCbc {
    fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        RecCbc { aes: aes::Aes128::new(&key.into()), chain: iv, seq: 0 }
    }
    fn hash(&mut self, covered: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(self.seq.to_be_bytes());
        h.update(covered);
        self.seq += 1;
        h.finalize().into()
    }
    /// `u16 len || ciphertext` for one body (non-zero filler, as the Mac uses).
    fn seal(&mut self, body: &[u8]) -> Vec<u8> {
        let fill = (16 - (2 + body.len() + 20) % 16) % 16;
        let mut p = (body.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(body);
        p.extend((0..fill).map(|i| (i as u8).wrapping_mul(29) ^ 0xa5));
        let h = self.hash(&p);
        p.extend_from_slice(&h);
        for block in p.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = block.try_into().unwrap();
            for (b, c) in block.iter_mut().zip(self.chain) {
                *b ^= c;
            }
            self.aes.encrypt_block(block.into());
            self.chain = *block;
        }
        let mut out = (p.len() as u16).to_be_bytes().to_vec();
        out.extend(p);
        out
    }
    /// Decrypt and verify one record's ciphertext; returns the body.
    fn open(&mut self, mut ct: Vec<u8>) -> Vec<u8> {
        assert!(ct.len() >= 32 && ct.len().is_multiple_of(16), "bad record length {}", ct.len());
        for block in ct.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = block.try_into().unwrap();
            let c = *block;
            self.aes.decrypt_block(block.into());
            for (b, x) in block.iter_mut().zip(self.chain) {
                *b ^= x;
            }
            self.chain = c;
        }
        let n = ct.len();
        let h = self.hash(&ct[..n - 20]);
        assert_eq!(&ct[n - 20..], &h, "client record failed the integrity check");
        let len = u16::from_be_bytes([ct[0], ct[1]]) as usize;
        ct[2..2 + len].to_vec()
    }
}

/// Length of a client message from its first bytes.
fn client_msg_len(m: &[u8]) -> usize {
    match m[0] {
        0 => 20,
        2 => 4 + 4 * u16::from_be_bytes([m[2], m[3]]) as usize,
        3 => 10,
        4 => 8,
        5 => 6,
        6 => 8 + u32::from_be_bytes([m[4], m[5], m[6], m[7]]) as usize,
        other => panic!("mock Mac: unexpected client message {other}"),
    }
}

#[derive(Clone, Default)]
struct AppleOpts {
    /// Flip a ciphertext byte of the first record the server sends.
    tamper: bool,
    /// Put the whole picture three times into the first update (about 180 KB: several records,
    /// boundaries in the middle of rectangles).
    big_update: bool,
    /// Split every server message into records of at most this many body bytes.
    chunk: Option<usize>,
    /// Offer type 36 (SRP) besides 30.
    offer_srp: bool,
    /// The client is expected to pick 36 when offered (it does unless SRP is turned off).
    expect_srp: bool,
    /// Send a wrong SRP proof M2 (an impostor that got the password check past somehow).
    bad_m2: bool,
}

/// RFC 5054 Appendix A, 4096-bit group (generator 5).
const SRP_N_4096: &str = concat!(
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
}

/// A 4096-bit modulus (2^4096 - 1) with generator 5: the size macOS sends. Not a prime, which
/// does not matter for checking that both sides compute the same shared secret.
const APPLE_KEY_LEN: usize = 512;

/// Type 30 on the mock Mac; returns the wrap key, or None after refusing the credentials.
async fn ard_server(s: &mut TcpStream, user: &str, pass: &str) -> Option<[u8; 16]> {
    let n = BigUint::from_bytes_be(&[0xff; APPLE_KEY_LEN]);
    let private = BigUint::from_bytes_be(&[0x3c; 32]);
    let public = BigUint::from(5u8).modpow(&private, &n);
    let mut m = vec![0, 5];
    m.extend_from_slice(&(APPLE_KEY_LEN as u16).to_be_bytes());
    m.extend_from_slice(&[0xff; APPLE_KEY_LEN]);
    m.extend(pad_left(public.to_bytes_be(), APPLE_KEY_LEN));
    s.write_all(&m).await.unwrap();
    let mut resp = vec![0u8; 128 + APPLE_KEY_LEN];
    s.read_exact(&mut resp).await.unwrap();
    let client_pub = BigUint::from_bytes_be(&resp[128..]);
    let shared = pad_left(client_pub.modpow(&private, &n).to_bytes_be(), APPLE_KEY_LEN);
    let wrap: [u8; 16] = Md5::digest(&shared).into();
    let aes = aes::Aes128::new(&wrap.into());
    let mut plain = resp[..128].to_vec();
    for block in plain.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = block.try_into().unwrap();
        aes.decrypt_block(block.into());
    }
    let cstr = |b: &[u8]| b.iter().position(|&c| c == 0).map(|n| b[..n].to_vec());
    if cstr(&plain[..64]).as_deref() != Some(user.as_bytes()) || cstr(&plain[64..]).as_deref() != Some(pass.as_bytes())
    {
        s.write_all(&[0, 0, 0, 1]).await.unwrap(); // a Mac sends no reason to 003.889
        return None;
    }
    Some(wrap)
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = sha2::Sha512::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().to_vec()
}

/// Type 36 (SRP-6a, SHA-512, PBKDF2) on the mock Mac, the server's half written from the
/// formulas: v = g^x, B = k*v + g^b, S = (A * v^u)^b. Returns the wrap key SHA-256(K)[..16],
/// or None after refusing the proof.
async fn srp_server(s: &mut TcpStream, user: &str, pass: &str, bad_m2: bool) -> Option<[u8; 16]> {
    let len = APPLE_KEY_LEN;
    let n_bytes = unhex(SRP_N_4096);
    assert_eq!(n_bytes.len(), len);
    let n = BigUint::from_bytes_be(&n_bytes);
    let g = BigUint::from(5u8);
    let pad = |v: &BigUint| pad_left(v.to_bytes_be(), len);
    // Message 1: "", username, "", opaque "".
    let mlen = s.read_u32().await.unwrap() as usize;
    let id = skip(s, mlen).await.unwrap();
    let ulen = u16::from_be_bytes([id[2], id[3]]) as usize;
    assert_eq!(&id[..2], &[0, 0]);
    assert_eq!(&id[4..4 + ulen], user.as_bytes());
    assert_eq!(&id[4 + ulen..], &[0, 0, 0]);
    // Verifier for the right password (what the Mac stores).
    let salt: Vec<u8> = (100..132u8).collect();
    let iterations = 1000u64;
    let mut stretched = [0u8; 128];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass.as_bytes(), &salt, iterations as u32, &mut stretched);
    let x = BigUint::from_bytes_be(&sha512(&[&salt, &sha512(&[b":", &stretched])]));
    let v = g.modpow(&x, &n);
    let k = BigUint::from_bytes_be(&sha512(&[&n_bytes, &pad(&g)]));
    let b = BigUint::from_bytes_be(&[0x29; 48]);
    let big_b = (&k * &v + g.modpow(&b, &n)) % &n;
    let options = b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2";
    let mut m = vec![0u8];
    m.extend_from_slice(&(len as u16).to_be_bytes());
    m.extend_from_slice(&n_bytes);
    m.extend_from_slice(&[0, 1, 5]);
    m.push(salt.len() as u8);
    m.extend_from_slice(&salt);
    m.extend_from_slice(&(len as u16).to_be_bytes());
    m.extend(pad(&big_b));
    m.extend_from_slice(&iterations.to_be_bytes());
    m.extend_from_slice(&(options.len() as u16).to_be_bytes());
    m.extend_from_slice(options);
    let mut framed = (m.len() as u32).to_be_bytes().to_vec();
    framed.extend(m);
    s.write_all(&framed).await.unwrap();
    // Message 3: A, M1, options echo, 16 random bytes.
    let mlen = s.read_u32().await.unwrap() as usize;
    let p3 = skip(s, mlen).await.unwrap();
    let alen = u16::from_be_bytes([p3[0], p3[1]]) as usize;
    assert_eq!(alen, len, "A is padded to the length of N");
    let a_bytes = &p3[2..2 + alen];
    let mut at = 2 + alen;
    let m1_len = p3[at] as usize;
    let m1 = &p3[at + 1..at + 1 + m1_len];
    at += 1 + m1_len;
    let olen = u16::from_be_bytes([p3[at], p3[at + 1]]) as usize;
    assert_eq!(&p3[at + 2..at + 2 + olen], options, "options echoed");
    at += 2 + olen;
    assert_eq!((p3[at], p3.len() - at), (16, 17), "16-byte client random");
    let big_a = BigUint::from_bytes_be(a_bytes);
    let u = BigUint::from_bytes_be(&sha512(&[a_bytes, &pad(&big_b)]));
    let shared = (&big_a * v.modpow(&u, &n)).modpow(&b, &n);
    let key = sha512(&[&pad(&shared)]);
    let xor: Vec<u8> = sha512(&[&n_bytes]).iter().zip(sha512(&[&pad(&g)])).map(|(p, q)| p ^ q).collect();
    let expected_m1 = sha512(&[&xor, &sha512(&[b""]), &salt, a_bytes, &pad(&big_b), &key]);
    if m1 != expected_m1.as_slice() {
        s.write_all(&[0, 0, 0, 1]).await.unwrap(); // refused: the bare result word
        return None;
    }
    // Message 4: M2, server random, "", u32 0.
    let mut m2 = sha512(&[a_bytes, m1, &key]);
    if bad_m2 {
        m2[10] ^= 1;
    }
    let mut m = vec![64u8];
    m.extend(m2);
    m.push(16);
    m.extend_from_slice(&[0xab; 16]);
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let mut framed = (m.len() as u32).to_be_bytes().to_vec();
    framed.extend(m);
    s.write_all(&framed).await.unwrap();
    if bad_m2 {
        return None;
    }
    let digest: [u8; 32] = sha2::Sha256::digest(&key).into();
    Some(digest[..16].try_into().unwrap())
}

/// The mock Mac. Returns every client message it received inside the record layer.
async fn serve_apple(mut s: TcpStream, enc: Enc, user: &str, pass: &str, opts: AppleOpts) -> Vec<Vec<u8>> {
    s.write_all(b"RFB 003.889\n").await.unwrap();
    let mut v = [0u8; 12];
    s.read_exact(&mut v).await.unwrap();
    assert_eq!(&v, b"RFB 003.889\n", "client must answer Apple's revision to encrypt");
    let offer: &[u8] = if opts.offer_srp { &[30, 33, 36, 35] } else { &[30, 33, 35] };
    s.write_all(&[offer.len() as u8]).await.unwrap();
    s.write_all(offer).await.unwrap();
    let chosen = s.read_u8().await.unwrap();
    assert_eq!(chosen, if opts.offer_srp && opts.expect_srp { 36 } else { 30 });
    let wrap = if chosen == 36 {
        match srp_server(&mut s, user, pass, opts.bad_m2).await {
            Some(w) => w,
            None => return Vec::new(),
        }
    } else {
        match ard_server(&mut s, user, pass).await {
            Some(w) => w,
            None => return Vec::new(),
        }
    };
    let aes = aes::Aes128::new(&wrap.into());
    s.write_all(&[0, 0, 0, 0]).await.unwrap();
    assert_eq!(s.read_u8().await.unwrap(), 0x81, "ClientInit: shared + extended ServerInit");

    // Extended ServerInit: the name starts with u16 0, u32 flags, the 16-byte command bitmap.
    let mut name = vec![0, 0, 0, 0, 0, 0x12, 0xbf, 0xf6, 0xe7, 0x2f, 0xec];
    name.extend_from_slice(&[0; 11]);
    name.extend_from_slice(b"Mock Mac");
    let mut m = Vec::new();
    m.extend_from_slice(&(W as u16).to_be_bytes());
    m.extend_from_slice(&(H as u16).to_be_bytes());
    m.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
    m.extend_from_slice(&(name.len() as u32).to_be_bytes());
    m.extend(name);
    s.write_all(&m).await.unwrap();

    // Cleartext prelude.
    let viewer_info = skip(&mut s, 66).await.unwrap();
    assert_eq!(&viewer_info[..4], &[0x21, 0, 0, 62]);
    assert_eq!(skip(&mut s, 12).await.unwrap(), [0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1]);
    // The Mac answers command 1 at once; a MiscStatus first, as after a server restart.
    let key = [0x5au8; 16];
    let iv: [u8; 16] = core::array::from_fn(|i| i as u8 * 3);
    let mut m = vec![0x14, 0, 0, 4, 0, 1, 0, 2];
    m.extend_from_slice(&[0, 0, 0, 1]);
    m.extend(rect_header(0, 0, 0, 0, 0x44f));
    m.extend_from_slice(&1u32.to_be_bytes());
    for half in [key, iv] {
        let mut b = half;
        aes.encrypt_block((&mut b).into());
        m.extend_from_slice(&b);
    }
    s.write_all(&m).await.unwrap();
    assert_eq!(skip(&mut s, 8).await.unwrap(), [0x12, 0, 0, 2, 0, 1, 0, 0]);

    // Records from here on, both ways.
    let mut tx = RecCbc::new(key, iv);
    let mut rx = RecCbc::new(key, iv);
    let chunk = opts.chunk.unwrap_or(65_498);
    let mut tamper = opts.tamper;
    let mut received = Vec::new();
    let mut encoder = Encoder {
        img: picture(),
        zlib: Deflater::new(),
        zrle: Deflater::new(),
        tight: [Deflater::new(), Deflater::new(), Deflater::new(), Deflater::new()],
    };
    let mut parts = if opts.big_update { vec![(0, H)] } else { vec![(55, H - 55), (0, 55)] };
    loop {
        // One record = exactly one client message.
        let Ok(len) = s.read_u16().await else { return received };
        let Ok(ct) = skip(&mut s, len as usize).await else { return received };
        let msg = rx.open(ct);
        assert_eq!(msg.len(), client_msg_len(&msg), "a record must carry exactly one message: {msg:?}");
        if msg[0] == 0 {
            assert_eq!(msg[4..], [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        }
        let request = msg[0] == 3;
        received.push(msg);
        if !request {
            continue;
        }
        let Some((y0, h)) = parts.pop() else { continue };
        let mut m = Vec::new();
        if opts.big_update {
            let (_, body) = encoder.encode(Enc::Raw, y0, h);
            m.extend_from_slice(&[0, 0, 0, 3]);
            for _ in 0..3 {
                m.extend_from_slice(&body);
            }
        } else {
            let (count, body) = encoder.encode(enc, y0, h);
            m.extend_from_slice(&[0, 0]);
            m.extend_from_slice(&count.to_be_bytes());
            m.extend(body);
        }
        for piece in m.chunks(chunk) {
            let mut rec = tx.seal(piece);
            if tamper {
                let last = rec.len() - 1;
                rec[last] ^= 0x40;
                tamper = false;
            }
            if s.write_all(&rec).await.is_err() {
                return received;
            }
        }
    }
}

/// The client turns SRP off when the server offers it but the test expects type 30.
fn opts_srp_off(o: &AppleOpts) -> bool {
    o.offer_srp && !o.expect_srp
}

struct AppleRun {
    fb: Vec<u8>,
    statuses: Vec<String>,
    /// Every VNC security level reported, in order.
    security: Vec<VncSecurity>,
    received: Vec<Vec<u8>>,
}

/// Connect with `Required` to the mock Mac, collect the picture, optionally send some input,
/// then close.
async fn run_apple(enc: Enc, opts: AppleOpts, input: Vec<SessionInput>) -> AppleRun {
    let opts_copy = opts.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        serve_apple(s, enc, "mockuser", "p@ss wörd", opts).await
    });
    let config =
        VncConfig { username: Some("mockuser".into()), password: Some(String::from("p@ss wörd").into()), ..Default::default() };
    // Type 30 under Required needs the explicit opt-in; SRP must work without it.
    let options = VncOptions::default()
        .with_encryption(EncryptionPolicy::Required)
        .with_srp(!opts_srp_off(&opts_copy))
        .with_allow_unverified_sign_in(!(opts_copy.offer_srp && opts_copy.expect_srp));
    let (io, mut handle) = session_channels();
    let client =
        tokio::spawn(async move { rc_vnc::connect_and_run_with_options("127.0.0.1", port, config, options, io).await });
    let mut fb = vec![0u8; W * H * 4];
    let mut covered = vec![false; W * H];
    let mut statuses = Vec::new();
    let mut security = Vec::new();
    while covered.iter().any(|c| !c) {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out").expect("channel closed") {
            SessionEvent::Status(s) => statuses.push(s),
            ev @ SessionEvent::Security { .. } => {
                security.push(VncSecurity::from_event(&ev).unwrap_or_else(|| panic!("unknown security event {ev:?}")))
            }
            SessionEvent::Connected { name, .. } => assert_eq!(name, "Mock Mac"),
            SessionEvent::Frame { x, y, w, h, rgba } => {
                let (x, y, w, h) = (x as usize, y as usize, w as usize, h as usize);
                for row in 0..h {
                    let d = ((y + row) * W + x) * 4;
                    fb[d..d + w * 4].copy_from_slice(&rgba[row * w * 4..(row + 1) * w * 4]);
                    covered[(y + row) * W + x..(y + row) * W + x + w].fill(true);
                }
            }
            other => panic!("unexpected event {other:?}"),
        }
    }
    for i in input {
        handle.input.send(i).unwrap();
    }
    handle.input.send(SessionInput::Close).unwrap();
    loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => {
                assert!(error.is_none(), "{error:?}");
                break;
            }
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    }
    client.await.unwrap();
    let received = server.await.unwrap();
    AppleRun { fb, statuses, security, received }
}

#[tokio::test]
async fn apple_encrypted_session_paints() {
    for enc in [Enc::Zrle, Enc::Raw] {
        let run = run_apple(enc, AppleOpts::default(), vec![]).await;
        assert_picture(&run.fb);
        assert_eq!(run.security, [VncSecurity::EncryptedUnverified], "{:?}", run.statuses);
        assert!(run.statuses.iter().any(|s| s == "Setting up encryption"));
    }
}

#[tokio::test]
async fn apple_encrypted_input_arrives_in_records() {
    let input = vec![
        SessionInput::PointerMove { x: 3, y: 1 },
        SessionInput::Key { code: "KeyA".into(), key: "a".into(), down: true },
        SessionInput::Clipboard { text: "secret clipboard".into() },
    ];
    let run = run_apple(Enc::Zrle, AppleOpts::default(), input).await;
    let r = &run.received;
    // SetPixelFormat, SetEncodings, update requests, the input, the key release on close.
    assert_eq!(r[0][0], 0);
    assert_eq!(r[1][0], 2);
    assert!(r.contains(&vec![5, 0, 0, 3, 0, 1]), "{r:?}");
    assert!(r.contains(&vec![4, 1, 0, 0, 0, 0, 0, 0x61]));
    let mut cut = vec![6, 0, 0, 0, 0, 0, 0, 16];
    cut.extend_from_slice(b"secret clipboard");
    assert!(r.contains(&cut));
    assert_eq!(r.last().unwrap(), &vec![4, 0, 0, 0, 0, 0, 0, 0x61], "key released on close");
}

#[tokio::test]
async fn apple_large_update_spans_records() {
    // Max-size records, rectangles crossing record boundaries.
    let run = run_apple(Enc::Raw, AppleOpts { big_update: true, ..Default::default() }, vec![]).await;
    assert_picture(&run.fb);
    // Small odd-sized records, splitting even the message headers.
    let run = run_apple(Enc::Zrle, AppleOpts { chunk: Some(37), ..Default::default() }, vec![]).await;
    assert_picture(&run.fb);
}

#[tokio::test]
async fn apple_tampered_record_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        serve_apple(s, Enc::Raw, "u", "p", AppleOpts { tamper: true, ..Default::default() }).await
    });
    let config = VncConfig { username: Some("u".into()), password: Some(String::from("p").into()), ..Default::default() };
    let options =
        VncOptions::default().with_encryption(EncryptionPolicy::Required).with_allow_unverified_sign_in(true);
    let (io, mut handle) = session_channels();
    let client =
        tokio::spawn(async move { rc_vnc::connect_and_run_with_options("127.0.0.1", port, config, options, io).await });
    let err = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error.expect("expected an error"),
            Some(SessionEvent::Frame { .. }) => panic!("no pixels from a tampered record"),
            // Connected and the security report wait for the first record's integrity check.
            Some(SessionEvent::Connected { .. }) => panic!("must not connect before a record verified"),
            Some(ev @ SessionEvent::Security { .. }) => panic!("must not report security yet: {ev:?}"),
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    };
    assert_eq!(err.kind, ErrorKind::Security, "{}", err.detail);
    assert!(err.detail.contains("integrity"), "{}", err.detail);
    client.await.unwrap();
    server.await.unwrap();
}

/// A server that announces `greeting`, offers `types` (for 3.3: picks `types[0]`), and returns
/// the client's error and whatever the client sent back.
async fn offer_only(
    greeting: &'static [u8; 12],
    types: &'static [u8],
    config: VncConfig,
    options: VncOptions,
) -> (rc_types::SessionError, Vec<u8>) {
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let (io, mut handle) = session_channels();
    let task = tokio::spawn(rc_vnc::run_with_options(client, config, options, io));
    // The client may hang up as soon as it has read the greeting; ignore write errors.
    let _ = server.write_all(greeting).await;
    if greeting == b"RFB 003.003\n" {
        let _ = server.write_all(&u32::from(types[0]).to_be_bytes()).await;
    } else {
        let _ = server.write_all(&[types.len() as u8]).await;
        let _ = server.write_all(types).await;
    }
    let err = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error.expect("expected an error"),
            Some(SessionEvent::Connected { .. }) => panic!("must not connect"),
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    };
    task.await.unwrap();
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    (err, sent)
}

#[tokio::test]
async fn required_refuses_none_and_vnc_password() {
    let required = || VncOptions::default().with_encryption(EncryptionPolicy::Required);
    let mac = || VncConfig { username: Some("u".into()), password: Some(String::from("p").into()), ..Default::default() };
    let pw_only = || VncConfig { password: Some(String::from("p").into()), ..Default::default() };
    for types in [&[1u8][..], &[2], &[2, 1]] {
        for config in [mac(), pw_only()] {
            let (err, sent) = offer_only(b"RFB 003.889\n", types, config, required()).await;
            assert_eq!(err.kind, ErrorKind::Security, "{types:?}: {}", err.detail);
            assert!(err.detail.contains("could not be encrypted"), "{}", err.detail);
            assert!(err.detail.contains("None (1) and VNC password (2) are refused"), "{}", err.detail);
            // The client answered the version and chose nothing.
            assert_eq!(sent, b"RFB 003.889\n");
        }
    }
    // A server that is not a Mac: refused before anything is sent.
    let (err, sent) = offer_only(b"RFB 003.008\n", &[1], pw_only(), required()).await;
    assert_eq!(err.kind, ErrorKind::Security);
    assert!(err.detail.contains("not Apple Screen Sharing"), "{}", err.detail);
    assert!(sent.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Hostile servers (regressions from the security audit).
// ---------------------------------------------------------------------------------------------

fn creds() -> VncConfig {
    VncConfig { username: Some("alice".into()), password: Some(String::from("MacPassw0rd!").into()), ..Default::default() }
}

#[tokio::test]
async fn username_set_refuses_vnc_password_and_none_downgrade() {
    let cases: [(&'static [u8; 12], &'static [u8]); 5] = [
        (b"RFB 003.008\n", &[2]),
        (b"RFB 003.008\n", &[1]),
        (b"RFB 003.889\n", &[2, 1]),
        (b"RFB 003.003\n", &[2]),
        (b"RFB 003.003\n", &[1]),
    ];
    for (greeting, types) in cases {
        let (err, sent) = offer_only(greeting, types, creds(), VncOptions::default()).await;
        assert_eq!(err.kind, ErrorKind::Security, "{types:?}: {}", err.detail);
        assert!(err.detail.contains("clear the username"), "{}", err.detail);
        // Only the version reply: no security type chosen, no DES response sent.
        assert_eq!(sent.len(), 12, "{types:?}: client sent {sent:?}");
    }
}

/// A 3.8 server with no authentication, then `after` right behind ServerInit. Closes the
/// session after the first Bell.
async fn hostile(width: u16, height: u16, after: Vec<u8>) -> (Vec<SessionEvent>, Option<rc_types::SessionError>) {
    let (client, mut server) = tokio::io::duplex(1 << 20);
    let (io, mut handle) = session_channels();
    let task = tokio::spawn(rc_vnc::run(client, VncConfig::default(), io));
    server.write_all(b"RFB 003.008\n").await.unwrap();
    skip_duplex(&mut server, 12).await;
    server.write_all(&[1, 1]).await.unwrap();
    skip_duplex(&mut server, 1).await;
    server.write_all(&[0, 0, 0, 0]).await.unwrap();
    skip_duplex(&mut server, 1).await;
    let mut m = Vec::new();
    m.extend_from_slice(&width.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    m.extend(after);
    // Keep draining what the client sends so it never blocks on a full pipe.
    let feeder = tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(server);
        let w = async move {
            let _ = wr.write_all(&m).await;
            wr
        };
        let r = async move {
            let mut sink = Vec::new();
            let _ = rd.read_to_end(&mut sink).await;
        };
        let (_wr, ()) = tokio::join!(w, r);
    });
    let mut events = Vec::new();
    let error = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error,
            Some(SessionEvent::Status(_)) => {}
            Some(ev) => {
                let bell = matches!(ev, SessionEvent::Bell);
                events.push(ev);
                if bell {
                    handle.input.send(SessionInput::Close).unwrap();
                }
            }
            None => panic!("no Closed event"),
        }
    };
    task.await.unwrap();
    feeder.abort();
    (events, error)
}

async fn skip_duplex(s: &mut tokio::io::DuplexStream, n: usize) {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await.unwrap();
}

#[tokio::test]
async fn huge_server_init_is_a_protocol_error() {
    let (events, err) = hostile(65535, 65535, vec![]).await;
    let err = err.expect("error");
    assert_eq!(err.kind, ErrorKind::Protocol, "{}", err.detail);
    assert!(err.detail.contains("65535x65535"), "{}", err.detail);
    assert!(!events.iter().any(|e| matches!(e, SessionEvent::Frame { .. })));
}

#[tokio::test]
async fn huge_desktop_size_is_a_protocol_error() {
    let mut m = vec![0, 0, 0, 1];
    m.extend(rect_header(0, 0, 65535, 65535, -223));
    let (_, err) = hostile(64, 64, m).await;
    let err = err.expect("error");
    assert_eq!(err.kind, ErrorKind::Protocol, "{}", err.detail);
    assert!(err.detail.contains("65535x65535"), "{}", err.detail);
}

#[tokio::test]
async fn tight_jpeg_bomb_is_refused() {
    let mut jpeg = Vec::new();
    jpeg_encoder::Encoder::new(&mut jpeg, 50).encode(&[128u8; 8 * 8 * 3], 8, 8, jpeg_encoder::ColorType::Rgb).unwrap();
    let i = jpeg.windows(2).position(|p| p == [0xFF, 0xC0]).expect("SOF0");
    jpeg[i + 5..i + 7].copy_from_slice(&65000u16.to_be_bytes());
    jpeg[i + 7..i + 9].copy_from_slice(&65000u16.to_be_bytes());
    let mut m = vec![0, 0, 0, 1];
    m.extend(rect_header(0, 0, 1, 1, 7));
    m.push(0x90);
    m.push((jpeg.len() & 0x7f) as u8 | 0x80);
    m.push((jpeg.len() >> 7) as u8);
    m.extend(jpeg);
    let (_, err) = hostile(64, 64, m).await;
    let err = err.expect("error");
    assert_eq!(err.kind, ErrorKind::Protocol, "{}", err.detail);
    assert!(err.detail.contains("65000x65000"), "{}", err.detail);
}

#[tokio::test]
async fn oversized_clipboard_is_dropped_and_the_session_continues() {
    let len = 2 * 1024 * 1024u32;
    let mut m = vec![3, 0, 0, 0];
    m.extend_from_slice(&len.to_be_bytes());
    m.extend(std::iter::repeat_n(b'x', len as usize));
    m.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 2, b'o', b'k']);
    m.push(2); // Bell: the test closes after it
    let (events, err) = hostile(64, 64, m).await;
    assert!(err.is_none(), "{err:?}");
    let clips: Vec<_> =
        events.iter().filter_map(|e| if let SessionEvent::Clipboard(t) = e { Some(t.clone()) } else { None }).collect();
    assert_eq!(clips, ["ok"]);
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Bell)));
}

#[tokio::test]
async fn apple_srp_session_is_encrypted_and_verified() {
    let opts = AppleOpts { offer_srp: true, expect_srp: true, ..Default::default() };
    let input = vec![SessionInput::Key { code: "KeyA".into(), key: "a".into(), down: true }];
    let run = run_apple(Enc::Zrle, opts, input).await;
    assert_picture(&run.fb);
    assert_eq!(run.security, [VncSecurity::EncryptedVerified], "{:?}", run.statuses);
    assert!(run.statuses.iter().any(|s| s.contains("SRP")), "{:?}", run.statuses);
    assert!(run.received.contains(&vec![4, 1, 0, 0, 0, 0, 0, 0x61]));
}

#[tokio::test]
async fn apple_srp_turned_off_uses_type_30() {
    let opts = AppleOpts { offer_srp: true, expect_srp: false, ..Default::default() };
    let run = run_apple(Enc::Raw, opts, vec![]).await;
    assert_picture(&run.fb);
    assert_eq!(run.security, [VncSecurity::EncryptedUnverified]);
}

#[tokio::test]
async fn apple_srp_wrong_password_is_an_auth_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let opts = AppleOpts { offer_srp: true, expect_srp: true, ..Default::default() };
        serve_apple(s, Enc::Raw, "u", "right", opts).await
    });
    let config = VncConfig { username: Some("u".into()), password: Some(String::from("wrong").into()), ..Default::default() };
    let options = VncOptions::default().with_encryption(EncryptionPolicy::Required);
    let (io, mut handle) = session_channels();
    let client =
        tokio::spawn(async move { rc_vnc::connect_and_run_with_options("127.0.0.1", port, config, options, io).await });
    let err = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error.expect("expected an error"),
            Some(SessionEvent::Connected { .. }) => panic!("must not connect"),
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    };
    assert_eq!(err.kind, ErrorKind::AuthFailed, "{}", err.detail);
    assert!(err.detail.contains("SRP"), "{}", err.detail);
    client.await.unwrap();
    server.await.unwrap();
}

/// Security audit round 2: a man in the middle strips SRP (36) from the Mac's list to force
/// type 30, an unauthenticated Diffie-Hellman exchange that would hand it the password.
#[tokio::test]
async fn required_refuses_srp_stripped_from_the_list() {
    let required = || VncOptions::default().with_encryption(EncryptionPolicy::Required);
    for types in [&[30u8][..], &[30, 33, 35]] {
        let (err, sent) = offer_only(b"RFB 003.889\n", types, creds(), required()).await;
        assert_eq!(err.kind, ErrorKind::Security, "{types:?}: {}", err.detail);
        assert!(rc_vnc::is_srp_not_offered(&err), "{}", err.detail);
        assert!(err.detail.starts_with(rc_vnc::SRP_NOT_OFFERED), "{}", err.detail);
        // Nothing chosen, no credentials sent.
        assert_eq!(sent, b"RFB 003.889\n");
    }
    // SRP turned off (the escape hatch) also needs the opt-in now, with its own message.
    let (err, sent) = offer_only(b"RFB 003.889\n", &[30, 33, 36, 35], creds(), required().with_srp(false)).await;
    assert_eq!(err.kind, ErrorKind::Security, "{}", err.detail);
    assert!(!rc_vnc::is_srp_not_offered(&err), "{}", err.detail);
    assert!(err.detail.contains("turned off"), "{}", err.detail);
    assert_eq!(sent, b"RFB 003.889\n");
}

/// Security audit round 2: a wrong M2 used to be logged and the session still reported as
/// verified. Now it ends the connection before ClientInit.
#[tokio::test]
async fn apple_srp_wrong_server_proof_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let opts = AppleOpts { offer_srp: true, expect_srp: true, bad_m2: true, ..Default::default() };
        serve_apple(s, Enc::Raw, "u", "right", opts).await
    });
    let config =
        VncConfig { username: Some("u".into()), password: Some(String::from("right").into()), ..Default::default() };
    let options = VncOptions::default().with_encryption(EncryptionPolicy::Required);
    let (io, mut handle) = session_channels();
    let client =
        tokio::spawn(async move { rc_vnc::connect_and_run_with_options("127.0.0.1", port, config, options, io).await });
    let err = loop {
        match tokio::time::timeout(T, handle.events.recv()).await.expect("timed out") {
            Some(SessionEvent::Closed { error }) => break error.expect("expected an error"),
            Some(SessionEvent::Connected { .. }) => panic!("must not connect"),
            Some(ev @ SessionEvent::Security { .. }) => panic!("must not report security: {ev:?}"),
            Some(_) => {}
            None => panic!("no Closed event"),
        }
    };
    assert_eq!(err.kind, ErrorKind::Security, "{}", err.detail);
    assert!(err.detail.contains("M2"), "{}", err.detail);
    client.await.unwrap();
    server.await.unwrap();
}
