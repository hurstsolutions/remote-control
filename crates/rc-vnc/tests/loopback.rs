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
        password: (sec != Sec::None).then(|| "p@ss wörd".to_string()),
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
    let cfg = VncConfig { password: Some("wrong".into()), ..Default::default() };
    let err = expect_failure(Sec::Vnc, cfg).await;
    assert_eq!(err.kind, ErrorKind::AuthFailed);
    assert!(err.detail.contains("Authentication failed (mock)"), "{}", err.detail);
}

#[tokio::test]
async fn wrong_apple_password() {
    let cfg = VncConfig { username: Some("mockuser".into()), password: Some("wrong".into()), ..Default::default() };
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
