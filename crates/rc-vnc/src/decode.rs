//! Rectangle decoders. Everything assumes the pixel format this client always requests:
//! 32 bpp, depth 24, little-endian, true colour, 8 bits per channel, red shift 16, green shift 8,
//! blue shift 0. On the wire that is:
//!   PIXEL  (4 bytes) = B, G, R, unused
//!   CPIXEL (ZRLE, 3 bytes) = B, G, R      (the three least-significant bytes)
//!   TPIXEL (Tight, 3 bytes) = R, G, B     (Tight always sends red first)

use crate::error::{proto, Result, VncError};
use crate::fb::{Framebuffer, Rgba};
use crate::zlib::{ByteSrc, ZStream};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const ENC_RAW: i32 = 0;
pub(crate) const ENC_COPYRECT: i32 = 1;
pub(crate) const ENC_RRE: i32 = 2;
pub(crate) const ENC_HEXTILE: i32 = 5;
pub(crate) const ENC_ZLIB: i32 = 6;
pub(crate) const ENC_TIGHT: i32 = 7;
pub(crate) const ENC_ZRLE: i32 = 16;
pub(crate) const ENC_CURSOR: i32 = -239;
pub(crate) const ENC_DESKTOP_SIZE: i32 = -223;
pub(crate) const ENC_LAST_RECT: i32 = -224;
pub(crate) const ENC_EXT_DESKTOP_SIZE: i32 = -308;
/// Tight JPEG quality pseudo-encodings are -32 (level 0) ..= -23 (level 9).
pub(crate) const ENC_JPEG_QUALITY_0: i32 = -32;

/// Upper bound for one zlib-compressed block; a raw 5K screen is ~59 MB uncompressed.
const MAX_COMPRESSED: u32 = 128 * 1024 * 1024;

pub(crate) fn encoding_name(enc: i32) -> &'static str {
    match enc {
        ENC_RAW => "Raw",
        ENC_COPYRECT => "CopyRect",
        ENC_RRE => "RRE",
        4 => "CoRRE",
        ENC_HEXTILE => "Hextile",
        ENC_ZLIB => "Zlib",
        ENC_TIGHT => "Tight",
        8 => "ZlibHex",
        9 => "Ultra",
        ENC_ZRLE => "ZRLE",
        17 => "ZYWRLE",
        ENC_CURSOR => "Cursor (pseudo)",
        -240 => "XCursor (pseudo)",
        ENC_DESKTOP_SIZE => "DesktopSize (pseudo)",
        ENC_LAST_RECT => "LastRect (pseudo)",
        ENC_EXT_DESKTOP_SIZE => "ExtendedDesktopSize (pseudo)",
        -307 => "DesktopName (pseudo)",
        -32..=-23 => "JPEG quality level (pseudo)",
        -256..=-247 => "Compression level (pseudo)",
        1000..=1002 | 1011 | 1100..=1105 => "Apple-specific",
        _ => "unknown",
    }
}

#[inline]
fn bgrx(p: &[u8]) -> Rgba {
    [p[2], p[1], p[0], 255]
}

/// Read exactly `len` bytes without trusting `len` for the up-front allocation.
async fn read_vec<R: AsyncRead + Unpin>(r: &mut R, len: usize, out: &mut Vec<u8>) -> Result<()> {
    out.clear();
    let got = r.take(len as u64).read_to_end(out).await?;
    if got != len {
        return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(())
}

pub(crate) struct Decoder {
    zlib: ZStream,
    zrle: ZStream,
    tight: [ZStream; 4],
    /// Scratch for wire data (compressed blocks, raw rows).
    scratch: Vec<u8>,
    /// Scratch for decoded rows / tiles.
    rows: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Decoder {
            zlib: ZStream::new(),
            zrle: ZStream::new(),
            tight: [ZStream::new(), ZStream::new(), ZStream::new(), ZStream::new()],
            scratch: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Decode one rectangle of a real (non-pseudo) encoding into `fb`. CopyRect is handled by
    /// the caller. Returns Ok(false) for an encoding this decoder does not know.
    pub async fn decode<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        (x, y, w, h): (usize, usize, usize, usize),
        enc: i32,
    ) -> Result<bool> {
        match enc {
            ENC_RAW => self.raw(r, fb, x, y, w, h).await?,
            ENC_RRE => self.rre(r, fb, x, y, w, h).await?,
            ENC_HEXTILE => self.hextile(r, fb, x, y, w, h).await?,
            ENC_ZLIB => self.zlib(r, fb, x, y, w, h).await?,
            ENC_ZRLE => self.zrle(r, fb, x, y, w, h).await?,
            ENC_TIGHT => self.tight(r, fb, x, y, w, h).await?,
            _ => return Ok(false),
        }
        // Do not let one unusually large block pin memory for the rest of the session.
        const KEEP: usize = 4 * 1024 * 1024;
        if self.scratch.capacity() > KEEP {
            self.scratch = Vec::new();
        }
        if self.rows.capacity() > KEEP {
            self.rows = Vec::new();
        }
        Ok(true)
    }

    async fn raw<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        if w == 0 || h == 0 {
            return Ok(());
        }
        let row_bytes = w * 4;
        let rows_per_chunk = (64 * 1024 / row_bytes).max(1);
        let mut row = 0;
        while row < h {
            let n = rows_per_chunk.min(h - row);
            self.scratch.resize(n * row_bytes, 0);
            r.read_exact(&mut self.scratch).await?;
            for (i, line) in self.scratch.chunks_exact(row_bytes).enumerate() {
                fb.put_bgrx_row(x, y + row + i, line);
            }
            row += n;
        }
        Ok(())
    }

    async fn rre<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        let count = r.read_u32().await?;
        let mut bg = [0u8; 4];
        r.read_exact(&mut bg).await?;
        fb.fill(x, y, w, h, bgrx(&bg));
        let mut sub = [0u8; 12];
        for _ in 0..count {
            r.read_exact(&mut sub).await?;
            let sx = u16::from_be_bytes([sub[4], sub[5]]) as usize;
            let sy = u16::from_be_bytes([sub[6], sub[7]]) as usize;
            let sw = u16::from_be_bytes([sub[8], sub[9]]) as usize;
            let sh = u16::from_be_bytes([sub[10], sub[11]]) as usize;
            // Keep subrectangles inside their parent rectangle.
            if sx < w && sy < h {
                fb.fill(x + sx, y + sy, sw.min(w - sx), sh.min(h - sy), bgrx(&sub));
            }
        }
        Ok(())
    }

    async fn hextile<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        const RAW: u8 = 1;
        const BG: u8 = 2;
        const FG: u8 = 4;
        const ANY_SUBRECTS: u8 = 8;
        const SUBRECTS_COLOURED: u8 = 16;
        let mut bg: Rgba = [0, 0, 0, 255];
        let mut fg: Rgba = [0, 0, 0, 255];
        let mut px = [0u8; 4];
        for ty in (0..h).step_by(16) {
            let th = 16.min(h - ty);
            for tx in (0..w).step_by(16) {
                let tw = 16.min(w - tx);
                let flags = r.read_u8().await?;
                if flags & RAW != 0 {
                    self.scratch.resize(tw * th * 4, 0);
                    r.read_exact(&mut self.scratch).await?;
                    for (i, line) in self.scratch.chunks_exact(tw * 4).enumerate() {
                        fb.put_bgrx_row(x + tx, y + ty + i, line);
                    }
                    continue;
                }
                if flags & BG != 0 {
                    r.read_exact(&mut px).await?;
                    bg = bgrx(&px);
                }
                fb.fill(x + tx, y + ty, tw, th, bg);
                if flags & FG != 0 {
                    r.read_exact(&mut px).await?;
                    fg = bgrx(&px);
                }
                if flags & ANY_SUBRECTS != 0 {
                    let n = r.read_u8().await? as usize;
                    let coloured = flags & SUBRECTS_COLOURED != 0;
                    let each = if coloured { 6 } else { 2 };
                    self.scratch.resize(n * each, 0);
                    r.read_exact(&mut self.scratch).await?;
                    for s in self.scratch.chunks_exact(each) {
                        let (colour, geom) = if coloured { (bgrx(s), &s[4..]) } else { (fg, s) };
                        let sx = (geom[0] >> 4) as usize;
                        let sy = (geom[0] & 15) as usize;
                        let sw = (geom[1] >> 4) as usize + 1;
                        let sh = (geom[1] & 15) as usize + 1;
                        if sx < tw && sy < th {
                            fb.fill(x + tx + sx, y + ty + sy, sw.min(tw - sx), sh.min(th - sy), colour);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn read_zblock<R: AsyncRead + Unpin>(&mut self, r: &mut R, what: &str) -> Result<()> {
        let len = r.read_u32().await?;
        if len > MAX_COMPRESSED {
            return proto(format!("{what}: implausible compressed length {len}"));
        }
        read_vec(r, len as usize, &mut self.scratch).await
    }

    async fn zlib<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        self.read_zblock(r, "Zlib").await?;
        let mut z = self.zlib.reader(&self.scratch);
        if w > 0 {
            self.rows.resize(w * 4, 0);
            for row in 0..h {
                z.read_exact(&mut self.rows)?;
                fb.put_bgrx_row(x, y + row, &self.rows);
            }
        }
        z.finish()
    }

    async fn zrle<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        self.read_zblock(r, "ZRLE").await?;
        let mut z = self.zrle.reader(&self.scratch);
        self.rows.resize(64 * 64 * 4, 0);
        for ty in (0..h).step_by(64) {
            let th = 64.min(h - ty);
            for tx in (0..w).step_by(64) {
                let tw = 64.min(w - tx);
                let tile = &mut self.rows[..tw * th * 4];
                zrle_tile(&mut z, tile, tw, th)?;
                for (i, line) in tile.chunks_exact(tw * 4).enumerate() {
                    fb.put_rgba_row(x + tx, y + ty + i, line);
                }
            }
        }
        z.finish()
    }

    async fn tight<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        fb: &mut Framebuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Result<()> {
        let ctl = r.read_u8().await?;
        for (i, stream) in self.tight.iter_mut().enumerate() {
            if ctl & (1 << i) != 0 {
                stream.reset();
            }
        }
        let kind = ctl >> 4;
        match kind {
            8 => {
                let mut c = [0u8; 3];
                r.read_exact(&mut c).await?;
                fb.fill(x, y, w, h, [c[0], c[1], c[2], 255]);
                return Ok(());
            }
            9 => {
                let len = tight_compact_len(r).await?;
                read_vec(r, len, &mut self.scratch).await?;
                return tight_jpeg(&self.scratch, fb, x, y, w, h);
            }
            10..=15 => return proto(format!("Tight: invalid compression control byte {ctl:#04x}")),
            _ => {}
        }

        // Basic compression.
        let stream = (kind & 3) as usize;
        let filter_id = if kind & 4 != 0 { r.read_u8().await? } else { 0 };
        let mut palette = [[0u8, 0, 0, 255]; 256];
        let filter = match filter_id {
            0 => TightFilter::Copy,
            1 => {
                let n = r.read_u8().await? as usize + 1;
                let mut raw = [0u8; 256 * 3];
                r.read_exact(&mut raw[..n * 3]).await?;
                for (p, c) in palette.iter_mut().zip(raw[..n * 3].chunks_exact(3)) {
                    *p = [c[0], c[1], c[2], 255];
                }
                TightFilter::Palette(n)
            }
            2 => TightFilter::Gradient,
            other => return proto(format!("Tight: unknown filter {other}")),
        };
        let row_bytes = match filter {
            TightFilter::Copy | TightFilter::Gradient => w * 3,
            TightFilter::Palette(n) if n <= 2 => w.div_ceil(8),
            TightFilter::Palette(_) => w,
        };
        let total = row_bytes * h;
        if total < 12 {
            // Too small to be worth compressing: sent as-is, no length prefix.
            let mut small = [0u8; 12];
            r.read_exact(&mut small[..total]).await?;
            let mut src: &[u8] = &small[..total];
            tight_rows(&mut src, fb, &mut self.rows, filter, &palette, (x, y, w, h), row_bytes)
        } else {
            let len = tight_compact_len(r).await?;
            read_vec(r, len, &mut self.scratch).await?;
            let mut z = self.tight[stream].reader(&self.scratch);
            tight_rows(&mut z, fb, &mut self.rows, filter, &palette, (x, y, w, h), row_bytes)?;
            z.finish()
        }
    }
}

#[derive(Clone, Copy)]
enum TightFilter {
    Copy,
    Palette(usize),
    Gradient,
}

async fn tight_compact_len<R: AsyncRead + Unpin>(r: &mut R) -> Result<usize> {
    let b0 = r.read_u8().await? as usize;
    let mut len = b0 & 0x7f;
    if b0 & 0x80 != 0 {
        let b1 = r.read_u8().await? as usize;
        len |= (b1 & 0x7f) << 7;
        if b1 & 0x80 != 0 {
            let b2 = r.read_u8().await? as usize;
            len |= b2 << 14;
        }
    }
    Ok(len)
}

fn tight_rows<S: ByteSrc>(
    src: &mut S,
    fb: &mut Framebuffer,
    rows: &mut Vec<u8>,
    filter: TightFilter,
    palette: &[Rgba; 256],
    (x, y, w, h): (usize, usize, usize, usize),
    row_bytes: usize,
) -> Result<()> {
    if w == 0 || h == 0 {
        return Ok(());
    }
    match filter {
        TightFilter::Copy => {
            rows.resize(row_bytes, 0);
            for row in 0..h {
                src.read_exact(rows)?;
                fb.put_rgb_row(x, y + row, rows);
            }
        }
        TightFilter::Gradient => {
            // rows = [previous decoded row | current row]
            rows.clear();
            rows.resize(row_bytes * 2, 0);
            let (prev, cur) = rows.split_at_mut(row_bytes);
            for row in 0..h {
                src.read_exact(cur)?;
                for i in 0..row_bytes {
                    let left = if i >= 3 { cur[i - 3] as i32 } else { 0 };
                    let up = prev[i] as i32;
                    let up_left = if i >= 3 { prev[i - 3] as i32 } else { 0 };
                    let predicted = (left + up - up_left).clamp(0, 255);
                    cur[i] = (cur[i] as i32 + predicted) as u8;
                }
                fb.put_rgb_row(x, y + row, cur);
                prev.copy_from_slice(cur);
            }
        }
        TightFilter::Palette(n) => {
            // rows = [wire row | RGBA row]
            rows.resize(row_bytes + w * 4, 0);
            let (wire, out) = rows.split_at_mut(row_bytes);
            for row in 0..h {
                src.read_exact(wire)?;
                if n <= 2 {
                    for (i, px) in out.chunks_exact_mut(4).enumerate() {
                        let bit = (wire[i / 8] >> (7 - (i % 8))) & 1;
                        px.copy_from_slice(&palette[bit as usize]);
                    }
                } else {
                    for (px, &idx) in out.chunks_exact_mut(4).zip(wire.iter()) {
                        px.copy_from_slice(&palette[idx as usize]);
                    }
                }
                fb.put_rgba_row(x, y + row, out);
            }
        }
    }
    Ok(())
}

fn tight_jpeg(data: &[u8], fb: &mut Framebuffer, x: usize, y: usize, w: usize, h: usize) -> Result<()> {
    use jpeg_decoder::PixelFormat;
    let mut dec = jpeg_decoder::Decoder::new(data);
    let pixels = dec.decode().map_err(|e| VncError::Protocol(format!("Tight: JPEG decode failed: {e}")))?;
    let info = dec.info().ok_or_else(|| VncError::Protocol("Tight: JPEG has no header".into()))?;
    let (jw, jh) = (info.width as usize, info.height as usize);
    if jw != w || jh != h {
        return proto(format!("Tight: JPEG is {jw}x{jh} but the rectangle is {w}x{h}"));
    }
    match info.pixel_format {
        PixelFormat::RGB24 if pixels.len() == w * h * 3 => {
            for (row, line) in pixels.chunks_exact(w * 3).enumerate() {
                fb.put_rgb_row(x, y + row, line);
            }
        }
        PixelFormat::L8 if pixels.len() == w * h => {
            let mut line = vec![0u8; w * 3];
            for (row, grey) in pixels.chunks_exact(w).enumerate() {
                for (px, &g) in line.chunks_exact_mut(3).zip(grey) {
                    px.fill(g);
                }
                fb.put_rgb_row(x, y + row, &line);
            }
        }
        other => return proto(format!("Tight: unsupported JPEG pixel format {other:?}")),
    }
    Ok(())
}

/// Decode one ZRLE tile into `tile` (RGBA, `tw * th * 4` bytes).
fn zrle_tile<S: ByteSrc>(z: &mut S, tile: &mut [u8], tw: usize, th: usize) -> Result<()> {
    fn cpixel<S: ByteSrc>(z: &mut S) -> Result<Rgba> {
        let mut c = [0u8; 3];
        z.read_exact(&mut c)?;
        Ok([c[2], c[1], c[0], 255])
    }
    fn run_length<S: ByteSrc>(z: &mut S) -> Result<usize> {
        let mut len = 1usize;
        loop {
            let b = z.u8()?;
            len += b as usize;
            if b != 255 {
                return Ok(len);
            }
        }
    }

    let sub = z.u8()?;
    let npix = tw * th;
    match sub {
        0 => {
            let mut raw = [0u8; 64 * 3];
            for line in tile.chunks_exact_mut(tw * 4) {
                z.read_exact(&mut raw[..tw * 3])?;
                for (px, c) in line.chunks_exact_mut(4).zip(raw.chunks_exact(3)) {
                    px.copy_from_slice(&[c[2], c[1], c[0], 255]);
                }
            }
        }
        1 => {
            let c = cpixel(z)?;
            for px in tile.chunks_exact_mut(4) {
                px.copy_from_slice(&c);
            }
        }
        2..=16 => {
            let n = sub as usize;
            let mut palette = [[0u8, 0, 0, 255]; 16];
            for p in palette.iter_mut().take(n) {
                *p = cpixel(z)?;
            }
            let bits = match n {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            let row_bytes = (tw * bits).div_ceil(8);
            let mut packed = [0u8; 32];
            for line in tile.chunks_exact_mut(tw * 4) {
                z.read_exact(&mut packed[..row_bytes])?;
                for (i, px) in line.chunks_exact_mut(4).enumerate() {
                    let bit = i * bits;
                    let idx = (packed[bit / 8] >> (8 - bits - (bit % 8))) & ((1 << bits) - 1);
                    // An index past the palette is a server bug; draw it black rather than
                    // failing the whole session.
                    px.copy_from_slice(&palette[idx as usize]);
                }
            }
        }
        128 => {
            let mut done = 0;
            while done < npix {
                let c = cpixel(z)?;
                let len = run_length(z)?;
                if done + len > npix {
                    return proto("ZRLE: run overflows tile");
                }
                for px in tile[done * 4..(done + len) * 4].chunks_exact_mut(4) {
                    px.copy_from_slice(&c);
                }
                done += len;
            }
        }
        130..=255 => {
            let n = (sub - 128) as usize;
            let mut palette = [[0u8; 4]; 127];
            for p in palette.iter_mut().take(n) {
                *p = cpixel(z)?;
            }
            let mut done = 0;
            while done < npix {
                let b = z.u8()?;
                let len = if b & 0x80 != 0 { run_length(z)? } else { 1 };
                let idx = (b & 0x7f) as usize;
                if idx >= n {
                    return proto("ZRLE: palette index out of range");
                }
                if done + len > npix {
                    return proto("ZRLE: run overflows tile");
                }
                for px in tile[done * 4..(done + len) * 4].chunks_exact_mut(4) {
                    px.copy_from_slice(&palette[idx]);
                }
                done += len;
            }
        }
        other => return proto(format!("ZRLE: invalid tile subencoding {other}")),
    }
    Ok(())
}

/// Decode the body of a Cursor pseudo-encoding rectangle into straight-alpha RGBA.
pub(crate) async fn read_cursor<R: AsyncRead + Unpin>(r: &mut R, w: usize, h: usize) -> Result<Vec<u8>> {
    let mask_row = w.div_ceil(8);
    let mut pixels = Vec::new();
    read_vec(r, w * h * 4, &mut pixels).await?;
    let mut mask = Vec::new();
    read_vec(r, mask_row * h, &mut mask).await?;
    let mut rgba = Vec::with_capacity(w * h * 4);
    for (i, p) in pixels.chunks_exact(4).enumerate() {
        let (cx, cy) = (i % w, i / w);
        let opaque = mask[cy * mask_row + cx / 8] & (0x80 >> (cx % 8)) != 0;
        rgba.extend_from_slice(&[p[2], p[1], p[0], if opaque { 255 } else { 0 }]);
    }
    Ok(rgba)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zlib::tests::TestDeflater;

    const RED: Rgba = [255, 0, 0, 255];
    const GREEN: Rgba = [0, 255, 0, 255];
    const BLUE: Rgba = [0, 0, 255, 255];
    const ORANGE: Rgba = [250, 128, 16, 255];

    /// Wire PIXEL for an RGBA colour.
    fn px(c: Rgba) -> [u8; 4] {
        [c[2], c[1], c[0], 0]
    }
    fn cpx(c: Rgba) -> [u8; 3] {
        [c[2], c[1], c[0]]
    }
    fn tpx(c: Rgba) -> [u8; 3] {
        [c[0], c[1], c[2]]
    }

    /// Decode and assert the whole stream was consumed.
    async fn run(dec: &mut Decoder, fb: &mut Framebuffer, rect: (usize, usize, usize, usize), enc: i32, data: &[u8]) {
        let mut r: &[u8] = data;
        assert!(dec.decode(&mut r, fb, rect, enc).await.unwrap());
        assert!(r.is_empty(), "{} trailing bytes", r.len());
    }

    #[tokio::test]
    async fn raw_converts_bgrx_to_rgba() {
        let mut fb = Framebuffer::new(4, 3);
        let mut data = Vec::new();
        for c in [RED, GREEN, BLUE, ORANGE] {
            data.extend_from_slice(&px(c));
        }
        run(&mut Decoder::new(), &mut fb, (1, 1, 2, 2), ENC_RAW, &data).await;
        assert_eq!(fb.pixel(1, 1), RED);
        assert_eq!(fb.pixel(2, 1), GREEN);
        assert_eq!(fb.pixel(1, 2), BLUE);
        assert_eq!(fb.pixel(2, 2), ORANGE);
        assert_eq!(fb.pixel(0, 0), [0, 0, 0, 255]);
    }

    #[tokio::test]
    async fn raw_out_of_bounds_is_consumed_and_clipped() {
        let mut fb = Framebuffer::new(2, 2);
        let data: Vec<u8> = px(RED).repeat(9);
        run(&mut Decoder::new(), &mut fb, (1, 1, 3, 3), ENC_RAW, &data).await;
        assert_eq!(fb.pixel(1, 1), RED);
        assert_eq!(fb.pixel(0, 0), [0, 0, 0, 255]);
    }

    #[tokio::test]
    async fn rre() {
        let mut fb = Framebuffer::new(8, 8);
        let mut data = vec![0, 0, 0, 2];
        data.extend_from_slice(&px(BLUE));
        data.extend_from_slice(&px(RED));
        data.extend_from_slice(&[0, 1, 0, 1, 0, 2, 0, 2]);
        data.extend_from_slice(&px(ORANGE));
        data.extend_from_slice(&[0, 3, 0, 0, 0, 1, 0, 4]);
        run(&mut Decoder::new(), &mut fb, (2, 2, 4, 4), ENC_RRE, &data).await;
        assert_eq!(fb.pixel(2, 2), BLUE);
        assert_eq!(fb.pixel(3, 3), RED);
        assert_eq!(fb.pixel(4, 4), RED);
        assert_eq!(fb.pixel(5, 2), ORANGE);
        assert_eq!(fb.pixel(5, 5), ORANGE);
        assert_eq!(fb.pixel(6, 2), [0, 0, 0, 255]);
    }

    #[tokio::test]
    async fn hextile() {
        // 20x18 rect => tiles: (16x16, 4x16) then (16x2, 4x2)
        let mut fb = Framebuffer::new(20, 18);
        let mut data = Vec::new();
        // tile 0: bg + fg + 2 monochrome subrects
        data.push(2 | 4 | 8);
        data.extend_from_slice(&px(BLUE));
        data.extend_from_slice(&px(RED));
        data.push(2);
        data.extend_from_slice(&[0x00, 0x00]); // 1x1 at 0,0
        data.extend_from_slice(&[0x12, 0x31]); // x=1,y=2 w=4,h=2
        // tile 1: reuse bg, coloured subrect
        data.push(8 | 16);
        data.push(1);
        data.extend_from_slice(&px(GREEN));
        data.extend_from_slice(&[0x10, 0x0f]); // x=1,y=0 w=1,h=16
        // tile 2: raw 16x2
        data.push(1);
        for i in 0..32 {
            data.extend_from_slice(&px(if i % 2 == 0 { ORANGE } else { GREEN }));
        }
        // tile 3: nothing specified => previous bg (blue)
        data.push(0);
        run(&mut Decoder::new(), &mut fb, (0, 0, 20, 18), ENC_HEXTILE, &data).await;
        assert_eq!(fb.pixel(0, 0), RED);
        assert_eq!(fb.pixel(1, 0), BLUE);
        assert_eq!(fb.pixel(1, 2), RED);
        assert_eq!(fb.pixel(4, 3), RED);
        assert_eq!(fb.pixel(5, 3), BLUE);
        assert_eq!(fb.pixel(16, 5), BLUE);
        assert_eq!(fb.pixel(17, 15), GREEN);
        assert_eq!(fb.pixel(0, 16), ORANGE);
        assert_eq!(fb.pixel(1, 17), GREEN);
        assert_eq!(fb.pixel(19, 17), BLUE);
    }

    #[tokio::test]
    async fn zlib_two_rects_share_one_stream() {
        let mut fb = Framebuffer::new(4, 2);
        let mut def = TestDeflater::new();
        let mut dec = Decoder::new();
        for (row, colour) in [(0, ORANGE), (1, GREEN)] {
            let comp = def.block(&px(colour).repeat(4));
            let mut data = (comp.len() as u32).to_be_bytes().to_vec();
            data.extend_from_slice(&comp);
            run(&mut dec, &mut fb, (0, row, 4, 1), ENC_ZLIB, &data).await;
        }
        assert_eq!(fb.pixel(3, 0), ORANGE);
        assert_eq!(fb.pixel(0, 1), GREEN);
    }

    fn zrle_wrap(def: &mut TestDeflater, tiles: &[u8]) -> Vec<u8> {
        let comp = def.block(tiles);
        let mut data = (comp.len() as u32).to_be_bytes().to_vec();
        data.extend_from_slice(&comp);
        data
    }

    #[tokio::test]
    async fn zrle_all_subencodings() {
        // 70x4 rect => tile A 64x4 and tile B 6x4 per update.
        let mut def = TestDeflater::new();
        let mut dec = Decoder::new();
        let mut fb = Framebuffer::new(70, 4);

        // Update 1: A = solid, B = raw
        let mut t = vec![1];
        t.extend_from_slice(&cpx(ORANGE));
        t.push(0);
        for i in 0..24 {
            t.extend_from_slice(&cpx(if i == 7 { RED } else { BLUE }));
        }
        run(&mut dec, &mut fb, (0, 0, 70, 4), ENC_ZRLE, &zrle_wrap(&mut def, &t)).await;
        assert_eq!(fb.pixel(63, 3), ORANGE);
        assert_eq!(fb.pixel(64, 0), BLUE);
        assert_eq!(fb.pixel(65, 1), RED);

        // Update 2: A = plain RLE (run of 256 = 64*4 written as 255, 0), B = packed palette of 2
        let mut t = vec![128];
        t.extend_from_slice(&cpx(GREEN));
        t.extend_from_slice(&[255, 0]);
        t.push(2);
        t.extend_from_slice(&cpx(RED));
        t.extend_from_slice(&cpx(BLUE));
        t.extend_from_slice(&[0b0100_0000, 0b1111_1100, 0, 0b1000_0000]); // 6 px per row, padded
        run(&mut dec, &mut fb, (0, 0, 70, 4), ENC_ZRLE, &zrle_wrap(&mut def, &t)).await;
        assert_eq!(fb.pixel(0, 0), GREEN);
        assert_eq!(fb.pixel(63, 3), GREEN);
        assert_eq!(fb.pixel(64, 0), RED);
        assert_eq!(fb.pixel(65, 0), BLUE);
        assert_eq!(fb.pixel(69, 1), BLUE);
        assert_eq!(fb.pixel(66, 2), RED);
        assert_eq!(fb.pixel(64, 3), BLUE);
        assert_eq!(fb.pixel(65, 3), RED);

        // Update 3: A = palette RLE (3 colours), B = packed palette of 3 (2 bits) then of 5 (4 bits)
        let mut t = vec![131];
        for c in [RED, GREEN, BLUE] {
            t.extend_from_slice(&cpx(c));
        }
        t.push(0); // single RED
        t.extend_from_slice(&[0x81, 253]); // GREEN run of 254
        t.push(2); // single BLUE  (1 + 254 + 1 = 256)
        t.push(3);
        for c in [RED, GREEN, BLUE] {
            t.extend_from_slice(&cpx(c));
        }
        for _ in 0..4 {
            t.extend_from_slice(&[0b00_01_10_00, 0b01_10_00_00]); // R G B R G B
        }
        run(&mut dec, &mut fb, (0, 0, 70, 4), ENC_ZRLE, &zrle_wrap(&mut def, &t)).await;
        assert_eq!(fb.pixel(0, 0), RED);
        assert_eq!(fb.pixel(1, 0), GREEN);
        assert_eq!(fb.pixel(62, 3), GREEN);
        assert_eq!(fb.pixel(63, 3), BLUE);
        assert_eq!(fb.pixel(64, 2), RED);
        assert_eq!(fb.pixel(66, 2), BLUE);
        assert_eq!(fb.pixel(69, 3), BLUE);

        // Update 4 on a 2x1 rect: packed palette of 5 (4 bits per pixel)
        let mut t = vec![5];
        for c in [RED, GREEN, BLUE, ORANGE, [1, 2, 3, 255]] {
            t.extend_from_slice(&cpx(c));
        }
        t.push(0x43);
        run(&mut dec, &mut fb, (0, 0, 2, 1), ENC_ZRLE, &zrle_wrap(&mut def, &t)).await;
        assert_eq!(fb.pixel(0, 0), [1, 2, 3, 255]);
        assert_eq!(fb.pixel(1, 0), ORANGE);
    }

    #[tokio::test]
    async fn zrle_bad_run_is_error_not_panic() {
        let mut def = TestDeflater::new();
        let mut t = vec![128];
        t.extend_from_slice(&cpx(GREEN));
        t.extend_from_slice(&[255, 255, 0]);
        let data = zrle_wrap(&mut def, &t);
        let mut fb = Framebuffer::new(4, 4);
        let mut r: &[u8] = &data;
        assert!(Decoder::new().decode(&mut r, &mut fb, (0, 0, 4, 4), ENC_ZRLE).await.is_err());
    }

    fn compact(len: usize) -> Vec<u8> {
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
    }

    #[tokio::test]
    async fn tight_fill_and_copy() {
        let mut fb = Framebuffer::new(8, 8);
        let mut dec = Decoder::new();
        let mut data = vec![0x80];
        data.extend_from_slice(&tpx(ORANGE));
        run(&mut dec, &mut fb, (0, 0, 8, 8), ENC_TIGHT, &data).await;
        assert_eq!(fb.pixel(7, 7), ORANGE);

        // Copy filter, tiny (3 px = 9 bytes < 12): uncompressed, no length.
        let mut data = vec![0x00];
        for c in [RED, GREEN, BLUE] {
            data.extend_from_slice(&tpx(c));
        }
        run(&mut dec, &mut fb, (0, 0, 3, 1), ENC_TIGHT, &data).await;
        assert_eq!([fb.pixel(0, 0), fb.pixel(1, 0), fb.pixel(2, 0)], [RED, GREEN, BLUE]);

        // Copy filter, compressed on stream 2, twice (stream state persists), with explicit
        // filter id 0 the second time.
        let mut def = TestDeflater::new();
        for (ctl, extra, colour) in [(0x20u8, None, GREEN), (0x60, Some(0u8), BLUE)] {
            let comp = def.block(&tpx(colour).repeat(16));
            let mut data = vec![ctl];
            data.extend(extra);
            data.extend(compact(comp.len()));
            data.extend_from_slice(&comp);
            run(&mut dec, &mut fb, (4, 4, 4, 4), ENC_TIGHT, &data).await;
            assert_eq!(fb.pixel(4, 4), colour);
            assert_eq!(fb.pixel(7, 7), colour);
        }
        assert_eq!(fb.pixel(3, 3), ORANGE);

        // Stream reset flag: a fresh deflater on stream 2 only works if bit 2 resets it.
        let mut def = TestDeflater::new();
        let comp = def.block(&tpx(RED).repeat(16));
        let mut data = vec![0x20 | 0x04];
        data.extend(compact(comp.len()));
        data.extend_from_slice(&comp);
        run(&mut dec, &mut fb, (4, 4, 4, 4), ENC_TIGHT, &data).await;
        assert_eq!(fb.pixel(5, 5), RED);
    }

    #[tokio::test]
    async fn tight_palette() {
        let mut fb = Framebuffer::new(10, 4);
        let mut dec = Decoder::new();
        // 2 colours, 10x2 => 2 bytes per row = 4 bytes (< 12, uncompressed)
        let mut data = vec![0x40, 1, 1];
        data.extend_from_slice(&tpx(RED));
        data.extend_from_slice(&tpx(BLUE));
        data.extend_from_slice(&[0b1000_0000, 0b0100_0000, 0b0000_0001, 0b1000_0000]);
        run(&mut dec, &mut fb, (0, 0, 10, 2), ENC_TIGHT, &data).await;
        assert_eq!(fb.pixel(0, 0), BLUE);
        assert_eq!(fb.pixel(1, 0), RED);
        assert_eq!(fb.pixel(9, 0), BLUE);
        assert_eq!(fb.pixel(7, 1), BLUE);
        assert_eq!(fb.pixel(8, 1), BLUE);
        assert_eq!(fb.pixel(9, 1), RED);

        // 3 colours, 10x2 => 20 index bytes, compressed on stream 1
        let mut def = TestDeflater::new();
        let idx: Vec<u8> = (0..20).map(|i| (i % 3) as u8).collect();
        let comp = def.block(&idx);
        let mut data = vec![0x50, 1, 2];
        for c in [RED, GREEN, ORANGE] {
            data.extend_from_slice(&tpx(c));
        }
        data.extend(compact(comp.len()));
        data.extend_from_slice(&comp);
        run(&mut dec, &mut fb, (0, 2, 10, 2), ENC_TIGHT, &data).await;
        assert_eq!(fb.pixel(0, 2), RED);
        assert_eq!(fb.pixel(1, 2), GREEN);
        assert_eq!(fb.pixel(2, 2), ORANGE);
        assert_eq!(fb.pixel(0, 3), GREEN); // index 10 % 3 == 1
    }

    #[tokio::test]
    async fn tight_gradient() {
        // Encode an image with the gradient predictor, then check we invert it.
        let (w, h) = (5usize, 4usize);
        let img: Vec<[u8; 3]> =
            (0..w * h).map(|i| [(i * 13 % 256) as u8, (255 - i * 7 % 256) as u8, (i * i % 256) as u8]).collect();
        let at = |x: isize, y: isize, c: usize| -> i32 {
            if x < 0 || y < 0 {
                0
            } else {
                img[y as usize * w + x as usize][c] as i32
            }
        };
        let mut residual = Vec::new();
        for y in 0..h as isize {
            for x in 0..w as isize {
                for c in 0..3 {
                    let pred = (at(x - 1, y, c) + at(x, y - 1, c) - at(x - 1, y - 1, c)).clamp(0, 255);
                    residual.push((at(x, y, c) - pred) as u8);
                }
            }
        }
        let mut def = TestDeflater::new();
        let comp = def.block(&residual);
        let mut data = vec![0x40, 2];
        data.extend(compact(comp.len()));
        data.extend_from_slice(&comp);
        let mut fb = Framebuffer::new(w, h);
        run(&mut Decoder::new(), &mut fb, (0, 0, w, h), ENC_TIGHT, &data).await;
        for y in 0..h {
            for x in 0..w {
                let p = img[y * w + x];
                assert_eq!(fb.pixel(x, y), [p[0], p[1], p[2], 255]);
            }
        }
    }

    #[tokio::test]
    async fn tight_jpeg() {
        let (w, h) = (32usize, 16usize);
        // Left half red-ish, right half blue-ish: catches channel swaps.
        let mut rgb = Vec::new();
        for _ in 0..h {
            for x in 0..w {
                rgb.extend_from_slice(if x < w / 2 { &[220, 30, 30] } else { &[30, 30, 220] });
            }
        }
        let mut jpeg = Vec::new();
        jpeg_encoder::Encoder::new(&mut jpeg, 95)
            .encode(&rgb, w as u16, h as u16, jpeg_encoder::ColorType::Rgb)
            .unwrap();
        assert!(jpeg.len() > 127, "want a multi-byte compact length");
        let mut data = vec![0x90];
        data.extend(compact(jpeg.len()));
        data.extend_from_slice(&jpeg);
        let mut fb = Framebuffer::new(w, h);
        run(&mut Decoder::new(), &mut fb, (0, 0, w, h), ENC_TIGHT, &data).await;
        let near = |a: Rgba, b: [i32; 3]| (0..3).all(|i| (a[i] as i32 - b[i]).abs() < 24);
        assert!(near(fb.pixel(2, 2), [220, 30, 30]), "{:?}", fb.pixel(2, 2));
        assert!(near(fb.pixel(29, 13), [30, 30, 220]), "{:?}", fb.pixel(29, 13));
        assert_eq!(fb.pixel(0, 0)[3], 255);
    }

    #[tokio::test]
    async fn tight_invalid_control() {
        let mut fb = Framebuffer::new(4, 4);
        let mut r: &[u8] = &[0xA0, 0, 0, 0];
        assert!(Decoder::new().decode(&mut r, &mut fb, (0, 0, 4, 4), ENC_TIGHT).await.is_err());
    }

    #[tokio::test]
    async fn cursor() {
        // 9x2 cursor: mask rows are 2 bytes.
        let mut data = Vec::new();
        for i in 0..18 {
            data.extend_from_slice(&px(if i == 0 { RED } else { BLUE }));
        }
        data.extend_from_slice(&[0b1000_0000, 0b1000_0000, 0b0000_0001, 0]);
        let mut r: &[u8] = &data;
        let rgba = read_cursor(&mut r, 9, 2).await.unwrap();
        assert!(r.is_empty());
        assert_eq!(&rgba[0..4], &RED);
        assert_eq!(&rgba[4..8], &[0, 0, 255, 0]);
        assert_eq!(&rgba[8 * 4..9 * 4], &BLUE);
        assert_eq!(&rgba[(9 + 7) * 4..(9 + 8) * 4], &BLUE);
        assert_eq!(rgba[(9 + 8) * 4 + 3], 0);
    }

    #[tokio::test]
    async fn unknown_encoding_and_truncation() {
        let mut fb = Framebuffer::new(4, 4);
        let mut r: &[u8] = &[];
        assert!(!Decoder::new().decode(&mut r, &mut fb, (0, 0, 4, 4), 999).await.unwrap());
        let mut r: &[u8] = &[1, 2, 3];
        assert!(Decoder::new().decode(&mut r, &mut fb, (0, 0, 4, 4), ENC_RAW).await.is_err());
    }
}
