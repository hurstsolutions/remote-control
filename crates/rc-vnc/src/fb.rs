//! Local RGBA framebuffer. All drawing primitives clip, so a rectangle that pokes outside the
//! framebuffer (seen from some servers around a resize) is consumed from the wire but never
//! writes out of bounds.

pub(crate) type Rgba = [u8; 4];

pub(crate) struct Framebuffer {
    w: usize,
    h: usize,
    data: Vec<u8>,
}

impl Framebuffer {
    pub fn new(w: usize, h: usize) -> Self {
        let mut fb = Framebuffer { w: 0, h: 0, data: Vec::new() };
        fb.resize(w, h);
        fb
    }

    /// Reallocate to the new size; contents become opaque black.
    pub fn resize(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        self.data.clear();
        self.data.shrink_to_fit();
        self.data.resize(w * h * 4, 0);
        for px in self.data.chunks_exact_mut(4) {
            px[3] = 255;
        }
    }

    pub fn width(&self) -> usize {
        self.w
    }
    pub fn height(&self) -> usize {
        self.h
    }

    /// Clip a run of `n` pixels starting at (x, y); returns (offset into data, count).
    fn clip_row(&self, x: usize, y: usize, n: usize) -> Option<(usize, usize)> {
        if y >= self.h || x >= self.w {
            return None;
        }
        let n = n.min(self.w - x);
        if n == 0 {
            return None;
        }
        Some(((y * self.w + x) * 4, n))
    }

    /// One row of wire pixels in our negotiated format (bytes B, G, R, X).
    pub fn put_bgrx_row(&mut self, x: usize, y: usize, src: &[u8]) {
        if let Some((off, n)) = self.clip_row(x, y, src.len() / 4) {
            let dst = &mut self.data[off..off + n * 4];
            for (d, s) in dst.chunks_exact_mut(4).zip(src.chunks_exact(4)) {
                d[0] = s[2];
                d[1] = s[1];
                d[2] = s[0];
                d[3] = 255;
            }
        }
    }

    /// One row of 3-byte R, G, B pixels (Tight TPIXEL / JPEG output).
    pub fn put_rgb_row(&mut self, x: usize, y: usize, src: &[u8]) {
        if let Some((off, n)) = self.clip_row(x, y, src.len() / 3) {
            let dst = &mut self.data[off..off + n * 4];
            for (d, s) in dst.chunks_exact_mut(4).zip(src.chunks_exact(3)) {
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = 255;
            }
        }
    }

    /// One row of RGBA pixels.
    pub fn put_rgba_row(&mut self, x: usize, y: usize, src: &[u8]) {
        if let Some((off, n)) = self.clip_row(x, y, src.len() / 4) {
            self.data[off..off + n * 4].copy_from_slice(&src[..n * 4]);
        }
    }

    pub fn fill(&mut self, x: usize, y: usize, w: usize, h: usize, c: Rgba) {
        for row in y..y.saturating_add(h).min(self.h) {
            if let Some((off, n)) = self.clip_row(x, row, w) {
                for d in self.data[off..off + n * 4].chunks_exact_mut(4) {
                    d.copy_from_slice(&c);
                }
            }
        }
    }

    /// CopyRect. Returns false (and does nothing) if either rectangle is not fully inside.
    pub fn copy_rect(&mut self, sx: usize, sy: usize, dx: usize, dy: usize, w: usize, h: usize) -> bool {
        if sx + w > self.w || dx + w > self.w || sy + h > self.h || dy + h > self.h {
            return false;
        }
        let n = w * 4;
        let stride = self.w * 4;
        let mut copy = |row: usize| {
            let s = (sy + row) * stride + sx * 4;
            let d = (dy + row) * stride + dx * 4;
            self.data.copy_within(s..s + n, d);
        };
        // Overlap-safe: row order depends on direction; copy_within handles overlap inside a row.
        if dy > sy {
            (0..h).rev().for_each(&mut copy);
        } else {
            (0..h).for_each(&mut copy);
        }
        true
    }

    /// Copy out a rectangle (must be inside the framebuffer) as tightly packed RGBA.
    pub fn extract(&self, x: usize, y: usize, w: usize, h: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(w * h * 4);
        for row in y..y + h {
            let off = (row * self.w + x) * 4;
            out.extend_from_slice(&self.data[off..off + w * 4]);
        }
        out
    }

    /// Intersect a rectangle with the framebuffer.
    pub fn clip(&self, x: usize, y: usize, w: usize, h: usize) -> Option<(usize, usize, usize, usize)> {
        if x >= self.w || y >= self.h {
            return None;
        }
        let w = w.min(self.w - x);
        let h = h.min(self.h - y);
        if w == 0 || h == 0 {
            None
        } else {
            Some((x, y, w, h))
        }
    }

    #[cfg(test)]
    pub fn pixel(&self, x: usize, y: usize) -> Rgba {
        let off = (y * self.w + x) * 4;
        [self.data[off], self.data[off + 1], self.data[off + 2], self.data[off + 3]]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipping_and_copy() {
        let mut fb = Framebuffer::new(4, 4);
        fb.fill(2, 2, 10, 10, [1, 2, 3, 255]);
        assert_eq!(fb.pixel(3, 3), [1, 2, 3, 255]);
        assert_eq!(fb.pixel(1, 1), [0, 0, 0, 255]);
        fb.put_bgrx_row(3, 0, &[10, 20, 30, 0, 40, 50, 60, 0]);
        assert_eq!(fb.pixel(3, 0), [30, 20, 10, 255]);
        fb.put_bgrx_row(0, 9, &[1, 1, 1, 1]);
        fb.put_rgb_row(9, 0, &[1, 1, 1]);
        // overlapping copy downwards
        let mut fb = Framebuffer::new(2, 4);
        for y in 0..4 {
            fb.fill(0, y, 2, 1, [y as u8, 0, 0, 255]);
        }
        assert!(fb.copy_rect(0, 0, 0, 1, 2, 3));
        assert_eq!((0..4).map(|y| fb.pixel(0, y)[0]).collect::<Vec<_>>(), vec![0, 0, 1, 2]);
        assert!(fb.copy_rect(0, 1, 0, 0, 2, 3));
        assert_eq!((0..4).map(|y| fb.pixel(1, y)[0]).collect::<Vec<_>>(), vec![0, 1, 2, 2]);
        assert!(!fb.copy_rect(0, 0, 1, 0, 2, 1));
        assert_eq!(fb.extract(0, 1, 2, 1), vec![1, 0, 0, 255, 1, 0, 0, 255]);
    }
}
