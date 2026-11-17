//! Persistent zlib streams. RFB keeps one inflate stream alive for the whole connection per
//! encoding (four for Tight), so every compressed block must be fed to it completely.

use crate::error::{proto, Result, VncError};
use flate2::{Decompress, FlushDecompress};

const BUF: usize = 32 * 1024;

pub(crate) struct ZStream {
    d: Decompress,
    buf: Vec<u8>,
}

impl ZStream {
    pub fn new() -> Self {
        ZStream { d: Decompress::new(true), buf: vec![0; BUF] }
    }

    pub fn reset(&mut self) {
        self.d = Decompress::new(true);
    }

    /// Start inflating one compressed block.
    pub fn reader<'a>(&'a mut self, input: &'a [u8]) -> ZReader<'a> {
        ZReader { d: &mut self.d, buf: &mut self.buf, input, pos: 0, len: 0 }
    }
}

/// A source of decoded bytes: either an inflating stream or a plain slice.
pub(crate) trait ByteSrc {
    fn read_exact(&mut self, out: &mut [u8]) -> Result<()>;

    fn u8(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }
}

impl ByteSrc for &[u8] {
    fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
        if self.len() < out.len() {
            return proto("pixel data shorter than the rectangle requires");
        }
        let (a, b) = self.split_at(out.len());
        out.copy_from_slice(a);
        *self = b;
        Ok(())
    }
}

pub(crate) struct ZReader<'a> {
    d: &'a mut Decompress,
    buf: &'a mut Vec<u8>,
    input: &'a [u8],
    pos: usize,
    len: usize,
}

impl ZReader<'_> {
    /// Run inflate once into `out`; returns bytes produced.
    fn inflate_into(d: &mut Decompress, input: &mut &[u8], out: &mut [u8]) -> Result<usize> {
        loop {
            let (in0, out0) = (d.total_in(), d.total_out());
            d.decompress(input, out, FlushDecompress::None)
                .map_err(|e| VncError::Protocol(format!("zlib inflate failed: {e}")))?;
            let used = (d.total_in() - in0) as usize;
            let made = (d.total_out() - out0) as usize;
            *input = &input[used..];
            if made > 0 {
                return Ok(made);
            }
            if used == 0 {
                return proto("zlib data ended before the rectangle was complete");
            }
        }
    }

    /// Feed any remaining compressed bytes through the stream (keeping its state in sync) and
    /// make sure nothing unexpected is left over.
    pub fn finish(mut self) -> Result<()> {
        if self.pos < self.len {
            tracing::debug!(extra = self.len - self.pos, "zlib block produced more data than the rectangle needed");
        }
        while !self.input.is_empty() {
            let (in0, out0) = (self.d.total_in(), self.d.total_out());
            self.d
                .decompress(self.input, self.buf, FlushDecompress::None)
                .map_err(|e| VncError::Protocol(format!("zlib inflate failed: {e}")))?;
            let used = (self.d.total_in() - in0) as usize;
            let made = (self.d.total_out() - out0) as usize;
            self.input = &self.input[used..];
            if used == 0 && made == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl ByteSrc for ZReader<'_> {
    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            if self.pos < self.len {
                let n = (self.len - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                out = &mut out[n..];
            } else if out.len() >= BUF {
                // Large read: inflate straight into the destination.
                let n = Self::inflate_into(self.d, &mut self.input, out)?;
                out = &mut out[n..];
            } else {
                self.len = Self::inflate_into(self.d, &mut self.input, self.buf)?;
                self.pos = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    /// A persistent deflate stream that sync-flushes each block, like a VNC server.
    pub(crate) struct TestDeflater(Compress);
    impl TestDeflater {
        pub fn new() -> Self {
            TestDeflater(Compress::new(Compression::default(), true))
        }
        pub fn block(&mut self, data: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 256);
            let before = self.0.total_in();
            self.0.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
            assert_eq!((self.0.total_in() - before) as usize, data.len());
            out
        }
    }

    #[test]
    fn stream_persists_across_blocks() {
        let mut def = TestDeflater::new();
        let mut z = ZStream::new();
        let a: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let b = b"second block reuses the dictionary".to_vec();
        for data in [&a, &b, &a] {
            let comp = def.block(data);
            let mut r = z.reader(&comp);
            let mut out = vec![0u8; data.len()];
            // mix of small and large reads
            let (head, tail) = out.split_at_mut(data.len().min(7));
            r.read_exact(head).unwrap();
            r.read_exact(tail).unwrap();
            r.finish().unwrap();
            assert_eq!(&out, data);
        }
    }

    #[test]
    fn truncated_block_is_an_error() {
        let mut def = TestDeflater::new();
        let mut z = ZStream::new();
        let comp = def.block(&[7u8; 1000]);
        let mut r = z.reader(&comp);
        let mut out = vec![0u8; 2000];
        assert!(r.read_exact(&mut out).is_err());
    }
}
