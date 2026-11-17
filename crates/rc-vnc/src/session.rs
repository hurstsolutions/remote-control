//! The running session: a reader that decodes server messages into the local framebuffer and
//! emits events, and a writer that turns front-end input into client messages.

use crate::decode::{self, encoding_name, Decoder};
use crate::error::{proto, Result, VncError};
use crate::fb::Framebuffer;
use crate::input::{self, lock, InputState, Screen, Shared, SharedRef};
use crate::proto as hs;
use crate::VncConfig;
use rc_types::{CursorShape, SessionEvent, SessionInput};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest Frame event, in pixels (2 MiB of RGBA). Bigger rectangles are sent as bands so a
/// full 5K update never needs one giant allocation.
const MAX_FRAME_PIXELS: usize = 512 * 1024;
const MAX_CUT_TEXT: u32 = 64 * 1024 * 1024;
const MAX_CURSOR_SIDE: usize = 2048;

/// Encodings advertised by default, in preference order.
pub(crate) fn default_encodings() -> Vec<i32> {
    let mut v = vec![
        decode::ENC_COPYRECT,
        decode::ENC_TIGHT,
        decode::ENC_ZRLE,
        decode::ENC_HEXTILE,
        decode::ENC_ZLIB,
        decode::ENC_RRE,
        decode::ENC_RAW,
        decode::ENC_JPEG_QUALITY_0 + 8,
    ];
    v.extend_from_slice(&DEFAULT_PSEUDO);
    v
}

const DEFAULT_PSEUDO: [i32; 4] =
    [decode::ENC_CURSOR, decode::ENC_DESKTOP_SIZE, decode::ENC_EXT_DESKTOP_SIZE, decode::ENC_LAST_RECT];

/// Parse an encoding override such as "zrle,hextile" or "raw nopseudo" (see `RC_VNC_ENCODINGS`
/// in the crate docs). Unknown tokens are reported in the second element.
pub(crate) fn parse_encodings(spec: &str) -> (Vec<i32>, Vec<String>) {
    let mut out = Vec::new();
    let mut unknown = Vec::new();
    let mut pseudo = true;
    for tok in spec.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        let enc = match tok.to_ascii_lowercase().as_str() {
            "raw" => decode::ENC_RAW,
            "copyrect" => decode::ENC_COPYRECT,
            "rre" => decode::ENC_RRE,
            "hextile" => decode::ENC_HEXTILE,
            "zlib" => decode::ENC_ZLIB,
            "tight" => decode::ENC_TIGHT,
            "zrle" => decode::ENC_ZRLE,
            "jpeg" => decode::ENC_JPEG_QUALITY_0 + 8,
            "nopseudo" => {
                pseudo = false;
                continue;
            }
            other => match other.parse::<i32>() {
                Ok(n) => n,
                Err(_) => {
                    unknown.push(tok.to_string());
                    continue;
                }
            },
        };
        if !out.contains(&enc) {
            out.push(enc);
        }
    }
    if pseudo {
        for p in DEFAULT_PSEUDO {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    (out, unknown)
}

pub(crate) fn encodings_from_env() -> Vec<i32> {
    match std::env::var("RC_VNC_ENCODINGS") {
        Ok(spec) if !spec.trim().is_empty() => {
            let (list, unknown) = parse_encodings(&spec);
            if !unknown.is_empty() {
                warn!(?unknown, "RC_VNC_ENCODINGS: ignoring unknown tokens");
            }
            info!(spec = %spec, "encoding list overridden by RC_VNC_ENCODINGS");
            list
        }
        _ => default_encodings(),
    }
}

async fn emit(events: &mpsc::Sender<SessionEvent>, ev: SessionEvent) -> Result<()> {
    events.send(ev).await.map_err(|_| VncError::Gone)
}

/// During the handshake the only input that matters is Close (or the front end going away).
async fn wait_for_close(input: &mut mpsc::UnboundedReceiver<SessionInput>) {
    loop {
        match input.recv().await {
            None | Some(SessionInput::Close) => return,
            Some(_) => trace!("input ignored during the handshake"),
        }
    }
}

/// Handshake then run until the session ends. `Ok(())` and the two quiet error variants mean a
/// clean close.
pub(crate) async fn session<S>(
    mut stream: S,
    config: &VncConfig,
    events: &mpsc::Sender<SessionEvent>,
    input: &mut mpsc::UnboundedReceiver<SessionInput>,
    stage: &mut &'static str,
    encodings: &[i32],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let init = {
        let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, hs::handshake(&mut stream, config, events, stage));
        tokio::select! {
            r = handshake => match r {
                Ok(r) => r?,
                Err(_) => {
                    return proto(format!(
                        "the server stopped responding (no handshake progress within {} s)",
                        HANDSHAKE_TIMEOUT.as_secs()
                    ))
                }
            },
            _ = wait_for_close(input) => return Err(VncError::UserClosed),
            _ = events.closed() => return Err(VncError::Gone),
        }
    };
    *stage = hs::STAGE_SESSION;

    let shared: SharedRef =
        Arc::new(Mutex::new(Shared { width: init.width, height: init.height, ..Default::default() }));

    let (rd, mut wr) = tokio::io::split(stream);

    let mut hello = Vec::new();
    input::set_pixel_format(&mut hello);
    input::set_encodings(&mut hello, encodings);
    input::update_request(&mut hello, false, init.width, init.height);
    info!(
        encodings = %encodings.iter().map(|e| format!("{e} ({})", encoding_name(*e))).collect::<Vec<_>>().join(", "),
        "sending SetPixelFormat (32bpp, depth 24, little-endian, R<<16 G<<8 B<<0), SetEncodings and the first update request"
    );
    wr.write_all(&hello).await?;
    wr.flush().await?;

    emit(events, SessionEvent::Connected { width: init.width, height: init.height, name: init.name }).await?;

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut reader = Reader {
        rd: BufReader::with_capacity(64 * 1024, rd),
        fb: Framebuffer::new(init.width as usize, init.height as usize),
        dec: Decoder::new(),
        seen: HashSet::new(),
        shared: shared.clone(),
        events,
        out: out_tx,
        warned_oob: false,
        updates: 0,
    };

    tokio::select! {
        r = reader.run() => r,
        r = writer(&mut wr, input, out_rx, &shared, config.view_only) => r,
        _ = events.closed() => Err(VncError::Gone),
    }
}

async fn writer<W: AsyncWrite + Unpin>(
    wr: &mut W,
    input: &mut mpsc::UnboundedReceiver<SessionInput>,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    shared: &SharedRef,
    view_only: bool,
) -> Result<()> {
    let mut state = InputState::new(view_only);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let mut close = false;
        tokio::select! {
            msg = out_rx.recv() => match msg {
                Some(bytes) => buf.extend_from_slice(&bytes),
                // The reader is gone; it reports the reason. Just stop writing.
                None => return std::future::pending::<Result<()>>().await,
            },
            item = input.recv() => match item {
                Some(first) => {
                    close = state.handle(first, shared, &mut buf);
                    // Batch whatever else is already queued into one write.
                    for _ in 0..256 {
                        if close {
                            break;
                        }
                        match input.try_recv() {
                            Ok(next) => close = state.handle(next, shared, &mut buf),
                            Err(_) => break,
                        }
                    }
                }
                None => close = true,
            },
        }
        if close {
            // Do not leave modifiers or buttons stuck on the remote side.
            state.release_all(&mut buf);
            if !buf.is_empty() {
                let _ = wr.write_all(&buf).await;
            }
            let _ = wr.shutdown().await;
            info!("closing the session at the front end's request");
            return Err(VncError::UserClosed);
        }
        if !buf.is_empty() {
            wr.write_all(&buf).await?;
            wr.flush().await?;
        }
    }
}

struct Reader<'a, R> {
    rd: BufReader<R>,
    fb: Framebuffer,
    dec: Decoder,
    /// Encodings / pseudo-encodings already logged.
    seen: HashSet<i32>,
    shared: SharedRef,
    events: &'a mpsc::Sender<SessionEvent>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    warned_oob: bool,
    updates: u64,
}

impl<R: AsyncRead + Unpin> Reader<'_, R> {
    async fn run(&mut self) -> Result<()> {
        loop {
            let msg = self.rd.read_u8().await?;
            match msg {
                0 => self.framebuffer_update().await?,
                1 => self.colour_map().await?,
                2 => {
                    debug!("bell");
                    emit(self.events, SessionEvent::Bell).await?;
                }
                3 => self.server_cut_text().await?,
                other => {
                    // The length of an unknown message is unknowable, so we cannot skip it.
                    warn!(message_type = other, "unexpected server message type; cannot continue");
                    return proto(format!("the server sent an unknown message type {other}"));
                }
            }
        }
    }

    fn request_update(&self, incremental: bool) {
        let (w, h) = {
            let s = lock(&self.shared);
            (s.width, s.height)
        };
        let mut buf = Vec::with_capacity(10);
        input::update_request(&mut buf, incremental, w, h);
        // If the writer is gone the session is ending anyway.
        let _ = self.out.send(buf);
    }

    /// Apply a new framebuffer size. Returns true if it actually changed.
    async fn resize(&mut self, w: u16, h: u16) -> Result<bool> {
        if (w as usize, h as usize) == (self.fb.width(), self.fb.height()) {
            return Ok(false);
        }
        info!(
            old_width = self.fb.width(),
            old_height = self.fb.height(),
            width = w,
            height = h,
            "remote desktop resized"
        );
        self.fb.resize(w as usize, h as usize);
        {
            let mut s = lock(&self.shared);
            s.width = w;
            s.height = h;
        }
        emit(self.events, SessionEvent::Resized { width: w, height: h }).await?;
        Ok(true)
    }

    /// Emit the (clipped) rectangle from the local framebuffer as one or more Frame events.
    async fn emit_rect(&mut self, x: usize, y: usize, w: usize, h: usize) -> Result<()> {
        let Some((x, y, w, h)) = self.fb.clip(x, y, w, h) else {
            return Ok(());
        };
        let band = (MAX_FRAME_PIXELS / w).max(1);
        let mut row = 0;
        while row < h {
            let n = band.min(h - row);
            let rgba = self.fb.extract(x, y + row, w, n);
            let ev = SessionEvent::Frame { x: x as u16, y: (y + row) as u16, w: w as u16, h: n as u16, rgba };
            emit(self.events, ev).await?;
            row += n;
        }
        Ok(())
    }

    async fn framebuffer_update(&mut self) -> Result<()> {
        let _padding = self.rd.read_u8().await?;
        let count = self.rd.read_u16().await?;
        let mut resized = false;
        let mut handled = 0u32;
        trace!(count, "FramebufferUpdate");
        for _ in 0..count {
            let x = self.rd.read_u16().await? as usize;
            let y = self.rd.read_u16().await? as usize;
            let w = self.rd.read_u16().await? as usize;
            let h = self.rd.read_u16().await? as usize;
            let enc = self.rd.read_i32().await?;
            if self.seen.insert(enc) {
                info!(encoding = enc, name = encoding_name(enc), x, y, w, h, "first rectangle with this encoding");
            }
            trace!(x, y, w, h, enc, "rectangle");
            handled += 1;
            match enc {
                decode::ENC_LAST_RECT => break,
                decode::ENC_DESKTOP_SIZE => resized |= self.resize(w as u16, h as u16).await?,
                decode::ENC_EXT_DESKTOP_SIZE => resized |= self.ext_desktop_size(x, y, w, h).await?,
                decode::ENC_CURSOR => self.cursor(x, y, w, h).await?,
                decode::ENC_COPYRECT => {
                    let sx = self.rd.read_u16().await? as usize;
                    let sy = self.rd.read_u16().await? as usize;
                    if self.fb.copy_rect(sx, sy, x, y, w, h) {
                        self.emit_rect(x, y, w, h).await?;
                    } else {
                        warn!(sx, sy, x, y, w, h, "CopyRect outside the framebuffer; ignored");
                    }
                }
                _ => {
                    if self.fb.clip(x, y, w, h) != Some((x, y, w, h)) && w > 0 && h > 0 && !self.warned_oob {
                        self.warned_oob = true;
                        warn!(
                            x, y, w, h,
                            fb_width = self.fb.width(),
                            fb_height = self.fb.height(),
                            "rectangle extends outside the framebuffer; clipping (further cases not logged)"
                        );
                    }
                    if !self.dec.decode(&mut self.rd, &mut self.fb, (x, y, w, h), enc).await? {
                        warn!(encoding = enc, x, y, w, h, "server used an encoding we did not advertise");
                        return proto(format!(
                            "the server sent a rectangle with unsupported encoding {enc} ({})",
                            encoding_name(enc)
                        ));
                    }
                    self.emit_rect(x, y, w, h).await?;
                }
            }
        }
        self.updates += 1;
        if self.updates == 1 {
            info!(rectangles = handled, "first framebuffer update received");
        }
        if handled == 0 {
            // An empty update: do not spin if the server answers every request immediately.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // After a resize our copy is blank, so ask for everything.
        self.request_update(!resized);
        Ok(())
    }

    async fn ext_desktop_size(&mut self, reason: usize, status: usize, w: usize, h: usize) -> Result<bool> {
        let n = self.rd.read_u8().await? as usize;
        let mut pad = [0u8; 3];
        self.rd.read_exact(&mut pad).await?;
        let mut screens = Vec::with_capacity(n);
        let mut b = [0u8; 16];
        for _ in 0..n {
            self.rd.read_exact(&mut b).await?;
            screens.push(Screen {
                id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                x: u16::from_be_bytes([b[4], b[5]]),
                y: u16::from_be_bytes([b[6], b[7]]),
                w: u16::from_be_bytes([b[8], b[9]]),
                h: u16::from_be_bytes([b[10], b[11]]),
                flags: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            });
        }
        debug!(reason, status, w, h, ?screens, "ExtendedDesktopSize");
        let first = {
            let mut s = lock(&self.shared);
            let first = !s.ext_desktop_size;
            s.ext_desktop_size = true;
            first
        };
        if first {
            info!("server supports ExtendedDesktopSize; remote resize (SetDesktopSize) is available");
        }
        if reason == 1 && status != 0 {
            let why = match status {
                1 => "resize is administratively prohibited",
                2 => "out of resources",
                3 => "invalid screen layout",
                _ => "unknown error",
            };
            warn!(status, why, "the server rejected our SetDesktopSize request");
            return Ok(false);
        }
        lock(&self.shared).screens = screens;
        self.resize(w as u16, h as u16).await
    }

    async fn cursor(&mut self, hot_x: usize, hot_y: usize, w: usize, h: usize) -> Result<()> {
        if w > MAX_CURSOR_SIDE || h > MAX_CURSOR_SIDE {
            return proto(format!("implausible cursor size {w}x{h}"));
        }
        let shape = if w == 0 || h == 0 {
            CursorShape::Hidden
        } else {
            let rgba = decode::read_cursor(&mut self.rd, w, h).await?;
            if rgba.chunks_exact(4).all(|p| p[3] == 0) {
                CursorShape::Hidden
            } else {
                CursorShape::Bitmap {
                    width: w as u16,
                    height: h as u16,
                    hot_x: hot_x.min(w - 1) as u16,
                    hot_y: hot_y.min(h - 1) as u16,
                    rgba,
                }
            }
        };
        emit(self.events, SessionEvent::Cursor(shape)).await
    }

    async fn colour_map(&mut self) -> Result<()> {
        // We always use true colour, so a colour map is meaningless; skip it.
        let mut head = [0u8; 5];
        self.rd.read_exact(&mut head).await?;
        let n = u16::from_be_bytes([head[3], head[4]]) as u64;
        warn!(entries = n, "ignoring SetColourMapEntries (true colour was requested)");
        let skipped = tokio::io::copy(&mut (&mut self.rd).take(n * 6), &mut tokio::io::sink()).await?;
        if skipped != n * 6 {
            return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(())
    }

    async fn server_cut_text(&mut self) -> Result<()> {
        let mut pad = [0u8; 3];
        self.rd.read_exact(&mut pad).await?;
        let len = self.rd.read_u32().await?;
        if len > MAX_CUT_TEXT {
            return proto(format!("implausible clipboard length {len}"));
        }
        let mut bytes = Vec::new();
        let got = (&mut self.rd).take(len as u64).read_to_end(&mut bytes).await?;
        if got != len as usize {
            return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        debug!(bytes = len, "clipboard text received from the server");
        // ServerCutText is Latin-1 by definition.
        let text: String = bytes.iter().map(|&b| b as char).collect();
        emit(self.events, SessionEvent::Clipboard(text)).await
    }
}
