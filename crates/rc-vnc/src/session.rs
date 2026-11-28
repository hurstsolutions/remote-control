//! The running session: a reader that decodes server messages into the local framebuffer and
//! emits events, and a writer that turns front-end input into client messages.

use crate::apple;
use crate::decode::{self, encoding_name, Decoder};
use crate::error::{proto, Result, VncError};
use crate::fb::Framebuffer;
use crate::input::{self, lock, InputState, Screen, Shared, SharedRef};
use crate::proto as hs;
use crate::record::RecordStream;
use crate::{VncConfig, VncOptions};
use rc_types::{CursorShape, SessionEvent, SessionInput};
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest Frame event, in pixels (2 MiB of RGBA). Bigger rectangles are sent as bands so a
/// full 5K update never needs one giant allocation.
const MAX_FRAME_PIXELS: usize = 512 * 1024;
/// Side of the blocks compared against what the window already shows. A Mac resends the whole
/// screen in every update; only blocks that changed are sent on to the window.
const DIFF_TILE: usize = 64;
/// Larger clipboard text from the server is dropped (read past, never buffered).
const MAX_CUT_TEXT: u32 = 1024 * 1024;
const MAX_CURSOR_SIDE: usize = 2048;
/// Largest compressed Apple cursor image we accept.
const MAX_CURSOR_IMAGE: u32 = 16 * 1024 * 1024;
/// Apple cursor shapes kept for re-selection.
const MAX_CURSOR_CACHE: usize = 256;

/// The session's byte stream: the socket as is, or inside Apple's encrypted record layer.
enum Transport<S> {
    Plain(S),
    Records(Box<RecordStream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Transport<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Records(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Transport<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Transport::Records(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => Pin::new(s).poll_flush(cx),
            Transport::Records(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Records(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

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
    options: &VncOptions,
    events: &mpsc::Sender<SessionEvent>,
    input: &mut mpsc::UnboundedReceiver<SessionInput>,
    stage: &mut &'static str,
    encodings: &[i32],
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let done = {
        let handshake =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, hs::handshake(&mut stream, config, options, events, stage));
        tokio::select! {
            r = handshake => match r {
                Ok(r) => r?,
                Err(_) if *stage == hs::STAGE_ENCRYPTION => {
                    return Err(VncError::Security(format!(
                        "the Mac did not send the encryption key within {} s of being asked for an encrypted session",
                        HANDSHAKE_TIMEOUT.as_secs()
                    )))
                }
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
    let init = done.init;
    let encrypted = done.keys.is_some();
    let stream = match done.keys {
        // The handshake read unbuffered, so the next byte on the socket starts the first record.
        Some(keys) => Transport::Records(Box::new(RecordStream::new(stream, keys))),
        None => Transport::Plain(stream),
    };
    let security = match (encrypted, done.server_verified) {
        (false, _) => crate::VncSecurity::Unencrypted,
        (true, false) => crate::VncSecurity::EncryptedUnverified,
        (true, true) => crate::VncSecurity::EncryptedVerified,
    };
    if !encrypted && options.encryption != crate::EncryptionPolicy::Off {
        warn!(policy = ?options.encryption, "the session is not encrypted by VNC (the server or sign-in did not allow it)");
    }

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

    let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut reader = Reader {
        rd: BufReader::with_capacity(64 * 1024, rd),
        fb: Framebuffer::try_new(init.width as usize, init.height as usize)?,
        dec: Decoder::new(),
        seen: HashSet::new(),
        shared: shared.clone(),
        events,
        out: out_tx,
        warned_oob: false,
        updates: 0,
        apple: done.apple,
        cursors: HashMap::new(),
        stats: Stats::new(),
        shown: Shown::new(init.width as usize, init.height as usize),
    };

    if encrypted {
        // Announce nothing until the Mac's first record has passed its integrity check: that
        // proves it holds the key the sign-in produced (an impostor could not wrap it). The
        // full update request above guarantees the Mac sends something.
        *stage = hs::STAGE_ENCRYPTION;
        debug!("encryption setup: waiting for the Mac's first encrypted message");
        let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.rd.fill_buf());
        tokio::select! {
            r = first => match r {
                Ok(Ok([])) => {
                    return Err(VncError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the Mac closed the connection before its first encrypted message",
                    )))
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    return Err(VncError::Security(format!(
                        "the Mac sent no encrypted message within {} s of the encryption setup",
                        HANDSHAKE_TIMEOUT.as_secs()
                    )))
                }
            },
            _ = wait_for_close(input) => return Err(VncError::UserClosed),
            _ = events.closed() => return Err(VncError::Gone),
        }
        debug!("encryption setup: the Mac's first encrypted message passed its integrity check");
        *stage = hs::STAGE_SESSION;
    }

    info!(?security, "{}", security.status_text());
    emit(events, security.to_event()).await?;
    emit(events, SessionEvent::Connected { width: init.width, height: init.height, name: init.name }).await?;

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
    /// Speaking Apple's 003.889: Apple messages and metadata encodings may appear.
    apple: bool,
    /// Apple cursor cache (encoding 0x450): id -> shape.
    cursors: HashMap<u32, CursorShape>,
    stats: Stats,
    shown: Shown,
}

/// A copy of what the window has been sent, to skip blocks a server resends unchanged.
struct Shown {
    w: usize,
    data: Vec<u8>,
}

impl Shown {
    /// Alpha 0 never occurs in the framebuffer (always opaque), so every block counts as changed
    /// until it has been sent once.
    fn new(w: usize, h: usize) -> Self {
        Shown { w, data: vec![0; w * h * 4] }
    }

    /// Compare a block (inside the framebuffer) with what was sent; if it differs, record the
    /// new contents and return true.
    fn update(&mut self, fb: &Framebuffer, x: usize, y: usize, w: usize, h: usize) -> bool {
        let mut changed = false;
        for row in y..y + h {
            let off = (row * self.w + x) * 4;
            let src = fb.row(x, row, w);
            let dst = &mut self.data[off..off + w * 4];
            if changed {
                dst.copy_from_slice(src);
            } else if dst != src {
                dst.copy_from_slice(src);
                changed = true;
            }
        }
        changed
    }
}

/// Throughput counters, logged every `STATS_EVERY` so a laggy session's log shows whether time
/// goes to waiting for the server (network or the server itself) or to our decoding.
struct Stats {
    since: Instant,
    updates: u64,
    rects: u64,
    pixels: u64,
    /// Pixels actually sent to the window after skipping unchanged blocks.
    sent_pixels: u64,
    busy: Duration,
    /// Part of `busy` spent handing frames to the window.
    emit: Duration,
}

const STATS_EVERY: Duration = Duration::from_secs(10);

impl Stats {
    fn new() -> Self {
        Stats {
            since: Instant::now(),
            updates: 0,
            rects: 0,
            pixels: 0,
            sent_pixels: 0,
            busy: Duration::ZERO,
            emit: Duration::ZERO,
        }
    }

    fn record(&mut self, rects: u32, pixels: u64, busy: Duration, width: usize, height: usize) {
        self.updates += 1;
        self.rects += rects as u64;
        self.pixels += pixels;
        self.busy += busy;
        let elapsed = self.since.elapsed();
        if elapsed >= STATS_EVERY {
            let secs = elapsed.as_secs_f64();
            debug!(
                updates_per_s = format!("{:.1}", self.updates as f64 / secs),
                rects_per_update = format!("{:.1}", self.rects as f64 / self.updates.max(1) as f64),
                megapixels_per_s = format!("{:.2}", self.pixels as f64 / secs / 1e6),
                sent_megapixels_per_s = format!("{:.2}", self.sent_pixels as f64 / secs / 1e6),
                busy_pct = format!("{:.0}", 100.0 * self.busy.as_secs_f64() / secs),
                handing_to_window_pct = format!("{:.0}", 100.0 * self.emit.as_secs_f64() / secs),
                width,
                height,
                "VNC throughput"
            );
            *self = Stats::new();
        }
    }
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
                apple::MSG_MISC_STATUS if self.apple => apple::skip_misc_status(&mut self.rd).await?,
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
        self.fb.resize(w as usize, h as usize)?;
        self.shown = Shown::new(w as usize, h as usize);
        {
            let mut s = lock(&self.shared);
            s.width = w;
            s.height = h;
        }
        emit(self.events, SessionEvent::Resized { width: w, height: h }).await?;
        Ok(true)
    }

    /// Emit the parts of the (clipped) rectangle that differ from what the window already shows,
    /// as horizontal runs of changed blocks on a fixed grid.
    async fn emit_rect(&mut self, x: usize, y: usize, w: usize, h: usize) -> Result<()> {
        let Some((x, y, w, h)) = self.fb.clip(x, y, w, h) else {
            return Ok(());
        };
        let (x_end, y_end) = (x + w, y + h);
        let mut ty = y - y % DIFF_TILE;
        while ty < y_end {
            let (y0, y1) = (ty.max(y), (ty + DIFF_TILE).min(y_end));
            let mut run: Option<usize> = None;
            let mut tx = x - x % DIFF_TILE;
            while tx < x_end {
                let (x0, x1) = (tx.max(x), (tx + DIFF_TILE).min(x_end));
                if self.shown.update(&self.fb, x0, y0, x1 - x0, y1 - y0) {
                    run.get_or_insert(x0);
                } else if let Some(start) = run.take() {
                    self.emit_band(start, y0, x0 - start, y1 - y0).await?;
                }
                tx += DIFF_TILE;
            }
            if let Some(start) = run {
                self.emit_band(start, y0, x_end - start, y1 - y0).await?;
            }
            ty += DIFF_TILE;
        }
        Ok(())
    }

    /// Emit a rectangle (inside the framebuffer) as one or more Frame events.
    async fn emit_band(&mut self, x: usize, y: usize, w: usize, h: usize) -> Result<()> {
        let started = Instant::now();
        let band = (MAX_FRAME_PIXELS / w).max(1);
        let mut row = 0;
        while row < h {
            let n = band.min(h - row);
            let rgba = self.fb.extract(x, y + row, w, n);
            let ev = SessionEvent::Frame { x: x as u16, y: (y + row) as u16, w: w as u16, h: n as u16, rgba };
            emit(self.events, ev).await?;
            row += n;
        }
        self.stats.sent_pixels += (w * h) as u64;
        self.stats.emit += started.elapsed();
        Ok(())
    }

    async fn framebuffer_update(&mut self) -> Result<()> {
        let _padding = self.rd.read_u8().await?;
        let count = self.rd.read_u16().await?;
        let started = Instant::now();
        // Ask for the next update now, before decoding this one, so the server prepares it while
        // we decode instead of waiting a full round trip per frame. An empty update is answered
        // after a short pause instead, so a server that replies to every request at once does not
        // make us spin.
        let pipelined = count > 0;
        if pipelined {
            self.request_update(true);
        }
        let mut pixels = 0u64;
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
            pixels += (w * h) as u64;
            match enc {
                decode::ENC_LAST_RECT => break,
                decode::ENC_DESKTOP_SIZE => resized |= self.resize(w as u16, h as u16).await?,
                decode::ENC_EXT_DESKTOP_SIZE => resized |= self.ext_desktop_size(x, y, w, h).await?,
                decode::ENC_CURSOR => self.cursor(x, y, w, h).await?,
                apple::ENC_REKEY if self.apple => {
                    // We never ask for a second rekey, and the Mac switches both of its ciphers the
                    // moment it sends one, so records already framed under the old key would fail.
                    warn!("the Mac sent a second encryption key mid-session; closing");
                    return Err(VncError::Security(
                        "the Mac changed the encryption key mid-session, which this client never asks for; the \
                         session was closed"
                            .into(),
                    ));
                }
                apple::ENC_CURSOR_IMAGE if self.apple => self.apple_cursor(x, y, w, h).await?,
                apple::ENC_CURSOR_POS
                | apple::ENC_DISPLAY_INFO
                | apple::ENC_DISPLAY_LAYOUT
                | apple::ENC_VENDOR_KEYSYMS
                | apple::ENC_KEYBOARD_SOURCE
                | apple::ENC_DEVICE_INFO
                | apple::ENC_MEDIA_STREAM
                    if self.apple =>
                {
                    apple::skip_metadata(&mut self.rd, enc).await?;
                    trace!(encoding = enc, "Apple metadata rectangle skipped");
                }
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
        self.stats.record(handled, pixels, started.elapsed(), self.fb.width(), self.fb.height());
        if resized {
            // After a resize our copy is blank, so ask for everything.
            self.request_update(false);
        } else if !pipelined {
            // An empty update: do not spin if the server answers every request immediately.
            tokio::time::sleep(Duration::from_millis(20)).await;
            self.request_update(true);
        }
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

    /// Apple's cursor cache (0x450): `u32 id, u32 compressed_len`, then (when the length is not
    /// zero) a zlib stream of `w*h` BGRX pixels followed by a separate `w*h` alpha plane, which
    /// is stored under the id. A zero length selects a stored shape.
    async fn apple_cursor(&mut self, hot_x: usize, hot_y: usize, w: usize, h: usize) -> Result<()> {
        let id = self.rd.read_u32().await?;
        let len = self.rd.read_u32().await?;
        if len == 0 {
            match self.cursors.get(&id) {
                Some(shape) => return emit(self.events, SessionEvent::Cursor(shape.clone())).await,
                None => {
                    debug!(id, "Apple cursor: select for an unknown id; keeping the current cursor");
                    return Ok(());
                }
            }
        }
        if len > MAX_CURSOR_IMAGE || w == 0 || h == 0 || w > MAX_CURSOR_SIDE || h > MAX_CURSOR_SIDE {
            return proto(format!("implausible Apple cursor image: {w}x{h}, {len} compressed bytes"));
        }
        let mut deflated = Vec::new();
        let got = (&mut self.rd).take(len as u64).read_to_end(&mut deflated).await?;
        if got != len as usize {
            return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        let pixels = w * h;
        let mut raw = vec![0u8; pixels * 5];
        let mut z = flate2::Decompress::new(true);
        let ok = z.decompress(&deflated, &mut raw, flate2::FlushDecompress::Sync).is_ok() && z.total_out() as usize == raw.len();
        if !ok {
            // Each shape is its own zlib stream, so a bad one can be dropped on its own.
            warn!(id, w, h, "Apple cursor: could not inflate the image; ignored");
            return Ok(());
        }
        let (bgrx, alpha) = raw.split_at(pixels * 4);
        let mut rgba = Vec::with_capacity(pixels * 4);
        for (p, &a) in bgrx.chunks_exact(4).zip(alpha) {
            rgba.extend_from_slice(&[p[2], p[1], p[0], a]);
        }
        let shape = CursorShape::Bitmap {
            width: w as u16,
            height: h as u16,
            hot_x: hot_x.min(w - 1) as u16,
            hot_y: hot_y.min(h - 1) as u16,
            rgba,
        };
        if self.cursors.len() >= MAX_CURSOR_CACHE {
            self.cursors.clear();
        }
        self.cursors.insert(id, shape.clone());
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
            let skipped = tokio::io::copy(&mut (&mut self.rd).take(len as u64), &mut tokio::io::sink()).await?;
            if skipped != len as u64 {
                return Err(VncError::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            warn!(bytes = len, limit = MAX_CUT_TEXT, "clipboard text from the server is too large; dropped");
            return Ok(());
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
