//! Connect to a VNC server, wait for a complete first frame, and run a small script of actions.
//!
//! ```text
//! cargo run -p rc-vnc --example vnc_shot -- HOST[:PORT] [--user U] [--password P] [--view-only]
//!     [--encodings zrle,hextile] ACTION...
//!
//! ACTIONS (run in order; the first one waits for the first complete frame):
//!   shot:PATH.png     write the current framebuffer as a PNG
//!   type:TEXT         type text (key down/up per character)
//!   key:NAME          press and release a named key (Enter, Tab, ArrowUp, F5 ...)
//!   click:X,Y         left click         rclick:X,Y   right click
//!   move:X,Y          move the pointer   wheel:DY     scroll by DY notches (may be fractional)
//!   clip:TEXT         send clipboard text to the server
//!   resize:WxH        ask the server to resize the desktop
//!   refresh           request a full update
//!   sleep:MS          keep processing events for MS milliseconds
//! ```
//! Events other than frames are printed to stdout as they arrive. Set `RUST_LOG=debug` for the
//! protocol log (stderr).

#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use rc_types::{session_channels, MouseButton, SessionEvent, SessionInput};
use rc_vnc::VncConfig;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Screen {
    w: usize,
    h: usize,
    rgba: Vec<u8>,
    covered: Vec<bool>,
    covered_count: usize,
    connected: bool,
    frames: u64,
    frame_bytes: u64,
    closed: Option<String>,
}

impl Screen {
    fn reset(&mut self, w: usize, h: usize) {
        self.w = w;
        self.h = h;
        self.rgba = vec![0; w * h * 4];
        self.covered = vec![false; w * h];
        self.covered_count = 0;
    }
    fn complete(&self) -> bool {
        self.connected && self.w * self.h > 0 && self.covered_count == self.w * self.h
    }
    fn blit(&mut self, x: usize, y: usize, w: usize, h: usize, rgba: &[u8]) {
        assert_eq!(rgba.len(), w * h * 4, "Frame has the wrong buffer size");
        assert!(x + w <= self.w && y + h <= self.h, "Frame outside the framebuffer");
        for row in 0..h {
            let dst = ((y + row) * self.w + x) * 4;
            self.rgba[dst..dst + w * 4].copy_from_slice(&rgba[row * w * 4..(row + 1) * w * 4]);
            for c in &mut self.covered[(y + row) * self.w + x..(y + row) * self.w + x + w] {
                if !*c {
                    *c = true;
                    self.covered_count += 1;
                }
            }
        }
        self.frames += 1;
        self.frame_bytes += rgba.len() as u64;
    }
}

fn write_png(path: &str, s: &Screen) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut enc = png::Encoder::new(file, s.w as u32, s.h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header()?;
    writer.write_image_data(&s.rgba)?;
    Ok(())
}

fn xy(s: &str) -> (u16, u16) {
    let (a, b) = s.split_once([',', 'x']).expect("expected X,Y");
    (a.parse().expect("number"), b.parse().expect("number"))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();

    let mut args = std::env::args().skip(1);
    let mut target = None;
    let mut config = VncConfig::default();
    let mut actions = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--user" => config.username = args.next(),
            "--password" => config.password = args.next().map(Into::into),
            "--view-only" => config.view_only = true,
            "--encodings" => std::env::set_var("RC_VNC_ENCODINGS", args.next().expect("--encodings LIST")),
            _ if target.is_none() => target = Some(a),
            _ => actions.push(a),
        }
    }
    let target = target.expect("usage: vnc_shot HOST[:PORT] [options] ACTION...");
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().expect("port")),
        None => (target, 5900),
    };

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let code = rt.block_on(async_main(host, port, config, actions));
    std::process::exit(code);
}

async fn async_main(host: String, port: u16, config: VncConfig, actions: Vec<String>) -> i32 {
    let (io, mut handle) = session_channels();
    let session = tokio::spawn(async move { rc_vnc::connect_and_run(&host, port, config, io).await });

    let screen = Arc::new(Mutex::new(Screen::default()));
    let pump = {
        let screen = screen.clone();
        tokio::spawn(async move {
            while let Some(ev) = handle.events.recv().await {
                let mut s = screen.lock().unwrap();
                match ev {
                    SessionEvent::Status(m) => println!("status: {m}"),
                    SessionEvent::ServerIdentity { sha256 } => println!("server identity: {sha256}"),
                    SessionEvent::Security { encrypted, server_verified, method } => {
                        println!("security: {method} (encrypted: {encrypted}, server verified: {server_verified})")
                    }
                    SessionEvent::Connected { width, height, name } => {
                        println!("connected: {width}x{height} {name:?}");
                        s.reset(width as usize, height as usize);
                        s.connected = true;
                    }
                    SessionEvent::Resized { width, height } => {
                        println!("resized: {width}x{height}");
                        s.reset(width as usize, height as usize);
                    }
                    SessionEvent::Frame { x, y, w, h, rgba } => {
                        s.blit(x as usize, y as usize, w as usize, h as usize, &rgba)
                    }
                    SessionEvent::Cursor(c) => match c {
                        rc_types::CursorShape::Bitmap { width, height, hot_x, hot_y, .. } => {
                            println!("cursor: {width}x{height} hotspot {hot_x},{hot_y}")
                        }
                        other => println!("cursor: {other:?}"),
                    },
                    SessionEvent::Clipboard(t) => println!("clipboard: {t:?}"),
                    SessionEvent::Bell => println!("bell"),
                    SessionEvent::Closed { error } => {
                        let msg = match error {
                            None => "clean".to_string(),
                            Some(e) => format!("{:?}: {}", e.kind, e.detail),
                        };
                        println!("closed: {msg}");
                        s.closed = Some(msg);
                    }
                }
            }
        })
    };
    let send = |i: SessionInput| {
        let _ = handle.input.send(i);
    };

    // Wait for the first complete frame (or the session ending).
    let start = Instant::now();
    loop {
        {
            let s = screen.lock().unwrap();
            if s.closed.is_some() {
                return 1;
            }
            if s.complete() {
                println!(
                    "first complete frame after {:?}: {} Frame events, {} bytes",
                    start.elapsed(),
                    s.frames,
                    s.frame_bytes
                );
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            eprintln!("timed out waiting for a complete frame");
            return 2;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let pause = || tokio::time::sleep(Duration::from_millis(30));
    for action in actions {
        let (verb, arg) = action.split_once(':').unwrap_or((action.as_str(), ""));
        match verb {
            "shot" => {
                // Give in-flight updates a moment, and wait out a resize in progress.
                for _ in 0..100 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if screen.lock().unwrap().complete() {
                        break;
                    }
                }
                let s = screen.lock().unwrap();
                match write_png(arg, &s) {
                    Ok(()) => println!("wrote {arg} ({}x{}, complete={})", s.w, s.h, s.complete()),
                    Err(e) => {
                        eprintln!("could not write {arg}: {e}");
                        return 3;
                    }
                }
            }
            "type" => {
                for c in arg.chars() {
                    let key = c.to_string();
                    send(SessionInput::Key { code: String::new(), key: key.clone(), down: true });
                    send(SessionInput::Key { code: String::new(), key, down: false });
                    pause().await;
                }
            }
            "key" => {
                send(SessionInput::Key { code: arg.to_string(), key: arg.to_string(), down: true });
                send(SessionInput::Key { code: arg.to_string(), key: arg.to_string(), down: false });
                pause().await;
            }
            "click" | "rclick" => {
                let (x, y) = xy(arg);
                let button = if verb == "click" { MouseButton::Left } else { MouseButton::Right };
                send(SessionInput::PointerMove { x, y });
                pause().await;
                send(SessionInput::PointerButton { button, down: true, x, y });
                pause().await;
                send(SessionInput::PointerButton { button, down: false, x, y });
                pause().await;
            }
            "move" => {
                let (x, y) = xy(arg);
                send(SessionInput::PointerMove { x, y });
            }
            "wheel" => {
                let s = screen.lock().unwrap();
                let (x, y) = ((s.w / 2) as u16, (s.h / 2) as u16);
                drop(s);
                send(SessionInput::Wheel { dx: 0.0, dy: arg.parse().expect("wheel:DY"), x, y });
            }
            "clip" => send(SessionInput::Clipboard { text: arg.to_string() }),
            "resize" => {
                let (width, height) = xy(arg);
                send(SessionInput::Resize { width, height });
            }
            "refresh" => send(SessionInput::Refresh),
            "sleep" => tokio::time::sleep(Duration::from_millis(arg.parse().expect("sleep:MS"))).await,
            other => {
                eprintln!("unknown action {other:?}");
                return 4;
            }
        }
        if let Some(why) = &screen.lock().unwrap().closed {
            eprintln!("session ended early: {why}");
            return 1;
        }
    }

    send(SessionInput::Close);
    let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
    let s = screen.lock().unwrap();
    println!("done: {} Frame events, {} bytes of pixels", s.frames, s.frame_bytes);
    0
}
