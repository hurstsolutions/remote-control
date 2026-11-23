//! Headless test client: connect, optionally send input, save a screenshot, print a verbose log.
//!
//! The password is read from the RC_PASSWORD environment variable so it never appears in shell
//! history or process listings.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context as _};
use clap::{Parser, Subcommand};
use rc_types::{session_channels, MouseButton, SessionEvent, SessionHandle, SessionInput};

#[derive(Parser)]
#[command(name = "rc", about = "RemoteControl headless test client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser)]
struct Common {
    /// Host name or IP address.
    host: String,
    #[arg(short, long, default_value = "")]
    user: String,
    /// Password (prefer the RC_PASSWORD environment variable).
    #[arg(long, env = "RC_PASSWORD", hide_env_values = true, default_value = "")]
    password: String,
    /// Save a PNG screenshot here once the screen has settled.
    #[arg(long)]
    screenshot: Option<PathBuf>,
    /// Seconds to let the screen settle before acting.
    #[arg(long, default_value_t = 4.0)]
    settle: f32,
    /// Type this text after connecting ("\n" = Enter).
    #[arg(long)]
    r#type: Option<String>,
    /// Click the left button at X,Y before typing.
    #[arg(long, value_parser = parse_point)]
    click: Option<(u16, u16)>,
    /// Put this text on the remote clipboard.
    #[arg(long)]
    set_clipboard: Option<String>,
    /// Ask the server to resize the desktop to WxH after connecting.
    #[arg(long, value_parser = parse_size)]
    resize: Option<(u16, u16)>,
}

#[derive(Subcommand)]
enum Command {
    /// Windows Remote Desktop.
    Rdp {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 3389)]
        port: u16,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long, value_parser = parse_size, default_value = "1280x800")]
        size: (u16, u16),
        /// Disable Network Level Authentication (needed for xrdp).
        #[arg(long)]
        no_nla: bool,
        /// Expected certificate SHA-256 (hex).
        #[arg(long)]
        pin: Option<String>,
    },
    /// Mac Screen Sharing (VNC), through an SSH tunnel unless --no-ssh is given.
    Vnc {
        #[command(flatten)]
        common: Common,
        /// Screen Sharing port on the Mac.
        #[arg(long, default_value_t = 5900)]
        port: u16,
        /// Connect straight to the VNC port without an SSH tunnel. Encryption then comes from Apple
        /// Screen Sharing itself (see --encryption).
        #[arg(long)]
        no_ssh: bool,
        /// VNC-level encryption: required, preferred or off. Default: required with --no-ssh
        /// (use off for non-Mac VNC servers on a trusted LAN), off through the SSH tunnel.
        #[arg(long, value_parser = parse_encryption)]
        encryption: Option<rc_vnc::EncryptionPolicy>,
        /// Do not sign in with SRP (type 36); use type 30 for encrypted sessions.
        #[arg(long)]
        no_srp: bool,
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// Expected SSH host key SHA-256 (hex).
        #[arg(long)]
        pin: Option<String>,
    },
}

fn parse_encryption(s: &str) -> Result<rc_vnc::EncryptionPolicy, String> {
    match s.to_ascii_lowercase().as_str() {
        "required" => Ok(rc_vnc::EncryptionPolicy::Required),
        "preferred" => Ok(rc_vnc::EncryptionPolicy::Preferred),
        "off" => Ok(rc_vnc::EncryptionPolicy::Off),
        _ => Err("expected required, preferred or off".into()),
    }
}

fn parse_size(s: &str) -> Result<(u16, u16), String> {
    let (w, h) = s.split_once(['x', 'X']).ok_or("expected WxH")?;
    Ok((w.parse().map_err(|_| "bad width")?, h.parse().map_err(|_| "bad height")?))
}

fn parse_point(s: &str) -> Result<(u16, u16), String> {
    let (x, y) = s.split_once(',').ok_or("expected X,Y")?;
    Ok((x.parse().map_err(|_| "bad x")?, y.parse().map_err(|_| "bad y")?))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RC_LOG").unwrap_or_else(|_| "info,rc_rdp=debug,rc_vnc=debug".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let (io, handle) = session_channels();
    let common = match cli.command {
        Command::Rdp { common, port, domain, size, no_nla, pin } => {
            let config = rc_rdp::RdpConfig {
                host: common.host.clone(),
                port,
                username: common.user.clone(),
                password: common.password.clone().into(),
                domain,
                width: size.0,
                height: size.1,
                scale_factor: 100,
                pinned_cert_sha256: pin,
                nla: !no_nla,
                clipboard: true,
            };
            rc_rdp::spawn(config, io)?;
            common
        }
        Command::Vnc { common, port, no_ssh, ssh_port, pin, encryption, no_srp } => {
            let config = rc_vnc::VncConfig {
                username: Some(common.user.clone()).filter(|u| !u.is_empty()),
                password: Some(common.password.clone()).filter(|p| !p.is_empty()),
                shared: true,
                view_only: false,
            };
            let default_policy =
                if no_ssh { rc_vnc::EncryptionPolicy::Required } else { rc_vnc::EncryptionPolicy::Off };
            let options =
                rc_vnc::VncOptions::default().with_encryption(encryption.unwrap_or(default_policy)).with_srp(!no_srp);
            if no_ssh {
                let host = common.host.clone();
                tokio::spawn(
                    async move { rc_vnc::connect_and_run_with_options(&host, port, config, options, io).await },
                );
            } else {
                let tunnel = rc_tunnel::open(rc_tunnel::TunnelConfig {
                    ssh_host: common.host.clone(),
                    ssh_port,
                    username: common.user.clone(),
                    password: common.password.clone().into(),
                    target_host: "127.0.0.1".to_owned(),
                    target_port: port,
                    pinned_host_key_sha256: pin,
                })
                .await;
                match tunnel {
                    Ok(tunnel) => {
                        println!("ssh host key sha256: {}", tunnel.host_key_sha256);
                        tokio::spawn(async move {
                            let guard = tunnel.guard;
                            rc_vnc::run_with_options(tunnel.stream, config, options, io).await;
                            guard.close().await;
                        });
                    }
                    Err(error) => bail!("tunnel failed [{:?}]: {}", error.kind, error.detail),
                }
            }
            common
        }
    };
    drive(common, handle).await
}

/// A local copy of the remote screen, built from Frame events.
struct Screen {
    width: u16,
    height: u16,
    rgba: Vec<u8>,
    frames: u64,
}

impl Screen {
    fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.rgba = vec![0; usize::from(width) * usize::from(height) * 4];
    }

    fn blit(&mut self, x: u16, y: u16, w: u16, h: u16, rgba: &[u8]) {
        self.frames += 1;
        let (x, y, w, h) = (usize::from(x), usize::from(y), usize::from(w), usize::from(h));
        let sw = usize::from(self.width);
        if x + w > sw || y + h > usize::from(self.height) || rgba.len() < w * h * 4 {
            tracing::warn!(x, y, w, h, "frame outside the screen; ignored");
            return;
        }
        for row in 0..h {
            let dst = ((y + row) * sw + x) * 4;
            self.rgba[dst..dst + w * 4].copy_from_slice(&rgba[row * w * 4..(row + 1) * w * 4]);
        }
    }

    fn save(&self, path: &PathBuf) -> anyhow::Result<()> {
        let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
        let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), u32::from(self.width), u32::from(self.height));
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header()?.write_image_data(&self.rgba)?;
        Ok(())
    }
}

/// Apply events for `duration`. Returns false when the session closed.
async fn pump(handle: &mut SessionHandle, screen: &mut Screen, duration: Duration) -> anyhow::Result<bool> {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        let event = match tokio::time::timeout_at(deadline, handle.events.recv()).await {
            Err(_) => return Ok(true),
            Ok(None) => return Ok(false),
            Ok(Some(event)) => event,
        };
        match event {
            SessionEvent::Status(text) => println!("status: {text}"),
            SessionEvent::ServerIdentity { sha256 } => println!("server identity sha256: {sha256}"),
            SessionEvent::Connected { width, height, name } => {
                println!("connected: {name} {width}x{height}");
                screen.resize(width, height);
            }
            SessionEvent::Resized { width, height } => {
                println!("resized: {width}x{height}");
                screen.resize(width, height);
            }
            SessionEvent::Frame { x, y, w, h, rgba } => screen.blit(x, y, w, h, &rgba),
            SessionEvent::Cursor(_) => {}
            SessionEvent::Clipboard(text) => println!("remote clipboard: {text:?}"),
            SessionEvent::Bell => println!("bell"),
            SessionEvent::Closed { error: None } => {
                println!("closed cleanly");
                return Ok(false);
            }
            SessionEvent::Closed { error: Some(error) } => bail!("session failed [{:?}]: {}", error.kind, error.detail),
        }
    }
}

/// Map a character to the US-layout physical key that types it.
fn key_for(ch: char) -> Option<(&'static str, bool)> {
    const PLAIN: &str = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./ \n\t";
    const SHIFT: &str = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?";
    const CODES: [&str; 50] = [
        "Backquote", "Digit1", "Digit2", "Digit3", "Digit4", "Digit5", "Digit6", "Digit7", "Digit8", "Digit9",
        "Digit0", "Minus", "Equal", "KeyQ", "KeyW", "KeyE", "KeyR", "KeyT", "KeyY", "KeyU", "KeyI", "KeyO", "KeyP",
        "BracketLeft", "BracketRight", "Backslash", "KeyA", "KeyS", "KeyD", "KeyF", "KeyG", "KeyH", "KeyJ", "KeyK",
        "KeyL", "Semicolon", "Quote", "KeyZ", "KeyX", "KeyC", "KeyV", "KeyB", "KeyN", "KeyM", "Comma", "Period",
        "Slash", "Space", "Enter", "Tab",
    ];
    if let Some(i) = PLAIN.chars().position(|c| c == ch) {
        return Some((CODES[i], false));
    }
    SHIFT.chars().position(|c| c == ch).map(|i| (CODES[i], true))
}

async fn drive(common: Common, mut handle: SessionHandle) -> anyhow::Result<()> {
    let mut screen = Screen { width: 0, height: 0, rgba: Vec::new(), frames: 0 };
    let settle = Duration::from_secs_f32(common.settle);
    let short = Duration::from_millis(40);

    if !pump(&mut handle, &mut screen, settle).await? {
        return Ok(());
    }
    if screen.width == 0 {
        bail!("no session after {:?}", settle);
    }

    if let Some((width, height)) = common.resize {
        handle.input.send(SessionInput::Resize { width, height })?;
        pump(&mut handle, &mut screen, Duration::from_secs(3)).await?;
    }
    if let Some((x, y)) = common.click {
        handle.input.send(SessionInput::PointerMove { x, y })?;
        handle.input.send(SessionInput::PointerButton { button: MouseButton::Left, down: true, x, y })?;
        handle.input.send(SessionInput::PointerButton { button: MouseButton::Left, down: false, x, y })?;
        pump(&mut handle, &mut screen, Duration::from_millis(500)).await?;
    }
    if let Some(text) = &common.set_clipboard {
        handle.input.send(SessionInput::Clipboard { text: text.clone() })?;
        pump(&mut handle, &mut screen, Duration::from_millis(500)).await?;
    }
    if let Some(text) = &common.r#type {
        for ch in text.replace("\\n", "\n").chars() {
            let Some((code, shift)) = key_for(ch) else {
                tracing::warn!(?ch, "cannot type this character");
                continue;
            };
            let key = |down| SessionInput::Key { code: code.to_owned(), key: ch.to_string(), down };
            let shift_key = |down| SessionInput::Key { code: "ShiftLeft".into(), key: "Shift".into(), down };
            if shift {
                handle.input.send(shift_key(true))?;
            }
            handle.input.send(key(true))?;
            handle.input.send(key(false))?;
            if shift {
                handle.input.send(shift_key(false))?;
            }
            pump(&mut handle, &mut screen, short).await?;
        }
        pump(&mut handle, &mut screen, Duration::from_secs(2)).await?;
    }

    println!("frames received: {}", screen.frames);
    if let Some(path) = &common.screenshot {
        screen.save(path)?;
        println!("screenshot saved: {}", path.display());
    }
    let _ = handle.input.send(SessionInput::Close);
    pump(&mut handle, &mut screen, Duration::from_secs(3)).await?;
    Ok(())
}
