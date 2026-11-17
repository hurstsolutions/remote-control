//! RFB handshake: protocol version, security negotiation, authentication, ClientInit/ServerInit.

use crate::auth;
use crate::error::{proto, Result, VncError};
use crate::VncConfig;
use rc_types::SessionEvent;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub(crate) const STAGE_VERSION: &str = "protocol version exchange";
pub(crate) const STAGE_SECURITY: &str = "security type negotiation";
pub(crate) const STAGE_AUTH: &str = "authentication";
pub(crate) const STAGE_AUTH_RESULT: &str = "waiting for the authentication result";
pub(crate) const STAGE_INIT: &str = "session initialisation";
pub(crate) const STAGE_SESSION: &str = "the session";

pub(crate) const SEC_NONE: u8 = 1;
pub(crate) const SEC_VNC: u8 = 2;
pub(crate) const SEC_ARD: u8 = 30;

const MAX_REASON: u32 = 64 * 1024;
const MAX_NAME: u32 = 1024 * 1024;
/// Largest Diffie-Hellman key we accept for Apple auth (macOS uses 128 bytes).
const MAX_ARD_KEY: usize = 1024;

pub(crate) fn security_type_name(t: u8) -> &'static str {
    match t {
        0 => "Invalid",
        1 => "None",
        2 => "VNC password",
        5 => "RA2",
        6 => "RA2ne",
        16 => "Tight",
        17 => "Ultra",
        18 => "TLS",
        19 => "VeNCrypt",
        20 => "SASL",
        21 => "MD5 hash",
        22 => "xvp",
        30 => "Apple Remote Desktop (DH)",
        33 => "Apple (newer, type 33)",
        35 => "Apple (newer, type 35)",
        36 => "Apple (newer, type 36)",
        129 => "RA2 (RealVNC 129)",
        _ => "unknown",
    }
}

fn describe_types(types: &[u8]) -> String {
    types.iter().map(|t| format!("{t} ({})", security_type_name(*t))).collect::<Vec<_>>().join(", ")
}

/// Text from the server: UTF-8 if valid, otherwise Latin-1. Control characters are dropped.
pub(crate) fn decode_text(bytes: &[u8]) -> String {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    };
    s.chars().filter(|c| !c.is_control()).collect()
}

/// The server's native pixel format, logged for diagnostics only (we always set our own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    fn parse(b: &[u8; 16]) -> Self {
        PixelFormat {
            bits_per_pixel: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_colour: b[3] != 0,
            red_max: u16::from_be_bytes([b[4], b[5]]),
            green_max: u16::from_be_bytes([b[6], b[7]]),
            blue_max: u16::from_be_bytes([b[8], b[9]]),
            red_shift: b[10],
            green_shift: b[11],
            blue_shift: b[12],
        }
    }
}

/// The format we always request: 32 bpp, depth 24, little-endian, true colour, 8 bits per
/// channel with red at bit 16, green at bit 8, blue at bit 0 (bytes on the wire: B, G, R, X).
pub(crate) const OUR_PIXEL_FORMAT: [u8; 16] = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0];

pub(crate) struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V33,
    V37,
    V38,
}

async fn status(events: &mpsc::Sender<SessionEvent>, msg: impl Into<String>) -> Result<()> {
    let msg = msg.into();
    info!("status: {msg}");
    events.send(SessionEvent::Status(msg)).await.map_err(|_| VncError::Gone)
}

async fn read_reason<S: AsyncRead + Unpin>(s: &mut S) -> Result<String> {
    let len = s.read_u32().await?;
    if len > MAX_REASON {
        return proto(format!("implausible reason string length {len}"));
    }
    let mut buf = vec![0u8; len as usize];
    s.read_exact(&mut buf).await?;
    Ok(decode_text(&buf))
}

/// Parse the 12-byte "RFB xxx.yyy\n" greeting.
fn parse_version(raw: &[u8; 12]) -> Result<(u32, u32)> {
    let text = String::from_utf8_lossy(raw);
    let bad = || VncError::Protocol(format!("not an RFB server: greeting was {:?}", text.as_ref()));
    if &raw[..4] != b"RFB " || raw[7] != b'.' {
        return Err(bad());
    }
    let num = |b: &[u8]| std::str::from_utf8(b).ok().and_then(|s| s.parse::<u32>().ok());
    match (num(&raw[4..7]), num(&raw[8..11])) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(bad()),
    }
}

fn pick_security(offered: &[u8], config: &VncConfig) -> Result<u8> {
    let has = |t: u8| offered.contains(&t);
    let have_user = config.username.as_deref().is_some_and(|u| !u.is_empty());
    let have_pass = config.password.is_some();
    if has(SEC_ARD) && have_user {
        if !have_pass {
            return Err(VncError::Auth("the server needs a password for this macOS account, but none was supplied".into()));
        }
        return Ok(SEC_ARD);
    }
    if has(SEC_VNC) && have_pass {
        return Ok(SEC_VNC);
    }
    if has(SEC_NONE) {
        return Ok(SEC_NONE);
    }
    if has(SEC_VNC) {
        return Err(VncError::Auth("the server requires a VNC password, but none was supplied".into()));
    }
    if has(SEC_ARD) {
        return Err(VncError::Auth(
            "the server requires a macOS username and password (Apple Remote Desktop authentication), \
             but no username was supplied"
                .into(),
        ));
    }
    Err(VncError::Unsupported(format!(
        "the server offers no security type this client supports (supported: 1 None, 2 VNC password, \
         30 Apple Remote Desktop); offered: [{}]",
        describe_types(offered)
    )))
}

/// Run the whole handshake. `stage` is kept up to date so that errors and timeouts can say
/// where things stopped.
pub(crate) async fn handshake<S>(
    s: &mut S,
    config: &VncConfig,
    events: &mpsc::Sender<SessionEvent>,
    stage: &mut &'static str,
) -> Result<ServerInit>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- ProtocolVersion ----
    *stage = STAGE_VERSION;
    status(events, "Negotiating protocol version").await?;
    let mut greeting = [0u8; 12];
    s.read_exact(&mut greeting).await?;
    let (major, minor) = parse_version(&greeting)?;
    let version = match (major, minor) {
        (3, 0..=6) => Version::V33,
        (3, 7) => Version::V37,
        (3, _) => Version::V38, // includes macOS's "003.889"
        (4.., _) => Version::V38,
        _ => return proto(format!("unsupported RFB protocol version {major}.{minor}")),
    };
    let reply: &[u8; 12] = match version {
        Version::V33 => b"RFB 003.003\n",
        Version::V37 => b"RFB 003.007\n",
        Version::V38 => b"RFB 003.008\n",
    };
    info!(
        server_version = %String::from_utf8_lossy(&greeting).trim_end(),
        client_version = %String::from_utf8_lossy(reply).trim_end(),
        apple = (major == 3 && minor == 889),
        "RFB protocol versions"
    );
    s.write_all(reply).await?;
    s.flush().await?;

    // ---- Security ----
    *stage = STAGE_SECURITY;
    let chosen = if version == Version::V33 {
        // The server decides.
        let t = s.read_u32().await?;
        info!(security_type = t, "RFB 3.3: server chose the security type");
        if t == 0 {
            let reason = read_reason(s).await.unwrap_or_default();
            warn!(%reason, "server refused the connection");
            return Err(refusal(&reason));
        }
        let t = u8::try_from(t).map_err(|_| VncError::Protocol(format!("invalid security type {t}")))?;
        match t {
            SEC_NONE => SEC_NONE,
            SEC_VNC if config.password.is_some() => SEC_VNC,
            SEC_VNC => {
                return Err(VncError::Auth("the server requires a VNC password, but none was supplied".into()))
            }
            other => {
                return Err(VncError::Unsupported(format!(
                    "the server requires security type {other} ({}), which this client does not support",
                    security_type_name(other)
                )))
            }
        }
    } else {
        let count = s.read_u8().await?;
        if count == 0 {
            let reason = read_reason(s).await.unwrap_or_default();
            warn!(%reason, "server refused the connection (zero security types)");
            return Err(refusal(&reason));
        }
        let mut offered = vec![0u8; count as usize];
        s.read_exact(&mut offered).await?;
        for t in &offered {
            info!(security_type = *t, name = security_type_name(*t), "server offers security type");
        }
        let chosen = pick_security(&offered, config).inspect_err(|e| {
            warn!(offered = %describe_types(&offered), "cannot pick a security type: {e}");
        })?;
        info!(
            security_type = chosen,
            name = security_type_name(chosen),
            offered = %describe_types(&offered),
            username_supplied = config.username.as_deref().is_some_and(|u| !u.is_empty()),
            password_supplied = config.password.is_some(),
            "chose security type"
        );
        s.write_all(&[chosen]).await?;
        s.flush().await?;
        chosen
    };

    // ---- Authentication ----
    *stage = STAGE_AUTH;
    match chosen {
        SEC_NONE => {}
        SEC_VNC => {
            status(events, "Authenticating (VNC password)").await?;
            let mut challenge = [0u8; 16];
            s.read_exact(&mut challenge).await?;
            let password = config.password.as_deref().unwrap_or("");
            if password.len() > 8 {
                info!("VNC password is longer than 8 bytes; only the first 8 are used by the protocol");
            }
            s.write_all(&auth::vnc_des_response(password, &challenge)).await?;
            s.flush().await?;
        }
        SEC_ARD => {
            status(events, "Authenticating (macOS account)").await?;
            let generator = s.read_u16().await?;
            let key_len = s.read_u16().await? as usize;
            info!(generator, key_len, "Apple auth: Diffie-Hellman parameters");
            if key_len == 0 || key_len > MAX_ARD_KEY {
                return proto(format!("Apple auth: implausible key length {key_len}"));
            }
            let mut prime = vec![0u8; key_len];
            s.read_exact(&mut prime).await?;
            let mut server_pub = vec![0u8; key_len];
            s.read_exact(&mut server_pub).await?;
            let response = auth::ard_response(
                generator,
                &prime,
                &server_pub,
                config.username.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or(""),
            )?;
            debug!(response_len = response.len(), "Apple auth: sending encrypted credentials and public key");
            s.write_all(&response).await?;
            s.flush().await?;
        }
        _ => unreachable!("pick_security only returns supported types"),
    }

    // ---- SecurityResult ----
    // Sent for every type in 3.8, but not for None in 3.3 / 3.7.
    if chosen != SEC_NONE || version == Version::V38 {
        *stage = STAGE_AUTH_RESULT;
        let result = s.read_u32().await?;
        if result != 0 {
            // 3.8 servers follow up with a reason; older ones just close. Do not hang if a
            // server claiming 3.8 sends none.
            let reason = if version == Version::V38 {
                match tokio::time::timeout(std::time::Duration::from_secs(5), read_reason(s)).await {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        debug!("no failure reason available: {e}");
                        String::new()
                    }
                    Err(_) => {
                        debug!("timed out waiting for a failure reason");
                        String::new()
                    }
                }
            } else {
                String::new()
            };
            warn!(result, %reason, security_type = chosen, "authentication failed");
            let what = match result {
                1 => "authentication failed".to_string(),
                2 => "authentication failed: too many attempts".to_string(),
                n => format!("authentication failed (security result {n})"),
            };
            let detail = if reason.is_empty() {
                format!("{what} using {}; the server gave no reason", security_type_name(chosen))
            } else {
                format!("{what} using {}; server said: {reason}", security_type_name(chosen))
            };
            return Err(VncError::Auth(detail));
        }
        info!(security_type = chosen, "authentication succeeded");
    } else {
        info!("no authentication required");
    }

    // ---- ClientInit / ServerInit ----
    *stage = STAGE_INIT;
    status(events, "Starting session").await?;
    s.write_all(&[u8::from(config.shared)]).await?;
    s.flush().await?;
    let width = s.read_u16().await?;
    let height = s.read_u16().await?;
    let mut pf = [0u8; 16];
    s.read_exact(&mut pf).await?;
    let name_len = s.read_u32().await?;
    if name_len > MAX_NAME {
        return proto(format!("implausible desktop name length {name_len}"));
    }
    let mut name = vec![0u8; name_len as usize];
    s.read_exact(&mut name).await?;
    let name = decode_text(&name);
    info!(width, height, name = %name, shared = config.shared, "ServerInit");
    info!(native_pixel_format = ?PixelFormat::parse(&pf), "server's native pixel format (we request 32bpp BGRX)");
    Ok(ServerInit { width, height, name })
}

/// The server refused before authentication (zero security types). The reason text decides the
/// kind: lock-outs after repeated failures are an auth problem from the user's point of view.
fn refusal(reason: &str) -> VncError {
    let lower = reason.to_ascii_lowercase();
    let detail = if reason.is_empty() {
        "the server refused the connection without giving a reason".to_string()
    } else {
        format!("the server refused the connection: {reason}")
    };
    if lower.contains("authentication") || lower.contains("security failures") || lower.contains("password") {
        VncError::Auth(detail)
    } else {
        VncError::Other(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(user: Option<&str>, pass: Option<&str>) -> VncConfig {
        VncConfig { username: user.map(Into::into), password: pass.map(Into::into), shared: true, view_only: false }
    }

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version(b"RFB 003.889\n").unwrap(), (3, 889));
        assert_eq!(parse_version(b"RFB 003.008\n").unwrap(), (3, 8));
        assert_eq!(parse_version(b"RFB 003.003\n").unwrap(), (3, 3));
        assert!(parse_version(b"SSH-2.0-Open").is_err());
        assert!(parse_version(b"RFB 0x3.008\n").is_err());
    }

    #[test]
    fn security_preference() {
        let mac = [30, 33, 36, 35];
        assert_eq!(pick_security(&mac, &cfg(Some("u"), Some("p"))).unwrap(), 30);
        assert!(matches!(pick_security(&mac, &cfg(None, Some("p"))), Err(VncError::Auth(_))));
        assert!(matches!(pick_security(&mac, &cfg(Some("u"), None)), Err(VncError::Auth(_))));
        // Mac with "VNC viewers may control screen with password" also offers 2.
        let mac_vnc = [30, 33, 36, 35, 2];
        assert_eq!(pick_security(&mac_vnc, &cfg(Some("u"), Some("p"))).unwrap(), 30);
        assert_eq!(pick_security(&mac_vnc, &cfg(None, Some("p"))).unwrap(), 2);
        assert_eq!(pick_security(&mac_vnc, &cfg(Some(""), Some("p"))).unwrap(), 2);
        assert_eq!(pick_security(&[2, 1], &cfg(None, Some("p"))).unwrap(), 2);
        assert_eq!(pick_security(&[2, 1], &cfg(None, None)).unwrap(), 1);
        assert_eq!(pick_security(&[1], &cfg(Some("u"), Some("p"))).unwrap(), 1);
        assert!(matches!(pick_security(&[2], &cfg(None, None)), Err(VncError::Auth(_))));
        match pick_security(&[33, 36, 35, 19], &cfg(Some("u"), Some("p"))) {
            Err(VncError::Unsupported(m)) => {
                for t in ["33", "36", "35", "19 (VeNCrypt)"] {
                    assert!(m.contains(t), "{m}");
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn text_decoding() {
        assert_eq!(decode_text("Zoë's Mac".as_bytes()), "Zoë's Mac");
        assert_eq!(decode_text(&[b'Z', b'o', 0xeb]), "Zoë");
        assert_eq!(decode_text(b"a\0b\n"), "ab");
    }
}
