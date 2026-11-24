//! RFB handshake: protocol version, security negotiation, authentication, ClientInit/ServerInit.

use crate::apple;
use crate::auth;
use crate::srp;
use crate::error::{proto, Result, VncError};
use crate::record::Keys;
use crate::{EncryptionPolicy, VncConfig, VncOptions, SRP_NOT_OFFERED};
use rc_types::SessionEvent;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

pub(crate) const STAGE_VERSION: &str = "protocol version exchange";
pub(crate) const STAGE_SECURITY: &str = "security type negotiation";
pub(crate) const STAGE_AUTH: &str = "authentication";
pub(crate) const STAGE_AUTH_RESULT: &str = "waiting for the authentication result";
pub(crate) const STAGE_INIT: &str = "session initialisation";
pub(crate) const STAGE_ENCRYPTION: &str = "encryption setup";
pub(crate) const STAGE_SESSION: &str = "the session";

pub(crate) const SEC_NONE: u8 = 1;
pub(crate) const SEC_VNC: u8 = 2;
pub(crate) const SEC_ARD: u8 = 30;
pub(crate) const SEC_RSA_SRP: u8 = 33;
pub(crate) const SEC_SRP: u8 = 36;

const MAX_REASON: u32 = 64 * 1024;
const MAX_NAME: u32 = 1024 * 1024;

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
        33 => "Apple RSA/SRP",
        35 => "Apple (newer, type 35)",
        36 => "Apple SRP",
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

/// What the handshake leaves behind for the session.
pub(crate) struct Handshake {
    pub init: ServerInit,
    /// Record-layer keys when the session is encrypted from here on.
    pub keys: Option<Keys>,
    /// We answered Apple's 003.889, so Apple messages and encodings may appear.
    pub apple: bool,
    /// The sign-in proved the server's identity (SRP); meaningful only with `keys`.
    pub server_verified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V33,
    V37,
    V38,
    /// Apple's RFB 003.889 (answered only when we intend to encrypt).
    Apple889,
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

fn has_user(config: &VncConfig) -> bool {
    config.username.as_deref().is_some_and(|u| !u.is_empty())
}

fn password(config: &VncConfig) -> &str {
    config.password.as_ref().map_or("", |p| p.as_str())
}

/// Under `Required`, type 30 would be used instead of SRP. Refused unless the caller allowed
/// an unverified sign-in: a man in the middle can strip 36 from the list, and type 30 is an
/// unauthenticated Diffie-Hellman exchange that hands it the password.
fn unverified_refused(offered: &[u8], srp: bool) -> VncError {
    if offered.contains(&SEC_SRP) && !srp {
        VncError::Security(format!(
            "SRP sign-in (Apple's verified sign-in) is turned off for this connection, and the Mac's other \
             encrypted sign-in (type 30) cannot verify the Mac's identity, so it is refused while encryption is \
             required. Turn SRP back on, or allow unverified sign-in for this connection. Offered: [{}]",
            describe_types(offered)
        ))
    } else {
        VncError::Security(format!(
            "{SRP_NOT_OFFERED}; this can mean someone is interfering with the connection, or an older Mac. \
             Apple's older sign-in (type 30) does not verify the Mac, and an impostor could learn the password \
             through it, so it is refused. Use an SSH tunnel, or allow unverified sign-in for this connection if \
             the network is trusted. Offered: [{}]",
            describe_types(offered)
        ))
    }
}

/// The explanation added when encryption is required and the server would allow a cleartext
/// login.
const DOWNGRADE_NOTE: &str = "Security types None (1) and VNC password (2) are refused while encryption is \
     required: they leave the session unencrypted, and anyone in the network path could strip the other types \
     from the server's list to force them. Use an SSH tunnel, or turn the encryption requirement off for this \
     connection if the network is trusted.";

fn pick_security(
    offered: &[u8],
    config: &VncConfig,
    policy: EncryptionPolicy,
    srp: bool,
    allow_unverified: bool,
) -> Result<u8> {
    let has = |t: u8| offered.contains(&t);
    let have_user = has_user(config);
    let have_pass = config.password.is_some();
    // SRP only when we are encrypting (policy is Off for every non-889 session), and only when
    // the Mac lists 36: a Mac takes SRP inside type 33 only then (and Apple's viewer sends 33's
    // SRP form only then). Carried by 33 when listed, as Apple's viewer does; 36 otherwise.
    let use_srp = srp && policy != EncryptionPolicy::Off && has(SEC_SRP);
    let srp_type = if has(SEC_RSA_SRP) { SEC_RSA_SRP } else { SEC_SRP };
    if use_srp && have_user && have_pass {
        return Ok(srp_type);
    }
    if policy == EncryptionPolicy::Required {
        // SRP (types 33 / 36, above) and type 30 lead to an encrypted session.
        if has(SEC_ARD) || has(SEC_SRP) {
            if !have_user {
                return Err(VncError::Auth(format!(
                    "an encrypted session needs a macOS username and password (Apple authentication), but no \
                     username was supplied.{}",
                    if has(SEC_VNC) { " A VNC password alone cannot encrypt the session." } else { "" }
                )));
            }
            if !have_pass {
                return Err(VncError::Auth("the server needs a password for this macOS account, but none was supplied".into()));
            }
            if use_srp {
                return Ok(srp_type);
            }
            if !allow_unverified || !has(SEC_ARD) {
                return Err(unverified_refused(offered, srp));
            }
            warn!("encryption is required, but signing in with type 30: the Mac's identity will not be verified");
            return Ok(SEC_ARD);
        }
        let weak = has(SEC_NONE) || has(SEC_VNC);
        return Err(VncError::Security(format!(
            "the session could not be encrypted: the Mac offers security types [{}], and this client can encrypt \
             only after Apple's macOS-account sign-in (SRP, types 33 and 36, or type 30), which is not among them.{}",
            describe_types(offered),
            if weak { format!(" {DOWNGRADE_NOTE}") } else { String::new() }
        )));
    }
    if has(SEC_ARD) && have_user {
        if !have_pass {
            return Err(VncError::Auth("the server needs a password for this macOS account, but none was supplied".into()));
        }
        return Ok(SEC_ARD);
    }
    if have_user && (has(SEC_NONE) || has(SEC_VNC)) {
        // A macOS account is configured, so this is meant to be a Mac. A server (or a man in the
        // middle) that offers only None / VNC password is either not that Mac or a downgrade.
        return Err(account_downgrade(offered));
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

/// One SRP message from the server: `u32` length (at most `max`), then the body.
async fn read_srp_message<S: AsyncRead + Unpin>(s: &mut S, what: &str, max: u32) -> Result<Vec<u8>> {
    let len = s.read_u32().await?;
    if len > max {
        log_following_bytes(s, what).await;
        return proto(format!("SRP: implausible {what} length {len}"));
    }
    let mut body = vec![0u8; len as usize];
    s.read_exact(&mut body).await?;
    debug!(len, "SRP: received the {what}");
    Ok(body)
}

/// The shortest plausible SRP challenge (a 3072-bit N alone takes 386 bytes).
const MIN_SRP_CHALLENGE: u32 = 256;

/// Diagnostics after an implausible length from the Mac: log (debug) up to 64 bytes that
/// follow, waiting at most two seconds. Only bytes the Mac sent are logged, never ours.
async fn log_following_bytes<S: AsyncRead + Unpin>(s: &mut S, what: &str) {
    let mut buf = [0u8; 64];
    let mut got = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while got < buf.len() {
        match tokio::time::timeout_at(deadline, s.read(&mut buf[got..])).await {
            Ok(Ok(n)) if n > 0 => got += n,
            Ok(Ok(_)) => {
                debug!("SRP: the Mac closed the connection");
                break;
            }
            Ok(Err(e)) => {
                debug!("SRP: read error while collecting diagnostics: {e}");
                break;
            }
            Err(_) => break,
        }
    }
    debug!(bytes = got, following = %srp::hex_bytes(&buf[..got]), "SRP: bytes that followed the {what} length");
}

/// The error for a server that offers only None / VNC password when a macOS account is set.
fn account_downgrade(offered: &[u8]) -> VncError {
    VncError::Security(format!(
        "a macOS username is set for this connection, but the server offers only [{}]. Security types None (1) \
         and VNC password (2) are refused when a username is set: they would send the session (and, for type 2, \
         a crackable form of the password) without the protection of the macOS sign-in, and a man in the middle \
         can force them by editing the server's list. If this really is a plain VNC server, clear the username.",
        describe_types(offered)
    ))
}

/// Run the whole handshake. `stage` is kept up to date so that errors and timeouts can say
/// where things stopped.
pub(crate) async fn handshake<S>(
    s: &mut S,
    config: &VncConfig,
    options: &VncOptions,
    events: &mpsc::Sender<SessionEvent>,
    stage: &mut &'static str,
) -> Result<Handshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- ProtocolVersion ----
    *stage = STAGE_VERSION;
    status(events, "Negotiating protocol version").await?;
    let mut greeting = [0u8; 12];
    s.read_exact(&mut greeting).await?;
    let (major, minor) = parse_version(&greeting)?;
    let is_apple = major == 3 && minor == 889;
    let policy = options.encryption;
    // Ask for Apple's revision only when we mean to encrypt; otherwise behave exactly like a
    // plain 3.8 client (which is what Off always was).
    let try_encryption = match policy {
        EncryptionPolicy::Off => false,
        EncryptionPolicy::Required => true,
        EncryptionPolicy::Preferred => has_user(config) && config.password.is_some(),
    };
    debug!(?policy, is_apple, try_encryption, "encryption policy");
    if policy == EncryptionPolicy::Required && !is_apple {
        warn!(
            server_version = %String::from_utf8_lossy(&greeting).trim_end(),
            "encryption is required but the server is not Apple Screen Sharing"
        );
        return Err(VncError::Security(format!(
            "the session could not be encrypted: the server announced RFB {major}.{minor}, not Apple Screen Sharing \
             (RFB 003.889), and only Apple Screen Sharing can encrypt a VNC session. Refusing to connect without \
             encryption. Use an SSH tunnel, or turn the encryption requirement off for this connection if the \
             network is trusted."
        )));
    }
    let version = match (major, minor) {
        (3, 889) if try_encryption => Version::Apple889,
        (3, 0..=6) => Version::V33,
        (3, 7) => Version::V37,
        (3, _) => Version::V38, // includes macOS's "003.889" when not encrypting
        (4.., _) => Version::V38,
        _ => return proto(format!("unsupported RFB protocol version {major}.{minor}")),
    };
    let reply: &[u8; 12] = match version {
        Version::V33 => b"RFB 003.003\n",
        Version::V37 => b"RFB 003.007\n",
        Version::V38 => b"RFB 003.008\n",
        Version::Apple889 => b"RFB 003.889\n",
    };
    info!(
        server_version = %String::from_utf8_lossy(&greeting).trim_end(),
        client_version = %String::from_utf8_lossy(reply).trim_end(),
        apple = is_apple,
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
            SEC_NONE | SEC_VNC if has_user(config) => return Err(account_downgrade(&[t])),
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
        // The policy matters only when we are speaking Apple's revision to encrypt.
        let effective = if version == Version::Apple889 { policy } else { EncryptionPolicy::Off };
        let chosen =
            pick_security(&offered, config, effective, options.srp, options.allow_unverified_sign_in).inspect_err(|e| {
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
    let mut wrap_key: Option<Zeroizing<[u8; 16]>> = None;
    let mut server_verified = false;
    match chosen {
        SEC_NONE => {}
        SEC_VNC => {
            status(events, "Authenticating (VNC password)").await?;
            let mut challenge = [0u8; 16];
            s.read_exact(&mut challenge).await?;
            let password = password(config);
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
            if key_len == 0 || key_len > auth::MAX_ARD_KEY {
                return Err(VncError::Security(format!(
                    "Apple auth: the server's Diffie-Hellman key length is {key_len} bytes (accepted: up to {})",
                    auth::MAX_ARD_KEY
                )));
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
                password(config),
            )?;
            debug!(response_len = response.message.len(), "Apple auth: sending encrypted credentials and public key");
            s.write_all(&response.message).await?;
            s.flush().await?;
            // MD5(shared secret): also the wrap key for the encrypted session's first rekey.
            wrap_key = Some(response.wrap_key);
        }
        SEC_SRP | SEC_RSA_SRP => {
            status(events, "Authenticating (macOS account, SRP)").await?;
            let username = config.username.as_deref().unwrap_or("");
            let rsa = chosen == SEC_RSA_SRP;
            let challenge = if rsa {
                // Type 33: fetch the Mac's RSA key, send message 1 encrypted to it.
                debug!("SRP (type 33): asking for the Mac's RSA public key");
                s.write_all(&srp::rsa1_key_request()).await?;
                s.flush().await?;
                let reply = read_srp_message(s, "RSA key reply", srp::MAX_RSA_KEY_REPLY).await?;
                let key = srp::parse_rsa_key_reply(&reply).inspect_err(|e| {
                    warn!("SRP: bad RSA key reply: {e}");
                    debug!(head = %srp::hex_bytes(&reply[..reply.len().min(64)]), "SRP: start of the RSA key reply");
                })?;
                // Not authenticated, and it need not be: the Mac's proof M2 below verifies the Mac.
                debug!(bits = key.bits(), "SRP (type 33): the Mac's RSA key");
                let packet = srp::rsa1_identity_packet(&key, username)?;
                debug!(bytes = packet.len(), "SRP (type 33): sending the encrypted identity message");
                s.write_all(&packet).await?;
                s.flush().await?;
                let body = read_srp_message(s, "challenge", srp::MAX_MESSAGE).await?;
                srp::parse_rsa1_challenge(&body).map_err(|e| {
                    debug!(head = %srp::hex_bytes(&body[..body.len().min(64)]), "SRP: start of the challenge");
                    if body.starts_with(&[0, 1, 0, 0]) {
                        warn!("SRP: the Mac sent its RSA key again instead of the challenge");
                        VncError::Protocol(
                            "SRP: the Mac could not decrypt the sign-in request (it sent its RSA key again)".into(),
                        )
                    } else {
                        warn!("SRP: bad challenge: {e}");
                        e
                    }
                })?
            } else {
                let identity = srp::identity_message(username);
                debug!(bytes = identity.len(), "SRP: sending the identity message");
                s.write_all(&identity).await?;
                s.flush().await?;
                let len = s.read_u32().await?;
                if !(MIN_SRP_CHALLENGE..=srp::MAX_MESSAGE).contains(&len) {
                    warn!(len, "SRP: implausible challenge length");
                    log_following_bytes(s, "challenge").await;
                    return proto(format!("SRP: the Mac answered the identity message with an implausible length ({len})"));
                }
                let mut body = vec![0u8; len as usize];
                s.read_exact(&mut body).await?;
                debug!(len, "SRP: received the challenge");
                srp::parse_challenge(&body).inspect_err(|e| warn!("SRP: bad challenge: {e}"))?
            };
            debug!(
                n_bits = challenge.n.len() * 8,
                g = %challenge.g.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                salt_len = challenge.salt.len(),
                b_len = challenge.b.len(),
                iterations = challenge.iterations,
                options = %String::from_utf8_lossy(&challenge.options),
                "SRP: challenge"
            );
            // Refuse unknown groups and oversized iteration counts before starting PBKDF2: a
            // blocking task cannot be cancelled, so if the handshake is abandoned (closed, timed
            // out) it runs to completion anyway, at most MAX_ITERATIONS rounds (about a second).
            srp::check_challenge(&challenge).inspect_err(|e| warn!("SRP: refusing the challenge: {e}"))?;
            let password = Zeroizing::new(password(config).to_owned());
            let ch = challenge.clone();
            // PBKDF2 with tens of thousands of iterations: keep it off the async workers.
            let proof = tokio::task::spawn_blocking(move || srp::client_proof(&ch, &password))
                .await
                .map_err(|e| VncError::Other(format!("SRP computation failed: {e}")))??;
            let mut client_random = [0u8; 16];
            getrandom::fill(&mut client_random)
                .map_err(|e| VncError::Other(format!("could not get random bytes from the OS: {e}")))?;
            let msg = if rsa {
                srp::rsa1_proof_packet(&proof, &challenge.options, &client_random)?
            } else {
                srp::proof_message(&proof, &challenge.options, &client_random)
            };
            debug!(bytes = msg.len(), "SRP: sending A and the proof M1");
            s.write_all(&msg).await?;
            s.flush().await?;
            *stage = STAGE_AUTH_RESULT;
            // A Mac that rejects M1 may send the SecurityResult word straight away instead of
            // message 4; a "length" that small cannot be message 4 (which holds a 64-byte M2).
            let len = s.read_u32().await?;
            if len < 8 {
                warn!(result = len, "SRP: the Mac answered the proof with a failure result instead of its own proof");
                return Err(VncError::Auth(format!(
                    "authentication failed using Apple SRP (security result {len}); check the username and password"
                )));
            }
            if len > srp::MAX_MESSAGE {
                log_following_bytes(s, "server proof").await;
                return proto(format!("SRP: implausible server proof length {len}"));
            }
            let mut fin = vec![0u8; len as usize];
            s.read_exact(&mut fin).await?;
            debug!(len, "SRP: received the server proof");
            let m2 = if rsa { srp::parse_rsa1_final(&fin)? } else { srp::parse_final(&fin)? };
            if !proof.server_proof_matches(&m2) {
                warn!(m2_len = m2.len(), "SRP: the Mac's proof M2 is wrong");
                return Err(VncError::Security(
                    "the Mac's SRP proof (M2) is wrong: whoever answered does not know this account's password \
                     verifier, so it may not be the Mac you meant to reach. The connection was closed before \
                     anything was shown or typed"
                        .into(),
                ));
            }
            debug!("SRP: the Mac's proof M2 is correct; the Mac knows the password verifier");
            wrap_key = Some(proof.wrap_key);
            server_verified = true;
        }
        _ => unreachable!("pick_security only returns supported types"),
    }

    // ---- SecurityResult ----
    // Sent for every type in 3.8, but not for None in 3.3 / 3.7.
    if chosen != SEC_NONE || matches!(version, Version::V38 | Version::Apple889) {
        *stage = STAGE_AUTH_RESULT;
        let result = s.read_u32().await?;
        if result != 0 {
            // 3.8 servers follow up with a reason; older ones just close. Do not hang if a
            // server claiming 3.8 sends none. A Mac sends no reason to a 003.889 client (and
            // keeps the connection open), so do not wait for one there.
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
    // Encrypt only with a wrap key from authentication (type 30 for now; SRP later).
    let encrypt_key = if version == Version::Apple889 { wrap_key } else { None };
    if version == Version::Apple889 && encrypt_key.is_none() {
        // Preferred, but the Mac's list did not lead to type 30 (e.g. only a VNC password).
        warn!(security_type = chosen, "the session will not be encrypted: the chosen sign-in gives no key to encrypt with");
    }
    let client_init = u8::from(config.shared) | if encrypt_key.is_some() { apple::CLIENT_INIT_EXTENDED } else { 0 };
    debug!(client_init = format_args!("{client_init:#04x}"), "sending ClientInit");
    s.write_all(&[client_init]).await?;
    s.flush().await?;
    let width = s.read_u16().await?;
    let height = s.read_u16().await?;
    let mut pf = [0u8; 16];
    s.read_exact(&mut pf).await?;
    let name_len = s.read_u32().await?;
    if name_len > MAX_NAME {
        return proto(format!("implausible desktop name length {name_len}"));
    }
    let mut raw_name = vec![0u8; name_len as usize];
    s.read_exact(&mut raw_name).await?;
    let mut extended = None;
    let name = if encrypt_key.is_some() {
        match apple::split_extended_name(&raw_name) {
            Some((ext, name)) => {
                debug!(
                    flags = format_args!("{:#010x}", ext.flags),
                    commands = %ext.commands.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    set_encryption = ext.accepts_set_encryption(),
                    viewer_info = ext.accepts(0x21),
                    observe_only = ext.observe_only(),
                    "extended ServerInit"
                );
                extended = Some(ext);
                decode_text(name)
            }
            None => {
                warn!(name_len, "asked for the extended ServerInit, but the name field is too short to hold it");
                decode_text(&raw_name)
            }
        }
    } else {
        decode_text(&raw_name)
    };
    info!(width, height, name = %name, shared = config.shared, "ServerInit");
    info!(native_pixel_format = ?PixelFormat::parse(&pf), "server's native pixel format (we request 32bpp BGRX)");
    if extended.is_some_and(|e| e.observe_only()) {
        warn!("the Mac allows only observing in this session; it will ignore keyboard and mouse input");
    }

    // ---- Apple encrypted session setup ----
    let mut keys = None;
    if let Some(wrap_key) = encrypt_key {
        *stage = STAGE_ENCRYPTION;
        if extended.is_some_and(|e| !e.accepts_set_encryption()) {
            return Err(VncError::Security(
                "the Mac's ServerInit does not list SetEncryption (message 0x12) among the messages it accepts".into(),
            ));
        }
        status(events, "Setting up encryption").await?;
        let prelude = apple::prelude();
        debug!(
            bytes = prelude.len(),
            "encryption setup: sending ViewerInfo, SetEncryption(start, AES-128) and SetEncryption(decrypt inbound)"
        );
        s.write_all(&prelude).await?;
        s.flush().await?;
        debug!("encryption setup: waiting for the Mac's rekey");
        keys = Some(apple::await_rekey(s, &wrap_key).await?);
        drop(wrap_key);
        info!("encryption setup: record layer active (AES-128-CBC, SHA-1 integrity)");
    }
    Ok(Handshake {
        init: ServerInit { width, height, name },
        server_verified: server_verified && keys.is_some(),
        keys,
        apple: version == Version::Apple889,
    })
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
        VncConfig {
            username: user.map(Into::into),
            password: pass.map(|p| p.to_owned().into()),
            shared: true,
            view_only: false,
        }
    }

    fn pick(offered: &[u8], config: &VncConfig) -> Result<u8> {
        pick_security(offered, config, EncryptionPolicy::Off, true, false)
    }

    #[test]
    fn srp_is_preferred_when_encrypting() {
        let full = cfg(Some("u"), Some("p"));
        let mac = [30, 33, 36, 35];
        for policy in [EncryptionPolicy::Required, EncryptionPolicy::Preferred] {
            for allow in [false, true] {
                // 33 carries SRP when listed (as Apple's viewer does); 36 only without 33.
                assert_eq!(pick_security(&mac, &full, policy, true, allow).unwrap(), 33);
                assert_eq!(pick_security(&[36, 33], &full, policy, true, allow).unwrap(), 33);
                assert_eq!(pick_security(&[30, 36, 35], &full, policy, true, allow).unwrap(), 36);
                assert_eq!(pick_security(&[36], &full, policy, true, allow).unwrap(), 36);
            }
        }
        // SRP turned off: type 30 under Preferred; under Required only when allowed.
        assert_eq!(pick_security(&mac, &full, EncryptionPolicy::Preferred, false, false).unwrap(), 30);
        assert_eq!(pick_security(&mac, &full, EncryptionPolicy::Required, false, true).unwrap(), 30);
        match pick_security(&mac, &full, EncryptionPolicy::Required, false, false) {
            Err(VncError::Security(m)) => {
                assert!(m.contains("SRP sign-in (Apple's verified sign-in) is turned off"), "{m}");
                assert!(!m.starts_with(SRP_NOT_OFFERED), "{m}");
            }
            other => panic!("{other:?}"),
        }
        // Never in an unencrypted (Off) session: behaviour there is unchanged.
        for allow in [false, true] {
            assert_eq!(pick_security(&mac, &full, EncryptionPolicy::Off, true, allow).unwrap(), 30);
        }
        for allow in [false, true] {
            assert!(pick_security(&[36], &full, EncryptionPolicy::Required, false, allow).is_err());
        }
    }

    /// Security audit round 2: a man in the middle rewrites the Mac's list [30, 33, 36, 35] to
    /// [30]; type 30 is unauthenticated Diffie-Hellman, so it would learn the password.
    #[test]
    fn required_refuses_srp_to_type_30_downgrade() {
        let full = cfg(Some("u"), Some("p"));
        for offered in [&[30u8][..], &[30, 33, 35], &[30, 33, 35, 2], &[30, 1]] {
            match pick_security(offered, &full, EncryptionPolicy::Required, true, false) {
                Err(VncError::Security(m)) => {
                    assert!(m.starts_with(SRP_NOT_OFFERED), "{m}");
                    assert!(m.contains("someone is interfering with the connection, or an older Mac"), "{m}");
                }
                other => panic!("{offered:?}: {other:?}"),
            }
            assert_eq!(pick_security(offered, &full, EncryptionPolicy::Required, true, true).unwrap(), 30);
            // Inside an SSH tunnel (Off) and with Preferred, unchanged.
            assert_eq!(pick_security(offered, &full, EncryptionPolicy::Off, true, false).unwrap(), 30);
            assert_eq!(pick_security(offered, &full, EncryptionPolicy::Preferred, true, false).unwrap(), 30);
        }
        // Missing credentials are still reported as such first.
        assert!(matches!(
            pick_security(&[30], &cfg(None, Some("p")), EncryptionPolicy::Required, true, false),
            Err(VncError::Auth(_))
        ));
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
        assert_eq!(pick(&mac, &cfg(Some("u"), Some("p"))).unwrap(), 30);
        assert!(matches!(pick(&mac, &cfg(None, Some("p"))), Err(VncError::Auth(_))));
        assert!(matches!(pick(&mac, &cfg(Some("u"), None)), Err(VncError::Auth(_))));
        // Mac with "VNC viewers may control screen with password" also offers 2.
        let mac_vnc = [30, 33, 36, 35, 2];
        assert_eq!(pick(&mac_vnc, &cfg(Some("u"), Some("p"))).unwrap(), 30);
        assert_eq!(pick(&mac_vnc, &cfg(None, Some("p"))).unwrap(), 2);
        assert_eq!(pick(&mac_vnc, &cfg(Some(""), Some("p"))).unwrap(), 2);
        assert_eq!(pick(&[2, 1], &cfg(None, Some("p"))).unwrap(), 2);
        assert_eq!(pick(&[2, 1], &cfg(None, None)).unwrap(), 1);
        assert!(matches!(pick(&[1], &cfg(Some("u"), Some("p"))), Err(VncError::Security(_))));
        assert!(matches!(pick(&[2], &cfg(None, None)), Err(VncError::Auth(_))));
        match pick(&[33, 36, 35, 19], &cfg(Some("u"), Some("p"))) {
            Err(VncError::Unsupported(m)) => {
                for t in ["33", "36", "35", "19 (VeNCrypt)"] {
                    assert!(m.contains(t), "{m}");
                }
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn username_set_refuses_none_and_vnc_password() {
        let mac = cfg(Some("alice"), Some("p"));
        for offered in [&[1u8][..], &[2], &[2, 1], &[33, 35, 2], &[35, 1]] {
            for policy in [EncryptionPolicy::Off, EncryptionPolicy::Preferred, EncryptionPolicy::Required] {
                match pick_security(offered, &mac, policy, true, false) {
                    Err(VncError::Security(m)) => assert!(m.contains("None (1)") && m.contains("(2)"), "{m}"),
                    other => panic!("{offered:?} {policy:?}: {other:?}"),
                }
            }
        }
        // Without a username, a plain VNC server still works.
        assert_eq!(pick(&[2, 1], &cfg(None, Some("p"))).unwrap(), 2);
        assert_eq!(pick(&[2, 1], &cfg(Some(""), Some("p"))).unwrap(), 2);
    }

    #[test]
    fn required_policy_refuses_weak_types() {
        let req = |offered: &[u8], c: &VncConfig| pick_security(offered, c, EncryptionPolicy::Required, true, false);
        let full = cfg(Some("u"), Some("p"));
        assert_eq!(req(&[30, 33, 36, 35, 2], &full).unwrap(), 33);
        // 33 without 36: the Mac would not take SRP inside 33, so it is not a verified sign-in.
        assert!(matches!(req(&[30, 33, 35], &full), Err(VncError::Security(_))));
        assert_eq!(pick_security(&[30, 33, 35, 2], &full, EncryptionPolicy::Required, true, true).unwrap(), 30);
        for offered in [&[1u8][..], &[2], &[2, 1], &[33, 35, 2]] {
            match req(offered, &full) {
                Err(VncError::Security(m)) => {
                    assert!(m.contains("could not be encrypted"), "{m}");
                    assert!(m.contains("None (1) and VNC password (2) are refused"), "{m}");
                }
                other => panic!("{offered:?}: {other:?}"),
            }
        }
        match req(&[33, 35], &full) {
            Err(VncError::Security(m)) => assert!(!m.contains("refused while"), "{m}"),
            other => panic!("{other:?}"),
        }
        // Type 2 is never used instead of 30, even with only a password.
        match req(&[30, 2], &cfg(None, Some("p"))) {
            Err(VncError::Auth(m)) => assert!(m.contains("VNC password alone cannot encrypt"), "{m}"),
            other => panic!("{other:?}"),
        }
        // Preferred keeps the old preferences.
        let pref =
            |offered: &[u8], c: &VncConfig| pick_security(offered, c, EncryptionPolicy::Preferred, true, false);
        assert_eq!(pref(&[30, 2], &full).unwrap(), 30);
        assert_eq!(pref(&[33, 2], &cfg(None, Some("p"))).unwrap(), 2);
        assert!(matches!(pref(&[33, 2], &full), Err(VncError::Security(_))));
    }

    #[test]
    fn text_decoding() {
        assert_eq!(decode_text("Zoë's Mac".as_bytes()), "Zoë's Mac");
        assert_eq!(decode_text(&[b'Z', b'o', 0xeb]), "Zoë");
        assert_eq!(decode_text(b"a\0b\n"), "ab");
    }
}
