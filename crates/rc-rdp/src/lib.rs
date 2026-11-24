//! RDP backend: drives an RDP session with the IronRDP crates and speaks `rc-types` to the front end.
//!
//! Security model: TLS is mandatory and Network Level Authentication (CredSSP) is on by default.
//! RDP hosts use self-signed certificates, so the certificate is pinned on first use: the SHA-256
//! of the server certificate is reported as `SessionEvent::ServerIdentity`, and when the caller
//! supplies a pinned value a mismatch aborts the connection before credentials are sent.

mod clipboard;
mod keymap;
mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_cliprdr::pdu::{ClipboardFormat, ClipboardFormatId};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError, ConnectorErrorKind, Sequence as _,
    State as _,
};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton as RdpButton, MousePosition, Operation, WheelRotations};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_pdu::nego::{ConnectionConfirm, SecurityProtocol};
use ironrdp_pdu::x224::X224;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{fast_path, ActiveStage, ActiveStageBuilder, ActiveStageOutput, SessionError as RdpSessionError};
use ironrdp_tokio::reqwest::ReqwestNetworkClient;
use ironrdp_tokio::{
    single_sequence_step, single_sequence_step_read, split_tokio_framed, FramedWrite as _,
    ShouldUpgrade, TokioFramed,
};
use rc_types::{
    CursorShape, ErrorKind, IdentityKind, MouseButton, SessionError, SessionEvent, SessionInput, SessionIo,
    MAX_CLIPBOARD_BYTES,
};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use x509_cert::der::Decode as _;
use zeroize::Zeroizing;

use crate::clipboard::{ClipEvent, TextClipboard};

#[derive(Clone)]
pub struct RdpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Wiped from memory when dropped; the session drops its copy once signed in.
    pub password: Zeroizing<String>,
    /// Windows domain, or `None` for a local / Microsoft account.
    pub domain: Option<String>,
    /// Initial desktop size in pixels. Clamped to what RDP allows (200..=8192 per side).
    pub width: u16,
    pub height: u16,
    /// Desktop scale factor in percent (100 = 1x, 200 = Retina).
    pub scale_factor: u32,
    /// Expected SHA-256 (lowercase hex) of the server's TLS certificate. `None` = first connection.
    pub pinned_cert_sha256: Option<String>,
    /// Network Level Authentication. Leave on for Windows; some Linux servers (xrdp) need it off.
    pub nla: bool,
    pub clipboard: bool,
}

impl std::fmt::Debug for RdpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("domain", &self.domain)
            .field("size", &(self.width, self.height))
            .field("scale_factor", &self.scale_factor)
            .field("pinned", &self.pinned_cert_sha256.is_some())
            .field("nla", &self.nla)
            .field("clipboard", &self.clipboard)
            .finish()
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}
type Framed = TokioFramed<Box<dyn Stream>>;

/// Run an RDP session until it ends. Never returns an error: the outcome is reported as the final
/// `SessionEvent::Closed`.
pub async fn run(config: RdpConfig, io: SessionIo) {
    let SessionIo { events, mut input } = io;
    // Only the target: the full config (with the username) goes to the debug level.
    info!(host = %config.host, port = config.port, nla = config.nla, clipboard = config.clipboard, "starting RDP session");
    debug!(?config, "RDP session config");
    let error = match session(config, events.clone(), &mut input).await {
        Ok(()) => None,
        Err(error) => {
            warn!(kind = ?error.kind, detail = %error.detail, "RDP session failed");
            Some(error)
        }
    };
    let _ = events.send(SessionEvent::Closed { error }).await;
}

/// Run a session on its own thread and return immediately.
///
/// Use this rather than `tokio::spawn(run(..))`: the IronRDP futures are not provably `Send`
/// (a rustc higher-ranked-lifetime limitation), and one thread per remote session also keeps a
/// busy decoder from stalling anything else.
pub fn spawn(config: RdpConfig, io: SessionIo) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new().name("rdp-session".to_owned()).spawn(move || {
        match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(run(config, io)),
            Err(e) => {
                let error = SessionError::new(ErrorKind::Other, format!("cannot start session runtime: {e}"));
                let _ = io.events.blocking_send(SessionEvent::Closed { error: Some(error) });
            }
        }
    })
}

async fn status(events: mpsc::Sender<SessionEvent>, text: &str) {
    info!("{text}");
    let _ = events.send(SessionEvent::Status(text.to_owned())).await;
}

async fn session(
    mut config: RdpConfig,
    events: mpsc::Sender<SessionEvent>,
    input: &mut mpsc::UnboundedReceiver<SessionInput>,
) -> Result<(), SessionError> {
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel();
    let local_text = Arc::new(Mutex::new(String::new()));

    let (connection, framed) = connect(&config, events.clone(), &clip_tx, &local_text).await?;
    // Signed in: the password is not needed again. Dropping it wipes this copy.
    config.password = Zeroizing::default();

    let size = connection.desktop_size;
    check_desktop_size(size.width, size.height)?;
    info!(width = size.width, height = size.height, "RDP session established");
    let _ = events
        .send(SessionEvent::Connected {
            width: size.width,
            height: size.height,
            name: config.host.clone(),
        })
        .await;

    active(framed, connection, events, input, &mut clip_rx, &local_text, &config).await
}

// ── Connection ───────────────────────────────────────────────────────────────

async fn connect(
    config: &RdpConfig,
    events: mpsc::Sender<SessionEvent>,
    clip_tx: &mpsc::UnboundedSender<ClipEvent>,
    local_text: &Arc<Mutex<String>>,
) -> Result<(ConnectionResult, Framed), SessionError> {
    status(events.clone(), &format!("Connecting to {}:{}", config.host, config.port)).await;

    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((config.host.as_str(), config.port)),
    )
    .await
    .map_err(|_| {
        SessionError::new(
            ErrorKind::Unreachable,
            format!("no answer from {}:{} after 10 s", config.host, config.port),
        )
    })?
    .map_err(|e| {
        SessionError::new(
            ErrorKind::Unreachable,
            format!("TCP connect to {}:{} failed: {e}", config.host, config.port),
        )
    })?;
    let _ = tcp.set_nodelay(true);
    let client_addr = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

    let mut connector = build_connector(config, client_addr, clip_tx, local_text)?;
    let mut framed = TokioFramed::new(tcp);

    status(events.clone(), "Negotiating security").await;
    let should_upgrade = negotiate(&mut framed, &mut connector, config.nla).await?;

    let (tcp, leftover) = framed.into_inner();
    check_no_plaintext_leftover(&leftover)?;
    let (tls, cert_der) = tls::upgrade(tcp, &config.host)
        .await
        .map_err(|e| SessionError::new(ErrorKind::Security, format!("TLS handshake failed: {e}")))?;
    let (version, cipher) = tls::negotiated(&tls);
    info!(?version, ?cipher, "TLS established");

    // Pin the certificate before any credentials leave this machine. The TLS layer has already
    // checked that the server holds this certificate's private key.
    let fingerprint = hex(&Sha256::digest(cert_der.as_ref()));
    let cert = x509_cert::Certificate::from_der(cert_der.as_ref());
    match &cert {
        Ok(cert) => info!(%fingerprint, subject = %cert.tbs_certificate.subject, "server certificate"),
        Err(_) => info!(%fingerprint, "server certificate"),
    }
    if let Some(pinned) = &config.pinned_cert_sha256 {
        if !pinned.eq_ignore_ascii_case(&fingerprint) {
            return Err(SessionError::identity_changed(
                IdentityKind::TlsCertificate,
                pinned.as_str(),
                fingerprint.as_str(),
                format!(
                    "the server's certificate changed (expected {pinned}, got {fingerprint}). \
                     This happens after Windows is reinstalled or the certificate renews, but it can \
                     also mean another machine is answering at this address. No credentials were sent."
                ),
            ));
        }
    }
    let cert =
        cert.map_err(|e| SessionError::new(ErrorKind::Security, format!("cannot parse server certificate: {e}")))?;
    // CredSSP binds the sign-in to this key (the certificate's subjectPublicKey bits).
    let server_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| SessionError::new(ErrorKind::Security, "server certificate has no usable public key"))?
        .to_owned();
    let _ = events
        .send(SessionEvent::ServerIdentity { sha256: fingerprint })
        .await;
    let _ = events.send(security_event(config)).await;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let boxed: Box<dyn Stream> = Box::new(tls);
    let mut framed = TokioFramed::new(boxed);

    status(events.clone(), "Signing in").await;
    let connection = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut ReqwestNetworkClient::new(),
        ironrdp_connector::ServerName::new(config.host.clone()),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| connector_error("sign-in", &e))?;

    Ok((connection, framed))
}

/// Bytes that arrived after the X.224 Connection Confirm but before the TLS handshake are
/// unauthenticated cleartext; a man in the middle could use them to inject data that would be
/// read as if it came through TLS. A real server sends nothing until our ClientHello.
fn check_no_plaintext_leftover(leftover: &[u8]) -> Result<(), SessionError> {
    if leftover.is_empty() {
        return Ok(());
    }
    warn!(bytes = leftover.len(), "unexpected cleartext after the X.224 Connection Confirm");
    Err(SessionError::new(
        ErrorKind::Security,
        format!(
            "the server sent {} unexpected byte(s) in cleartext after the security negotiation, before TLS \
             started; refusing to continue (this can mean someone is tampering with the connection)",
            leftover.len()
        ),
    ))
}

/// How the session is protected, reported once the certificate passed the pin check. A pin
/// that was set has matched by then (a mismatch ends the session), so the server is verified
/// exactly when there was a pin; on first use it is not.
fn security_event(config: &RdpConfig) -> SessionEvent {
    let method = if config.nla { "TLS + NLA" } else { "TLS" };
    SessionEvent::security(true, config.pinned_cert_sha256.is_some(), method)
}

/// X.224 security negotiation. With NLA on, refuses any answer other than CredSSP (HYBRID /
/// HYBRID_EX) before the connector sees it, so a downgrade is reported as a security problem.
async fn negotiate(
    framed: &mut TokioFramed<TcpStream>,
    connector: &mut ClientConnector,
    nla: bool,
) -> Result<ShouldUpgrade, SessionError> {
    let mut buf = WriteBuf::new();
    while !connector.should_perform_security_upgrade() {
        if !matches!(connector.state, ClientConnectorState::ConnectionInitiationWaitConfirm { .. }) {
            single_sequence_step(framed, connector, &mut buf)
                .await
                .map_err(|e| connector_error("security negotiation", &e))?;
            continue;
        }
        let Some(hint) = connector.next_pdu_hint() else {
            return Err(SessionError::new(ErrorKind::Protocol, "security negotiation: no reply expected"));
        };
        let pdu = framed.read_by_hint(hint).await.map_err(|e| {
            SessionError::new(ErrorKind::Disconnected, format!("security negotiation: connection lost: {e}"))
        })?;
        if nla {
            if let Ok(X224(ConnectionConfirm::Response { protocol, .. })) =
                ironrdp_core::decode::<X224<ConnectionConfirm>>(&pdu)
            {
                check_nla_selected(protocol)?;
            }
        }
        buf.clear();
        let written = connector
            .step(&pdu, &mut buf)
            .map_err(|e| connector_error("security negotiation", &e))?;
        if let Some(size) = written.size() {
            framed.write_all(&buf.filled()[..size]).await.map_err(|e| {
                SessionError::new(ErrorKind::Disconnected, format!("security negotiation: connection lost: {e}"))
            })?;
        }
    }
    // Defence in depth: whatever path got here, the selected protocol must still be CredSSP.
    if nla {
        match &connector.state {
            ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol } => check_nla_selected(*selected_protocol)?,
            other => {
                return Err(SessionError::new(
                    ErrorKind::Protocol,
                    format!("security negotiation ended in an unexpected state ({})", other.name()),
                ))
            }
        }
    }
    Ok(ironrdp_tokio::skip_connect_begin(connector))
}

fn check_nla_selected(selected: SecurityProtocol) -> Result<(), SessionError> {
    if selected.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX) {
        return Ok(());
    }
    Err(SessionError::new(
        ErrorKind::Security,
        format!(
            "the PC tried to skip Network Level Authentication (it selected {selected:?} instead of CredSSP). \
             This can mean another machine is intercepting the connection. No credentials were sent."
        ),
    ))
}

/// Largest desktop side the client will allocate a frame buffer for (16384 x 16384 x 4 = 1 GiB).
const MAX_DESKTOP_SIDE: u16 = 16384;

/// The frame buffer for a server-chosen desktop size, refusing absurd sizes before allocating.
fn desktop_image(width: u16, height: u16) -> Result<DecodedImage, SessionError> {
    check_desktop_size(width, height)?;
    Ok(DecodedImage::new(PixelFormat::RgbA32, width, height))
}

fn check_desktop_size(width: u16, height: u16) -> Result<(), SessionError> {
    if width > MAX_DESKTOP_SIDE || height > MAX_DESKTOP_SIDE {
        return Err(SessionError::new(
            ErrorKind::Protocol,
            format!("the server chose a {width}x{height} desktop; the limit is {MAX_DESKTOP_SIDE} pixels per side"),
        ));
    }
    Ok(())
}

fn build_connector(
    config: &RdpConfig,
    client_addr: SocketAddr,
    clip_tx: &mpsc::UnboundedSender<ClipEvent>,
    local_text: &Arc<Mutex<String>>,
) -> Result<ironrdp_connector::ClientConnector, SessionError> {
    use ironrdp_pdu::rdp::capability_sets::{client_codecs_capabilities, MajorPlatformType};
    use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};

    let codecs = client_codecs_capabilities(&[]).map_err(|e| SessionError::new(ErrorKind::Other, e))?;
    let (width, height) = MonitorLayoutEntry::adjust_display_size(u32::from(config.width), u32::from(config.height));

    let platform = if cfg!(target_os = "macos") {
        MajorPlatformType::MACINTOSH
    } else if cfg!(windows) {
        MajorPlatformType::WINDOWS
    } else {
        MajorPlatformType::UNIX
    };

    let connector_config = ironrdp_connector::Config {
        credentials: ironrdp_connector::Credentials::UsernamePassword {
            username: config.username.clone(),
            password: (*config.password).clone(),
        },
        domain: config.domain.clone().filter(|d| !d.is_empty()),
        // With NLA on, advertise only HYBRID / HYBRID_EX: offering plain SSL as well would let a
        // man in the middle pick it, skip CredSSP and receive the password in the Client Info PDU.
        enable_tls: !config.nla,
        enable_credssp: config.nla,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: ironrdp_connector::DesktopSize {
            width: u16::try_from(width).unwrap_or(config.width),
            height: u16::try_from(height).unwrap_or(config.height),
        },
        desktop_scale_factor: config.scale_factor,
        bitmap: Some(ironrdp_connector::BitmapConfig {
            color_depth: 32,
            lossy_compression: true,
            codecs,
        }),
        client_build: 0,
        client_name: "RemoteControl".to_owned(),
        client_dir: String::new(),
        platform,
        hardware_id: None,
        license_cache: None,
        enable_server_pointer: true,
        autologon: true,
        enable_audio_playback: false,
        request_data: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        compression_type: Some(CompressionType::K64),
        performance_flags: PerformanceFlags::default(),
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    };

    let drdynvc =
        ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector =
        ironrdp_connector::ClientConnector::new(connector_config, client_addr).with_static_channel(drdynvc);

    if config.clipboard {
        let backend = TextClipboard {
            local_text: Arc::clone(local_text),
            tx: clip_tx.clone(),
        };
        connector.attach_static_channel(ironrdp_cliprdr::Cliprdr::new(Box::new(backend)));
    }

    Ok(connector)
}

// ── Active session ───────────────────────────────────────────────────────────

struct InputState {
    db: Database,
    /// Fractional wheel notches not yet sent (vertical, horizontal).
    wheel: (f32, f32),
}

async fn active(
    framed: Framed,
    connection: ConnectionResult,
    events: mpsc::Sender<SessionEvent>,
    input: &mut mpsc::UnboundedReceiver<SessionInput>,
    clip_rx: &mut mpsc::UnboundedReceiver<ClipEvent>,
    local_text: &Arc<Mutex<String>>,
    config: &RdpConfig,
) -> Result<(), SessionError> {
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let size = connection.desktop_size;
    let mut image = desktop_image(size.width, size.height)?;
    let activation_factory = connection.activation_factory;

    let mut stage = ActiveStageBuilder {
        static_channels: connection.static_channels,
        user_channel_id: connection.user_channel_id,
        io_channel_id: connection.io_channel_id,
        message_channel_id: connection.message_channel_id,
        share_id: connection.share_id,
        compression_type: connection.compression_type,
        enable_server_pointer: connection.enable_server_pointer,
        pointer_software_rendering: connection.pointer_software_rendering,
    }
    .build();

    let mut state = InputState {
        db: Database::new(),
        wheel: (0.0, 0.0),
    };
    let mut cleanup = tokio::time::interval(Duration::from_secs(5));
    let mut closing = false;

    loop {
        let outputs = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = match frame {
                    Ok(frame) => frame,
                    // After we asked to log off, the server closing the socket is the expected end.
                    Err(_) if closing => return Ok(()),
                    Err(e) => return Err(SessionError::new(ErrorKind::Disconnected, format!("connection lost: {e}"))),
                };
                stage.process(&mut image, action, &payload).map_err(|e| session_error("processing server data", &e))?
            }
            message = input.recv() => {
                let Some(message) = message else {
                    // The front end went away: log off politely.
                    let outputs = stage.graceful_shutdown().map_err(|e| session_error("shutdown", &e))?;
                    write_outputs_only(&mut writer, outputs).await?;
                    return Ok(());
                };
                match message {
                    SessionInput::Close => {
                        closing = true;
                        stage.graceful_shutdown().map_err(|e| session_error("shutdown", &e))?
                    }
                    SessionInput::Resize { width, height } => {
                        let (w, h) = MonitorLayoutEntry::adjust_display_size(u32::from(width), u32::from(height));
                        match stage.encode_resize(w, h, Some(config.scale_factor), None) {
                            Some(frame) => vec![ActiveStageOutput::ResponseFrame(
                                frame.map_err(|e| session_error("resize", &e))?,
                            )],
                            None => {
                                debug!("server does not support dynamic resize (display control channel not open)");
                                Vec::new()
                            }
                        }
                    }
                    SessionInput::Clipboard { text } if !config.clipboard => {
                        debug!(bytes = text.len(), "clipboard sharing is off; local clipboard not sent");
                        Vec::new()
                    }
                    SessionInput::Clipboard { text } if text.len() > MAX_CLIPBOARD_BYTES => {
                        warn!(bytes = text.len(), limit = MAX_CLIPBOARD_BYTES, "local clipboard text too large; not sent");
                        Vec::new()
                    }
                    SessionInput::Clipboard { text } => {
                        if let Ok(mut local) = local_text.lock() {
                            *local = text;
                        }
                        let formats = vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
                        clip_message(&mut stage, ClipboardMessage::SendInitiateCopy(formats))?
                    }
                    SessionInput::Refresh => Vec::new(),
                    other => {
                        let fastpath = translate_input(&mut state, other);
                        if fastpath.is_empty() {
                            Vec::new()
                        } else {
                            stage
                                .process_fastpath_input(&mut image, &fastpath)
                                .map_err(|e| session_error("sending input", &e))?
                        }
                    }
                }
            }
            clip = clip_rx.recv() => {
                match clip {
                    Some(ClipEvent::Message(message)) => clip_message(&mut stage, message)?,
                    Some(ClipEvent::RemoteText(text)) => {
                        let _ = events.send(SessionEvent::Clipboard(text)).await;
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            _ = cleanup.tick() => {
                match stage.get_svc_processor_mut::<CliprdrClient>().map(|c| c.drive_timeouts()) {
                    Some(Ok(messages)) => {
                        let frame = stage
                            .process_svc_processor_messages(messages)
                            .map_err(|e| session_error("clipboard", &e))?;
                        if frame.is_empty() { Vec::new() } else { vec![ActiveStageOutput::ResponseFrame(frame)] }
                    }
                    _ => Vec::new(),
                }
            }
        };

        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => writer
                    .write_all(&frame)
                    .await
                    .map_err(|e| SessionError::new(ErrorKind::Disconnected, format!("connection lost: {e}")))?,
                ActiveStageOutput::GraphicsUpdate(rect) => {
                    if let Some(frame) = frame_event(&image, &rect) {
                        if events.send(frame).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                ActiveStageOutput::PointerDefault => {
                    let _ = events.send(SessionEvent::Cursor(CursorShape::Default)).await;
                }
                ActiveStageOutput::PointerHidden => {
                    let _ = events.send(SessionEvent::Cursor(CursorShape::Hidden)).await;
                }
                ActiveStageOutput::PointerPosition { .. } => {}
                ActiveStageOutput::PointerBitmap(pointer) => {
                    let _ = events
                        .send(SessionEvent::Cursor(CursorShape::Bitmap {
                            width: pointer.width,
                            height: pointer.height,
                            hot_x: pointer.hotspot_x,
                            hot_y: pointer.hotspot_y,
                            rgba: pointer.bitmap_data.clone(),
                        }))
                        .await;
                }
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation: the server is changing the desktop (e.g. resize).
                    debug!("deactivation-reactivation sequence");
                    let mut activation = activation_factory.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = single_sequence_step_read(&mut reader, &mut activation, &mut buf)
                            .await
                            .map_err(|e| connector_error("reactivation", &e))?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await.map_err(|e| {
                                SessionError::new(ErrorKind::Disconnected, format!("connection lost: {e}"))
                            })?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            pointer_software_rendering,
                        } = activation.connection_activation_state()
                        {
                            info!(width = desktop_size.width, height = desktop_size.height, "desktop reactivated");
                            image = desktop_image(desktop_size.width, desktop_size.height)?;
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: activation.io_channel_id(),
                                    user_channel_id: activation.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            let _ = events
                                .send(SessionEvent::Resized {
                                    width: desktop_size.width,
                                    height: desktop_size.height,
                                })
                                .await;
                            break;
                        }
                    }
                }
                ActiveStageOutput::MultitransportRequest(_) | ActiveStageOutput::AutoDetect(_) => {}
                ActiveStageOutput::Terminate(reason) => {
                    info!(%reason, "session terminated");
                    return Ok(());
                }
            }
        }
    }
}

async fn write_outputs_only<W: ironrdp_tokio::FramedWrite>(
    writer: &mut W,
    outputs: Vec<ActiveStageOutput>,
) -> Result<(), SessionError> {
    for output in outputs {
        if let ActiveStageOutput::ResponseFrame(frame) = output {
            let _ = writer.write_all(&frame).await;
        }
    }
    Ok(())
}

fn clip_message(stage: &mut ActiveStage, message: ClipboardMessage) -> Result<Vec<ActiveStageOutput>, SessionError> {
    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else {
        return Ok(Vec::new());
    };
    let result = match message {
        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
        ClipboardMessage::SendFormatData(response) => cliprdr.submit_format_data(response),
        ClipboardMessage::SendInitiatePaste(format) => cliprdr.initiate_paste(format),
        ClipboardMessage::Error(error) => {
            warn!(%error, "clipboard backend error");
            return Ok(Vec::new());
        }
        // File transfer is not implemented.
        _ => return Ok(Vec::new()),
    };
    match result {
        Ok(messages) => {
            let frame = stage
                .process_svc_processor_messages(messages)
                .map_err(|e| session_error("clipboard", &e))?;
            Ok(vec![ActiveStageOutput::ResponseFrame(frame)])
        }
        Err(error) => {
            // Clipboard trouble must never take the session down.
            warn!(%error, "clipboard operation failed");
            Ok(Vec::new())
        }
    }
}

/// Copy one updated rectangle out of the decoded image as tightly packed opaque RGBA.
fn frame_event(image: &DecodedImage, rect: &InclusiveRectangle) -> Option<SessionEvent> {
    let (iw, ih) = (image.width(), image.height());
    if iw == 0 || ih == 0 || rect.left >= iw || rect.top >= ih {
        return None;
    }
    let right = rect.right.min(iw - 1);
    let bottom = rect.bottom.min(ih - 1);
    if right < rect.left || bottom < rect.top {
        return None;
    }
    let w = right - rect.left + 1;
    let h = bottom - rect.top + 1;
    let stride = image.stride();
    let data = image.data();
    let row_bytes = usize::from(w) * 4;
    let mut rgba = Vec::with_capacity(row_bytes * usize::from(h));
    for row in rect.top..=bottom {
        let start = usize::from(row) * stride + usize::from(rect.left) * 4;
        rgba.extend_from_slice(data.get(start..start + row_bytes)?);
    }
    for pixel in rgba.as_chunks_mut::<4>().0 {
        pixel[3] = 255;
    }
    Some(SessionEvent::Frame {
        x: rect.left,
        y: rect.top,
        w,
        h,
        rgba,
    })
}

fn translate_input(state: &mut InputState, message: SessionInput) -> Vec<FastPathInputEvent> {
    let mut ops: Vec<Operation> = Vec::new();
    match message {
        SessionInput::PointerMove { x, y } => ops.push(Operation::MouseMove(MousePosition { x, y })),
        SessionInput::PointerButton { button, down, x, y } => {
            let button = match button {
                MouseButton::Left => RdpButton::Left,
                MouseButton::Middle => RdpButton::Middle,
                MouseButton::Right => RdpButton::Right,
                MouseButton::Back => RdpButton::X1,
                MouseButton::Forward => RdpButton::X2,
            };
            ops.push(Operation::MouseMove(MousePosition { x, y }));
            ops.push(if down {
                Operation::MouseButtonPressed(button)
            } else {
                Operation::MouseButtonReleased(button)
            });
        }
        SessionInput::Wheel { dx, dy, x, y } => {
            ops.push(Operation::MouseMove(MousePosition { x, y }));
            state.wheel.0 += dy * 120.0;
            state.wheel.1 += dx * 120.0;
            // Send whole units, keep the remainder; clamp to what one RDP wheel event can carry.
            let vertical = state.wheel.0.trunc().clamp(-255.0, 255.0);
            if vertical != 0.0 {
                state.wheel.0 -= vertical;
                ops.push(Operation::WheelRotations(WheelRotations {
                    is_vertical: true,
                    rotation_units: vertical as i16,
                }));
            }
            let horizontal = state.wheel.1.trunc().clamp(-255.0, 255.0);
            if horizontal != 0.0 {
                state.wheel.1 -= horizontal;
                ops.push(Operation::WheelRotations(WheelRotations {
                    is_vertical: false,
                    rotation_units: horizontal as i16,
                }));
            }
        }
        SessionInput::Key { code, key, down } => {
            if let Some(scancode) = keymap::scancode(&code) {
                ops.push(if down {
                    Operation::KeyPressed(scancode)
                } else {
                    Operation::KeyReleased(scancode)
                });
            } else {
                // No physical key known (IME, unusual layout): send the character itself.
                let mut chars = key.chars();
                if let (Some(ch), None) = (chars.next(), chars.next()) {
                    ops.push(if down {
                        Operation::UnicodeKeyPressed(ch)
                    } else {
                        Operation::UnicodeKeyReleased(ch)
                    });
                } else {
                    debug!(%code, "key has no RDP scancode; ignored");
                }
            }
        }
        SessionInput::ReleaseAll => return state.db.release_all().into_vec(),
        SessionInput::Clipboard { .. } | SessionInput::Resize { .. } | SessionInput::Refresh | SessionInput::Close => {}
    }
    state.db.apply(ops).into_vec()
}

// ── Errors ───────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        let inner_text = inner.to_string();
        if !text.contains(&inner_text) {
            text.push_str(": ");
            text.push_str(&inner_text);
        }
        source = inner.source();
    }
    text
}

fn connector_error(stage: &str, error: &ConnectorError) -> SessionError {
    let detail = format!("{stage}: {}", chain(error));
    let lower = detail.to_lowercase();
    let kind = match error.kind() {
        ConnectorErrorKind::AccessDenied | ConnectorErrorKind::Credssp(_) => ErrorKind::AuthFailed,
        ConnectorErrorKind::Negotiation(_) => ErrorKind::Unsupported,
        _ if lower.contains("logon") || lower.contains("access denied") || lower.contains("credential") => {
            ErrorKind::AuthFailed
        }
        // With NLA a wrong password usually shows up as the server hanging up mid-handshake.
        _ if lower.contains("eof") || lower.contains("reset") || lower.contains("broken pipe") => {
            ErrorKind::Disconnected
        }
        _ => ErrorKind::Protocol,
    };
    SessionError::new(kind, detail)
}

fn session_error(stage: &str, error: &RdpSessionError) -> SessionError {
    SessionError::new(ErrorKind::Protocol, format!("{stage}: {}", chain(error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(nla: bool) -> RdpConfig {
        RdpConfig {
            host: "pc.example".to_owned(),
            port: 3389,
            username: "user".to_owned(),
            password: "secret".to_owned().into(),
            domain: None,
            width: 1024,
            height: 768,
            scale_factor: 100,
            pinned_cert_sha256: None,
            nla,
            clipboard: false,
        }
    }

    fn requested_protocol(nla: bool) -> SecurityProtocol {
        let (clip_tx, _clip_rx) = mpsc::unbounded_channel();
        let local_text = Arc::new(Mutex::new(String::new()));
        let addr = SocketAddr::from(([127, 0, 0, 1], 50000));
        let mut connector = build_connector(&test_config(nla), addr, &clip_tx, &local_text).unwrap();
        let mut buf = WriteBuf::new();
        connector.step_no_input(&mut buf).unwrap();
        let X224(request) = ironrdp_core::decode::<X224<ironrdp_pdu::nego::ConnectionRequest>>(buf.filled()).unwrap();
        request.protocol
    }

    #[test]
    fn nla_connection_request_does_not_offer_plain_tls() {
        assert_eq!(requested_protocol(true), SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX);
    }

    #[test]
    fn non_nla_connection_request_offers_only_tls() {
        assert_eq!(requested_protocol(false), SecurityProtocol::SSL);
    }

    #[test]
    fn nla_downgrade_is_a_security_error() {
        assert!(check_nla_selected(SecurityProtocol::HYBRID).is_ok());
        assert!(check_nla_selected(SecurityProtocol::HYBRID_EX).is_ok());
        for selected in [SecurityProtocol::SSL, SecurityProtocol::empty()] {
            assert_eq!(check_nla_selected(selected).unwrap_err().kind, ErrorKind::Security);
        }
    }

    #[test]
    fn plaintext_leftover_before_tls_is_refused() {
        assert!(check_no_plaintext_leftover(&[]).is_ok());
        assert_eq!(check_no_plaintext_leftover(&[0x16, 3, 3]).unwrap_err().kind, ErrorKind::Security);
    }

    #[test]
    fn oversized_desktop_is_refused_before_allocating() {
        assert!(desktop_image(1920, 1080).is_ok());
        assert!(check_desktop_size(MAX_DESKTOP_SIDE, MAX_DESKTOP_SIDE).is_ok());
        for (w, h) in [(MAX_DESKTOP_SIDE + 1, 600), (800, u16::MAX), (u16::MAX, u16::MAX)] {
            let error = check_desktop_size(w, h).expect_err("must be refused");
            assert!(desktop_image(w, h).is_err());
            assert_eq!(error.kind, ErrorKind::Protocol);
        }
    }
}
