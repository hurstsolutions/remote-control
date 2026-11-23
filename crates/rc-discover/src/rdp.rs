//! The name in an RDP server's TLS certificate.
//!
//! Windows presents a self-signed certificate whose subject is the computer name (or its FQDN)
//! during the X.224 / TLS negotiation, before any sign-in. We send a minimal X.224 Connection
//! Request asking for TLS or CredSSP, complete the TLS handshake, read the certificate and close.
//! No CredSSP and no credentials: nothing here can lock out an account.
//!
//! The certificate is not verified, because nothing is trusted on the strength of it: the name is
//! only a label and the fingerprint is shown for information. Pinning still happens on the first
//! real connection.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};
use x509_cert::der::{Decode as _, Tag, Tagged as _};

/// PROTOCOL_SSL | PROTOCOL_HYBRID.
const REQUESTED_PROTOCOLS: u32 = 0x0000_0003;

/// What the certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpCertInfo {
    /// Subject CN, or the first DNS name in the subject alternative names.
    pub name: Option<String>,
    /// SHA-256 of the DER certificate, lowercase hex. Information only; never pinned from a scan.
    pub sha256: String,
}

/// The X.224 Connection Request (inside TPKT) with an RDP negotiation request.
pub fn connection_request() -> [u8; 19] {
    let p = REQUESTED_PROTOCOLS.to_le_bytes();
    [
        0x03, 0x00, 0x00, 0x13, // TPKT: version 3, length 19
        0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI 14, CR code, dst-ref, src-ref, class 0
        0x01, 0x00, 0x08, 0x00, p[0], p[1], p[2], p[3], // RDP_NEG_REQ
    ]
}

/// The protocol the server picked from an X.224 Connection Confirm, or None when it refused or
/// does not speak enhanced security at all.
pub fn selected_protocol(confirm: &[u8]) -> Option<u32> {
    // TPKT (4) + LI + code (0xD0) + dst-ref (2) + src-ref (2) + class, then the negotiation response.
    if confirm.len() < 19 || confirm[0] != 0x03 || confirm[5] & 0xF0 != 0xD0 {
        return None;
    }
    let neg = &confirm[11..19];
    if neg[0] != 0x02 {
        return None; // 0x03 is RDP_NEG_FAILURE
    }
    Some(u32::from_le_bytes([neg[4], neg[5], neg[6], neg[7]]))
}

/// Connect-negotiate-handshake on an open connection to an RDP port. Bounded by `limit`.
pub async fn certificate(mut tcp: TcpStream, limit: Duration) -> Option<RdpCertInfo> {
    let work = async {
        tcp.write_all(&connection_request()).await.ok()?;
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header).await.ok()?;
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if header[0] != 0x03 || !(11..=64).contains(&length) {
            return None;
        }
        let mut confirm = vec![0u8; length];
        confirm[..4].copy_from_slice(&header);
        tcp.read_exact(&mut confirm[4..]).await.ok()?;
        let selected = selected_protocol(&confirm)?;
        if selected & REQUESTED_PROTOCOLS == 0 {
            return None; // standard RDP security: no TLS, no certificate
        }
        let connector = tokio_rustls::TlsConnector::from(client_config()?);
        // The name is not checked; any syntactically valid one will do.
        let server_name = ServerName::try_from("rdp-server").ok()?;
        let mut tls = connector.connect(server_name, tcp).await.ok()?;
        let der = tls.get_ref().1.peer_certificates()?.first()?.as_ref().to_vec();
        let _ = tls.shutdown().await;
        Some(cert_info(&der))
    };
    tokio::time::timeout(limit, work).await.ok().flatten()
}

/// Name and fingerprint of a DER certificate. An unparsable certificate still has a fingerprint.
pub fn cert_info(der: &[u8]) -> RdpCertInfo {
    RdpCertInfo {
        name: cert_name(der),
        sha256: hex(&Sha256::digest(der)),
    }
}

fn cert_name(der: &[u8]) -> Option<String> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;
    let cn = tbs
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter(|atv| atv.oid == x509_cert::der::oid::db::rfc4519::CN)
        .find_map(|atv| directory_string(&atv.value));
    if cn.is_some() {
        return cn;
    }
    let (_, san) = tbs.get::<SubjectAltName>().ok()??;
    san.0.iter().find_map(|name| match name {
        GeneralName::DnsName(dns) => Some(dns.as_str().to_owned()),
        _ => None,
    })
}

fn directory_string(value: &x509_cert::der::Any) -> Option<String> {
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
        Tag::BmpString => {
            let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn client_config() -> Option<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ReadOnly(provider)))
        .with_no_client_auth();
    Some(Arc::new(config))
}

/// Accepts any certificate (we only read it), but still checks the handshake signatures so the
/// certificate we read is the one the server holds the key for.
#[derive(Debug)]
struct ReadOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for ReadOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_the_spec() {
        let request = connection_request();
        assert_eq!(usize::from(u16::from_be_bytes([request[2], request[3]])), request.len());
        assert_eq!(usize::from(request[4]) + 5, request.len(), "LI counts the bytes after it");
        assert_eq!(&request[15..], &[3, 0, 0, 0]);
    }

    #[test]
    fn reads_the_confirm() {
        let mut confirm = vec![0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0, 0, 0x12, 0x34, 0x00];
        confirm.extend_from_slice(&[0x02, 0x1F, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(selected_protocol(&confirm), Some(2));
        confirm[11] = 0x03; // failure
        assert_eq!(selected_protocol(&confirm), None);
        assert_eq!(selected_protocol(&confirm[..11]), None);
    }

    #[test]
    fn garbage_certificates_still_get_a_fingerprint() {
        let info = cert_info(b"not a certificate");
        assert_eq!(info.name, None);
        assert_eq!(info.sha256.len(), 64);
    }
}
