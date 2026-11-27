//! TLS for RDP.
//!
//! RDP hosts present self-signed certificates, so there is no chain to verify: trust comes from
//! pinning the certificate's SHA-256 (done by the caller, before any credentials are sent). That
//! pin is only meaningful if the server proves it holds the certificate's private key, so unlike
//! `ironrdp_tls::upgrade` (whose verifier accepts any handshake signature) this verifier checks
//! the TLS 1.2 / 1.3 handshake signature against the presented certificate.
//!
//! No key log is configured: `SSLKEYLOGFILE` is deliberately not honoured.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{self, CryptoProvider, WebPkiSupportedAlgorithms};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, DigitallySignedStruct, SignatureScheme};
use tracing::debug;

pub(crate) type TlsStream<S> = tokio_rustls::client::TlsStream<S>;

/// Accepts any certificate (the caller pins it) but requires a valid handshake signature made with
/// that certificate's key.
#[derive(Debug)]
struct PinnedByCaller {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedByCaller {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Self-signed by design; the SHA-256 pin is compared once the handshake has completed and
        // before anything is written to the connection.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinnedByCaller {
        algorithms: provider.signature_verification_algorithms,
    });
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider) as Arc<CryptoProvider>)
        // Windows RDP servers commonly offer only TLS 1.2; rustls supports no older version.
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // CredSSP does not support TLS session resumption (MS-CSSP 3.1.5).
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Perform the TLS handshake. Returns the stream and the server's end-entity certificate (DER).
pub(crate) async fn upgrade<S>(stream: S, host: &str) -> io::Result<(TlsStream<S>, CertificateDer<'static>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = client_config().map_err(io::Error::other)?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(sni_name(host), stream)
        .await?;
    tls.flush().await?;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| io::Error::other("the server presented no certificate"))?
        .clone()
        .into_owned();
    Ok((tls, cert))
}

/// TLS version and cipher suite, for the log.
pub(crate) fn negotiated<S>(tls: &TlsStream<S>) -> (Option<rustls::ProtocolVersion>, Option<rustls::CipherSuite>) {
    let connection = tls.get_ref().1;
    (
        connection.protocol_version(),
        connection.negotiated_cipher_suite().map(|suite| suite.suite()),
    )
}

/// The name sent for SNI. A host that is not a valid DNS name or IP address (e.g. a NetBIOS name
/// with an underscore) still gets a TLS connection; certificates are pinned by fingerprint, never
/// matched against names, so any host name (a MagicDNS name included) works. SNI carries no
/// trailing dot (RFC 6066), so a fully qualified "name." is sent without it.
fn sni_name(host: &str) -> ServerName<'static> {
    let name = host.strip_suffix('.').unwrap_or(host);
    ServerName::try_from(name.to_owned()).unwrap_or_else(|_| {
        debug!(%host, "host is not a valid TLS server name; using a placeholder for SNI");
        ServerName::try_from("rdp-server").expect("static name is valid")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_are_sent_as_given() {
        for host in ["studio-mac.example.ts.net", "Studio-Mac.example.ts.net", "pc.local"] {
            assert!(matches!(sni_name(host), ServerName::DnsName(ref n) if n.as_ref() == host), "{host}");
        }
        let fqdn = sni_name("studio-mac.example.ts.net.");
        assert!(matches!(fqdn, ServerName::DnsName(ref n) if n.as_ref() == "studio-mac.example.ts.net"));
        assert!(matches!(sni_name("100.64.0.2"), ServerName::IpAddress(_)));
        assert!(matches!(sni_name("Office PC"),ServerName::DnsName(ref n) if n.as_ref() == "rdp-server"));
    }
}
