use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;

/// Verifies the server's leaf certificate by exact byte match against a
/// single pinned cert, instead of chain-building against a CA and checking
/// certificate lifetime policy.
///
/// Carbonio CE's default self-signed certificate (5 year validity) is
/// rejected by both rustls-webpki and macOS's Security.framework because it
/// exceeds the CA/Browser Forum's ~825-day maximum leaf validity, even when
/// the CA itself is explicitly trusted. For a known, specific internal host
/// whose certificate we have out-of-band (copied directly off the server),
/// pinning the exact cert bytes is a stronger -- not weaker -- check than
/// chain validation: it only accepts that one certificate, cryptographic
/// identity confirmed by exact match, rather than "any cert this CA signed".
#[derive(Debug)]
pub struct PinnedCertVerifier {
    pinned_der: Vec<u8>,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    pub fn from_pem_file(path: &str) -> Result<Arc<dyn ServerCertVerifier>> {
        let pem_bytes = std::fs::read(path).with_context(|| format!("failed to read pinned cert at {path}"))?;
        let mut reader = std::io::BufReader::new(pem_bytes.as_slice());
        let der = rustls_pemfile::certs(&mut reader)
            .next()
            .context("no certificate found in PEM file")?
            .context("failed to parse pinned certificate PEM")?;
        Ok(Arc::new(Self {
            pinned_der: der.to_vec(),
            supported_algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }))
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned Carbonio certificate".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_cert_that_does_not_match_the_pin() {
        let verifier = PinnedCertVerifier {
            pinned_der: vec![1, 2, 3, 4],
            supported_algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let other_cert = CertificateDer::from(vec![9, 9, 9, 9]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result = verifier.verify_server_cert(&other_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_err());
    }

    #[test]
    fn accepts_a_cert_that_matches_the_pin_exactly() {
        let verifier = PinnedCertVerifier {
            pinned_der: vec![1, 2, 3, 4],
            supported_algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let matching_cert = CertificateDer::from(vec![1, 2, 3, 4]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result = verifier.verify_server_cert(&matching_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());
    }
}
