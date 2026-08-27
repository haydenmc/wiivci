//! The certificate chain (`title.cert`).
//!
//! The chain contains Nintendo's real public CA/CP/XS certificates and signatures. It is
//! identical across all retail titles and required for installation, but it is genuinely
//! Nintendo's data, so — like the keys and the base title — it is **user-supplied** rather
//! than bundled. Any dumped Wii U title provides a `title.cert`; the user passes it in.
//!
//! This module validates a supplied chain and passes it through unchanged.

use std::path::Path;

use crate::error::{Error, Result};

/// Size of a standard retail Wii U certificate chain.
pub const EXPECTED_CERT_LEN: usize = 0xA00; // 2560

const ROOT_CA_ISSUER: &[u8] = b"Root-CA00000003";

/// A validated certificate chain, ready to write as `title.cert`.
pub struct CertChain(pub Vec<u8>);

impl CertChain {
    /// Load and validate a certificate chain from a file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        Self::from_bytes(bytes)
    }

    /// Validate raw certificate-chain bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != EXPECTED_CERT_LEN {
            return Err(Error::UnsupportedDisc(format!(
                "certificate chain has unexpected size {} (expected {EXPECTED_CERT_LEN})",
                bytes.len()
            )));
        }
        // The first cert's signature type must be a known RSA type, and the chain must
        // contain the Root-CA00000003 issuer somewhere.
        let sig_type = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if !matches!(sig_type, 0x0001_0000..=0x0001_0005) {
            return Err(Error::UnsupportedDisc(format!(
                "certificate chain has unexpected signature type {sig_type:#x}"
            )));
        }
        if !bytes
            .windows(ROOT_CA_ISSUER.len())
            .any(|w| w == ROOT_CA_ISSUER)
        {
            return Err(Error::UnsupportedDisc(
                "certificate chain does not contain the Root-CA00000003 issuer".into(),
            ));
        }
        Ok(CertChain(bytes))
    }

    /// The raw certificate-chain bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_size() {
        assert!(CertChain::from_bytes(vec![0u8; 100]).is_err());
    }

    #[test]
    fn accepts_reference_cert() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref/title.cert");
        if !path.exists() {
            eprintln!(
                "skipping accepts_reference_cert: {} not present",
                path.display()
            );
            return;
        }
        let chain = CertChain::load(&path).expect("load reference cert");
        assert_eq!(chain.as_bytes().len(), EXPECTED_CERT_LEN);
    }
}
