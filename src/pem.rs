//! PEM encoding for public keys.
//!
//! Exports and imports public keys in PEM format — the standard used by
//! OpenSSL, TLS certificates, SSH, and most cryptographic tooling.
//! Private keys are intentionally not exported to PEM; use
//! `EncryptedKeyBundle` for private key persistence.
//!
//! # Format
//!
//! KEM public keys are wrapped as:
//! ```text
//! -----BEGIN ML-KEM PUBLIC KEY-----
//! <base64>
//! -----END ML-KEM PUBLIC KEY-----
//! ```
//!
//! DSA public keys are wrapped as:
//! ```text
//! -----BEGIN ML-DSA PUBLIC KEY-----
//! <base64>
//! -----END ML-DSA PUBLIC KEY-----
//! ```
//!
//! Each PEM block includes a header line identifying the algorithm and
//! security level so the file is self-describing.

use crate::dsa::DsaPublicKey;
use crate::kem::KemPublicKey;
use crate::{
    error::{PqcError, Result},
    SecurityLevel,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

const KEM_LABEL: &str = "ML-KEM PUBLIC KEY";
const DSA_LABEL: &str = "ML-DSA PUBLIC KEY";

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode a KEM public key as PEM.
pub fn kem_public_key_to_pem(key: &KemPublicKey) -> String {
    let header = format!(
        "Algorithm: {}; Level: {}",
        "ML-KEM",
        level_name(key.level())
    );
    encode_pem(KEM_LABEL, &header, key.as_bytes())
}

/// Encode a DSA public key as PEM.
pub fn dsa_public_key_to_pem(key: &DsaPublicKey) -> String {
    let header = format!(
        "Algorithm: {}; Level: {}",
        "ML-DSA",
        level_name(key.level())
    );
    encode_pem(DSA_LABEL, &header, key.as_bytes())
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode a KEM public key from PEM.
pub fn kem_public_key_from_pem(pem: &str) -> Result<KemPublicKey> {
    let (level, bytes) = decode_pem(pem, KEM_LABEL)?;
    Ok(KemPublicKey::from_raw(level, bytes))
}

/// Decode a DSA public key from PEM.
pub fn dsa_public_key_from_pem(pem: &str) -> Result<DsaPublicKey> {
    let (level, bytes) = decode_pem(pem, DSA_LABEL)?;
    Ok(DsaPublicKey::from_raw(level, bytes))
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn encode_pem(label: &str, header: &str, data: &[u8]) -> String {
    let b64 = BASE64.encode(data);
    // Wrap base64 at 64 characters per line (PEM standard)
    let wrapped = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "-----BEGIN {}-----\n{}\n{}\n-----END {}-----\n",
        label, header, wrapped, label
    )
}

fn decode_pem(pem: &str, expected_label: &str) -> Result<(SecurityLevel, Vec<u8>)> {
    let begin = format!("-----BEGIN {}-----", expected_label);
    let end = format!("-----END {}-----", expected_label);

    let start = pem
        .find(&begin)
        .ok_or_else(|| PqcError::Other(format!("Missing PEM header: {}", begin)))?;
    let finish = pem
        .find(&end)
        .ok_or_else(|| PqcError::Other(format!("Missing PEM footer: {}", end)))?;

    let body = &pem[start + begin.len()..finish];
    let mut lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if lines.is_empty() {
        return Err(PqcError::Other("Empty PEM body".into()));
    }

    // First line is the header — extract level
    let header_line = lines.remove(0);
    let level = parse_level_from_header(header_line)?;

    // Remaining lines are base64
    let b64: String = lines.join("");
    let bytes = BASE64
        .decode(&b64)
        .map_err(|_| PqcError::Other("Invalid base64 in PEM body".into()))?;

    Ok((level, bytes))
}

fn parse_level_from_header(header: &str) -> Result<SecurityLevel> {
    // Header format: "Algorithm: ML-KEM; Level: Level3"
    if header.contains("Level1") {
        return Ok(SecurityLevel::Level1);
    }
    if header.contains("Level3") {
        return Ok(SecurityLevel::Level3);
    }
    if header.contains("Level5") {
        return Ok(SecurityLevel::Level5);
    }
    Err(PqcError::Other(format!(
        "Cannot parse security level from PEM header: {}",
        header
    )))
}

fn level_name(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Level1 => "Level1",
        SecurityLevel::Level3 => "Level3",
        SecurityLevel::Level5 => "Level5",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::DsaKeyPair;
    use crate::kem::KemKeyPair;

    #[test]
    fn test_kem_pem_roundtrip() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level3,
            SecurityLevel::Level5,
        ] {
            let kp = KemKeyPair::generate(level).unwrap();
            let pk = kp.public_key();
            let pem = kem_public_key_to_pem(&pk);

            assert!(pem.contains("-----BEGIN ML-KEM PUBLIC KEY-----"));
            assert!(pem.contains("-----END ML-KEM PUBLIC KEY-----"));

            let restored = kem_public_key_from_pem(&pem).unwrap();
            assert_eq!(
                pk.as_bytes(),
                restored.as_bytes(),
                "KEM public key must survive PEM roundtrip at {:?}",
                level
            );
            assert_eq!(pk.level(), restored.level());
        }
    }

    #[test]
    fn test_dsa_pem_roundtrip() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level3,
            SecurityLevel::Level5,
        ] {
            let kp = DsaKeyPair::generate(level).unwrap();
            let pk = kp.public_key();
            let pem = dsa_public_key_to_pem(&pk);

            assert!(pem.contains("-----BEGIN ML-DSA PUBLIC KEY-----"));
            assert!(pem.contains("-----END ML-DSA PUBLIC KEY-----"));

            let restored = dsa_public_key_from_pem(&pem).unwrap();
            assert_eq!(
                pk.as_bytes(),
                restored.as_bytes(),
                "DSA public key must survive PEM roundtrip at {:?}",
                level
            );
            assert_eq!(pk.level(), restored.level());
        }
    }

    #[test]
    fn test_pem_verify_with_restored_key() {
        let kp = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pem = dsa_public_key_to_pem(&kp.public_key());
        let msg = b"verify after PEM round-trip";
        let sig = kp.sign(msg).unwrap();

        let restored_pk = dsa_public_key_from_pem(&pem).unwrap();
        DsaKeyPair::verify_with_typed_key(&restored_pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_wrong_label_rejected() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pem = kem_public_key_to_pem(&kp.public_key());
        // Try to parse KEM PEM as DSA
        assert!(dsa_public_key_from_pem(&pem).is_err());
    }
}
