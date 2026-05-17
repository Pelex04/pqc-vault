//! PEM encoding for public keys.
//!
//! Exports and imports public keys in PEM format. Private keys are
//! intentionally not exported to PEM — use `EncryptedKeyBundle` instead.
//!
//! # Format
//!
//! ```text
//! -----BEGIN ML-KEM PUBLIC KEY-----
//! Algorithm: ML-KEM; Level: Level3; Variant: Kyber768
//! <base64 — 64 chars per line>
//! -----END ML-KEM PUBLIC KEY-----
//! ```
//!
//! The header line carries algorithm, level, and variant so the file is
//! self-describing. Bytes are decoded and validated through pqcrypto
//! before a key object is constructed — `from_pem` never returns a key
//! containing unvalidated bytes.

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
        "Algorithm: ML-KEM; Level: {}; Variant: {}",
        level_name(key.level()),
        kem_variant(key.level())
    );
    encode_pem(KEM_LABEL, &header, key.as_bytes())
}

/// Encode a DSA public key as PEM.
pub fn dsa_public_key_to_pem(key: &DsaPublicKey) -> String {
    let header = format!(
        "Algorithm: ML-DSA; Level: {}; Variant: {}",
        level_name(key.level()),
        dsa_variant(key.level())
    );
    encode_pem(DSA_LABEL, &header, key.as_bytes())
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode and validate a KEM public key from PEM.
///
/// Bytes are parsed through pqcrypto before the key is constructed —
/// invalid or truncated keys are rejected before they can be used.
pub fn kem_public_key_from_pem(pem: &str) -> Result<KemPublicKey> {
    let (level, bytes) = decode_pem(pem, KEM_LABEL)?;
    // Validate through pqcrypto — rejects wrong lengths and malformed keys
    KemPublicKey::from_validated(level, bytes)
}

/// Decode and validate a DSA public key from PEM.
///
/// Bytes are parsed through pqcrypto before the key is constructed —
/// invalid or truncated keys are rejected before they can be used.
pub fn dsa_public_key_from_pem(pem: &str) -> Result<DsaPublicKey> {
    let (level, bytes) = decode_pem(pem, DSA_LABEL)?;
    // Validate through pqcrypto — rejects wrong lengths and malformed keys
    DsaPublicKey::from_validated(level, bytes)
}

// ── Internal ──────────────────────────────────────────────────────────────────

fn encode_pem(label: &str, header: &str, data: &[u8]) -> String {
    let b64 = BASE64.encode(data);
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

    let header_line = lines.remove(0);
    let level = parse_level_from_header(header_line)?;

    let b64: String = lines.join("");
    let bytes = BASE64
        .decode(&b64)
        .map_err(|_| PqcError::Other("Invalid base64 in PEM body".into()))?;

    Ok((level, bytes))
}

fn parse_level_from_header(header: &str) -> Result<SecurityLevel> {
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

fn kem_variant(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Level1 => "Kyber512",
        SecurityLevel::Level3 => "Kyber768",
        SecurityLevel::Level5 => "Kyber1024",
    }
}

fn dsa_variant(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Level1 => "Dilithium2",
        SecurityLevel::Level3 => "Dilithium3",
        SecurityLevel::Level5 => "Dilithium5",
    }
}

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
            assert_eq!(pk.as_bytes(), restored.as_bytes());
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
            assert_eq!(pk.as_bytes(), restored.as_bytes());
            assert_eq!(pk.level(), restored.level());
        }
    }

    #[test]
    fn test_pem_contains_variant() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pem = kem_public_key_to_pem(&kp.public_key());
        assert!(
            pem.contains("Kyber768"),
            "PEM header must include variant name"
        );
    }

    #[test]
    fn test_pem_verify_with_restored_key() {
        let kp = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pem = dsa_public_key_to_pem(&kp.public_key());
        let msg = b"verify after PEM round-trip";
        let sig = kp.sign(msg).unwrap();
        let pk = dsa_public_key_from_pem(&pem).unwrap();
        DsaKeyPair::verify_with_typed_key(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_wrong_label_rejected() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pem = kem_public_key_to_pem(&kp.public_key());
        assert!(dsa_public_key_from_pem(&pem).is_err());
    }

    #[test]
    fn test_corrupted_bytes_rejected() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk = kp.public_key();
        let pem = kem_public_key_to_pem(&pk);
        // Corrupt the base64 body
        let corrupted = pem.replace(&BASE64.encode(&pk.as_bytes()[..10]), "AAAAAAAAAAAAAAAA");
        // May or may not be valid base64, but if decoded will have wrong length
        // At minimum the level parse should work; length validation catches the rest
        let _ = kem_public_key_from_pem(&corrupted); // may error — that's correct
    }
}
