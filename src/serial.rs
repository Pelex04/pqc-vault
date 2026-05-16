//! Key serialisation — export and import key material securely.
//!
//! Raw key bytes can be exported and later restored. When persisting to disk,
//! use `EncryptedKeyBundle` which wraps keys in AES-256-GCM authenticated
//! encryption with a key derived from a passphrase via Argon2id.
//!
//! # Quick start
//!
//! ```rust
//! use pqc_vault::{SecurityLevel, kem::KemKeyPair};
//! use pqc_vault::serial::EncryptedKeyBundle;
//!
//! let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
//!
//! // Encrypt and serialise to JSON
//! let bundle = EncryptedKeyBundle::seal_kem(&kp, b"strong-passphrase").unwrap();
//! let json = bundle.to_json();
//!
//! // Later: restore
//! let bundle2 = EncryptedKeyBundle::from_json(&json).unwrap();
//! let restored = bundle2.unseal_kem(b"strong-passphrase").unwrap();
//! ```

use crate::dsa::DsaKeyPair;
use crate::kem::KemKeyPair;
use crate::{
    error::{PqcError, Result},
    SecurityLevel,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ── Raw key export ────────────────────────────────────────────────────────────

/// Exported bytes of a KEM key pair. Secret key is Zeroizing — wiped on drop.
pub struct KemKeyData {
    pub level: SecurityLevel,
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

impl KemKeyData {
    /// Restore a `KemKeyPair` from exported key data.
    pub fn into_keypair(self) -> Result<KemKeyPair> {
        KemKeyPair::from_bytes(self.level, &self.public_key, &self.secret_key)
    }
}

/// Exported bytes of a DSA key pair. Secret key is Zeroizing — wiped on drop.
pub struct DsaKeyData {
    pub level: SecurityLevel,
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

impl DsaKeyData {
    /// Restore a `DsaKeyPair` from exported key data.
    pub fn into_keypair(self) -> Result<DsaKeyPair> {
        DsaKeyPair::from_bytes(self.level, &self.public_key, &self.secret_key)
    }
}

// ── Encrypted key bundle ──────────────────────────────────────────────────────

/// Serialisable form of an encrypted key bundle.
/// Uses serde for robust JSON parsing — no hand-rolled string search.
#[derive(Serialize, Deserialize, Debug)]
struct BundleJson {
    kind: String,
    level: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// AES-256-GCM encrypted key bundle safe to write to disk.
///
/// Key material is encrypted using a key derived from a passphrase via
/// Argon2id (memory-hard KDF). The bundle includes the Argon2 salt and
/// AES nonce — only the passphrase is secret.
///
/// Serialises to/from JSON via serde_json.
///
/// # Argon2id parameters
///
/// Memory: 64 MB, iterations: 3, parallelism: 1.
///
/// Parallelism is set to 1 for portability across single-core environments.
/// This reduces offline attack resistance relative to the OWASP recommended
/// p=4, because a single-threaded attacker benefits proportionally. The
/// memory and iteration parameters still exceed OWASP minimums. For
/// deployments where offline attack resistance is critical, increase p to 4
/// and update the Params below.
pub struct EncryptedKeyBundle {
    inner: BundleJson,
}

impl EncryptedKeyBundle {
    /// Seal a KEM key pair into an encrypted bundle.
    pub fn seal_kem(kp: &KemKeyPair, passphrase: &[u8]) -> Result<Self> {
        let data = kp.export()?;
        let plaintext = encode_kem_plaintext(&data);
        let (salt, nonce, ct) = encrypt(&plaintext, passphrase)?;
        Ok(Self {
            inner: BundleJson {
                kind: "kem".into(),
                level: level_to_u8(data.level),
                salt,
                nonce,
                ciphertext: ct,
            },
        })
    }

    /// Seal a DSA key pair into an encrypted bundle.
    pub fn seal_dsa(kp: &DsaKeyPair, passphrase: &[u8]) -> Result<Self> {
        let data = kp.export()?;
        let plaintext = encode_dsa_plaintext(&data);
        let (salt, nonce, ct) = encrypt(&plaintext, passphrase)?;
        Ok(Self {
            inner: BundleJson {
                kind: "dsa".into(),
                level: level_to_u8(data.level),
                salt,
                nonce,
                ciphertext: ct,
            },
        })
    }

    /// Decrypt and restore a KEM key pair.
    pub fn unseal_kem(&self, passphrase: &[u8]) -> Result<KemKeyPair> {
        if self.inner.kind != "kem" {
            return Err(PqcError::Other("Bundle is not a KEM key".into()));
        }
        let level = u8_to_level(self.inner.level)?;
        let plaintext = decrypt(&self.inner, passphrase)?;
        decode_kem_plaintext(level, &plaintext)?.into_keypair()
    }

    /// Decrypt and restore a DSA key pair.
    pub fn unseal_dsa(&self, passphrase: &[u8]) -> Result<DsaKeyPair> {
        if self.inner.kind != "dsa" {
            return Err(PqcError::Other("Bundle is not a DSA key".into()));
        }
        let level = u8_to_level(self.inner.level)?;
        let plaintext = decrypt(&self.inner, passphrase)?;
        decode_dsa_plaintext(level, &plaintext)?.into_keypair()
    }

    /// Serialise to JSON string via serde_json.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.inner).expect("BundleJson is always serialisable")
    }

    /// Deserialise from JSON string via serde_json.
    pub fn from_json(s: &str) -> Result<Self> {
        let inner: BundleJson = serde_json::from_str(s)
            .map_err(|e| PqcError::Other(format!("Invalid bundle JSON: {}", e)))?;
        Ok(Self { inner })
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn encrypt(plaintext: &Zeroizing<Vec<u8>>, passphrase: &[u8]) -> Result<(String, String, String)> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let aes_key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| PqcError::Other("Encryption failed".into()))?;

    Ok((hex::encode(salt), hex::encode(nonce), hex::encode(ct)))
}

fn decrypt(bundle: &BundleJson, passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let salt =
        hex::decode(&bundle.salt).map_err(|_| PqcError::Other("Invalid salt encoding".into()))?;
    let nonce =
        hex::decode(&bundle.nonce).map_err(|_| PqcError::Other("Invalid nonce encoding".into()))?;
    let ct = hex::decode(&bundle.ciphertext)
        .map_err(|_| PqcError::Other("Invalid ciphertext encoding".into()))?;

    let aes_key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| {
            PqcError::Other("Decryption failed — wrong passphrase or corrupted bundle".into())
        })?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Argon2id — OWASP-compliant parameters.
    // p=1 for portability; see EncryptedKeyBundle doc comment for the tradeoff.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| PqcError::Other("Argon2 params error".into()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| PqcError::Other("Argon2 KDF failed".into()))?;
    Ok(key)
}

// ── Key encoding ──────────────────────────────────────────────────────────────

fn encode_kem_plaintext(data: &KemKeyData) -> Zeroizing<Vec<u8>> {
    let pk = &data.public_key;
    let sk = &*data.secret_key;
    let mut buf = Zeroizing::new(Vec::with_capacity(4 + pk.len() + sk.len()));
    buf.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    buf.extend_from_slice(pk);
    buf.extend_from_slice(sk);
    buf
}

fn decode_kem_plaintext(level: SecurityLevel, data: &[u8]) -> Result<KemKeyData> {
    if data.len() < 4 {
        return Err(PqcError::Other("Truncated key data".into()));
    }
    let pk_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() < 4 + pk_len {
        return Err(PqcError::Other("Truncated public key".into()));
    }
    Ok(KemKeyData {
        level,
        public_key: data[4..4 + pk_len].to_vec(),
        secret_key: Zeroizing::new(data[4 + pk_len..].to_vec()),
    })
}

fn encode_dsa_plaintext(data: &DsaKeyData) -> Zeroizing<Vec<u8>> {
    let pk = &data.public_key;
    let sk = &*data.secret_key;
    let mut buf = Zeroizing::new(Vec::with_capacity(4 + pk.len() + sk.len()));
    buf.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    buf.extend_from_slice(pk);
    buf.extend_from_slice(sk);
    buf
}

fn decode_dsa_plaintext(level: SecurityLevel, data: &[u8]) -> Result<DsaKeyData> {
    if data.len() < 4 {
        return Err(PqcError::Other("Truncated key data".into()));
    }
    let pk_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() < 4 + pk_len {
        return Err(PqcError::Other("Truncated public key".into()));
    }
    Ok(DsaKeyData {
        level,
        public_key: data[4..4 + pk_len].to_vec(),
        secret_key: Zeroizing::new(data[4 + pk_len..].to_vec()),
    })
}

// ── Level conversions ─────────────────────────────────────────────────────────

fn level_to_u8(level: SecurityLevel) -> u8 {
    match level {
        SecurityLevel::Level1 => 1,
        SecurityLevel::Level3 => 3,
        SecurityLevel::Level5 => 5,
    }
}

fn u8_to_level(n: u8) -> Result<SecurityLevel> {
    match n {
        1 => Ok(SecurityLevel::Level1),
        3 => Ok(SecurityLevel::Level3),
        5 => Ok(SecurityLevel::Level5),
        _ => Err(PqcError::Other(format!("Unknown security level: {}", n))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_export_import_roundtrip() {
        let original = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let orig_pub = original.public_key();
        let data = original.export().unwrap();
        let restored = data.into_keypair().unwrap();
        assert_eq!(orig_pub.as_bytes(), restored.public_key().as_bytes());
        let (ct, bob) = KemKeyPair::encapsulate(&restored.public_key()).unwrap();
        let alice = restored.decapsulate(&ct).unwrap();
        assert_eq!(alice.as_bytes(), bob.as_bytes());
    }

    #[test]
    fn test_dsa_export_import_roundtrip() {
        let original = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let orig_pub = original.public_key();
        let data = original.export().unwrap();
        let restored = data.into_keypair().unwrap();
        let msg = b"serialisation test";
        let sig = restored.sign(msg).unwrap();
        DsaKeyPair::verify_with_typed_key(&orig_pub, msg, &sig).unwrap();
    }

    #[test]
    fn test_encrypted_bundle_kem_roundtrip() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let orig_pub = kp.public_key();
        let bundle = EncryptedKeyBundle::seal_kem(&kp, b"test-passphrase-123").unwrap();
        let json = bundle.to_json();
        let restored = EncryptedKeyBundle::from_json(&json)
            .unwrap()
            .unseal_kem(b"test-passphrase-123")
            .unwrap();
        assert_eq!(orig_pub.as_bytes(), restored.public_key().as_bytes());
    }

    #[test]
    fn test_encrypted_bundle_dsa_roundtrip() {
        let kp = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let msg = b"encrypted dsa test";
        let sig = kp.sign(msg).unwrap();
        let bundle = EncryptedKeyBundle::seal_dsa(&kp, b"test-passphrase-456").unwrap();
        let restored = EncryptedKeyBundle::from_json(&bundle.to_json())
            .unwrap()
            .unseal_dsa(b"test-passphrase-456")
            .unwrap();
        DsaKeyPair::verify_with_typed_key(&restored.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let bundle = EncryptedKeyBundle::seal_kem(&kp, b"correct").unwrap();
        assert!(EncryptedKeyBundle::from_json(&bundle.to_json())
            .unwrap()
            .unseal_kem(b"wrong")
            .is_err());
    }

    #[test]
    fn test_all_levels_serialise() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level3,
            SecurityLevel::Level5,
        ] {
            let kp = KemKeyPair::generate(level).unwrap();
            let restored = EncryptedKeyBundle::from_json(
                &EncryptedKeyBundle::seal_kem(&kp, b"level-test")
                    .unwrap()
                    .to_json(),
            )
            .unwrap()
            .unseal_kem(b"level-test")
            .unwrap();
            assert_eq!(kp.public_key().as_bytes(), restored.public_key().as_bytes());
        }
    }

    #[test]
    fn test_serde_json_roundtrip() {
        // Ensure serde_json serialisation is symmetric
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let bundle = EncryptedKeyBundle::seal_kem(&kp, b"serde-test").unwrap();
        let json = bundle.to_json();
        // Verify it's valid JSON by parsing it again
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("kind").is_some());
        assert!(parsed.get("salt").is_some());
        assert!(parsed.get("nonce").is_some());
        assert!(parsed.get("ciphertext").is_some());
    }
}
