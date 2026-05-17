//! Key serialisation — export and import key material securely.
//!
//! Use `EncryptedKeyBundle` to persist key pairs to disk. Keys are encrypted
//! with AES-256-GCM using a key derived from a passphrase via Argon2id.
//!
//! # Quick start
//!
//! ```rust
//! use pqc_vault::{SecurityLevel, kem::KemKeyPair};
//! use pqc_vault::serial::EncryptedKeyBundle;
//!
//! let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
//!
//! let bundle = EncryptedKeyBundle::seal_kem(&kp, b"strong-passphrase").unwrap();
//! let json = bundle.to_json();
//!
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

/// Exported bytes of a KEM key pair.
///
/// The secret key field is private — access via `into_keypair()` only.
/// This prevents callers from accidentally logging or transmitting secret bytes.
pub struct KemKeyData {
    pub level: SecurityLevel,
    pub public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

impl KemKeyData {
    pub(crate) fn new(
        level: SecurityLevel,
        public_key: Vec<u8>,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            level,
            public_key,
            secret_key,
        }
    }
    /// Restore a `KemKeyPair` from exported key data.
    pub fn into_keypair(self) -> Result<KemKeyPair> {
        KemKeyPair::from_bytes(self.level, &self.public_key, &self.secret_key)
    }
}

/// Exported bytes of a DSA key pair.
///
/// The secret key field is private — access via `into_keypair()` only.
pub struct DsaKeyData {
    pub level: SecurityLevel,
    pub public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

impl DsaKeyData {
    pub(crate) fn new(
        level: SecurityLevel,
        public_key: Vec<u8>,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            level,
            public_key,
            secret_key,
        }
    }
    /// Restore a `DsaKeyPair` from exported key data.
    pub fn into_keypair(self) -> Result<DsaKeyPair> {
        DsaKeyPair::from_bytes(self.level, &self.public_key, &self.secret_key)
    }
}

// ── Encrypted key bundle ──────────────────────────────────────────────────────

/// Versioned JSON bundle format — enables forward-compatible format changes.
#[derive(Serialize, Deserialize, Debug)]
struct BundleJson {
    /// Bundle format version. Currently 1.
    version: u8,
    /// "kem" or "dsa"
    kind: String,
    /// Security level: 1, 3, or 5
    level: u8,
    /// Argon2id salt (16 bytes, hex-encoded)
    salt: String,
    /// AES-GCM nonce (12 bytes, hex-encoded)
    nonce: String,
    /// Encrypted key bytes (hex-encoded ciphertext + GCM tag)
    ciphertext: String,
}

const BUNDLE_VERSION: u8 = 1;

/// AES-256-GCM encrypted key bundle safe to write to disk.
///
/// # Argon2id parameters
///
/// Memory: 64 MB, iterations: 3, parallelism: 4.
///
/// These meet OWASP recommendations (m=64MB, t=3, p=4). Parallelism is set
/// to 4 following the OWASP default. Derivation takes approximately 0.5–1s
/// on a modern machine, which is intentional — it raises the cost of
/// offline dictionary attacks proportionally.
///
/// # Bundle format
///
/// JSON with a `version` field for forward compatibility. Version 1 uses
/// AES-256-GCM + Argon2id with the parameters above.
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
                version: BUNDLE_VERSION,
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
                version: BUNDLE_VERSION,
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
        if self.inner.version != BUNDLE_VERSION {
            return Err(PqcError::Other(format!(
                "Unsupported bundle version: {}. Expected {}.",
                self.inner.version, BUNDLE_VERSION
            )));
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
        if self.inner.version != BUNDLE_VERSION {
            return Err(PqcError::Other(format!(
                "Unsupported bundle version: {}. Expected {}.",
                self.inner.version, BUNDLE_VERSION
            )));
        }
        let level = u8_to_level(self.inner.level)?;
        let plaintext = decrypt(&self.inner, passphrase)?;
        decode_dsa_plaintext(level, &plaintext)?.into_keypair()
    }

    /// Serialise to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.inner).expect("BundleJson is always serialisable")
    }

    /// Deserialise from JSON string.
    pub fn from_json(s: &str) -> Result<Self> {
        let inner: BundleJson = serde_json::from_str(s)
            .map_err(|e| PqcError::Other(format!("Invalid bundle JSON: {}", e)))?;
        Ok(Self { inner })
    }

    /// Returns the bundle format version.
    pub fn version(&self) -> u8 {
        self.inner.version
    }
    /// Returns the kind: "kem" or "dsa".
    pub fn kind(&self) -> &str {
        &self.inner.kind
    }
    /// Returns the security level.
    pub fn level(&self) -> u8 {
        self.inner.level
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
    // Argon2id — OWASP recommended parameters: m=64MB, t=3, p=4.
    // See EncryptedKeyBundle doc comment for rationale.
    let params = Params::new(64 * 1024, 3, 4, Some(32))
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
    Ok(KemKeyData::new(
        level,
        data[4..4 + pk_len].to_vec(),
        Zeroizing::new(data[4 + pk_len..].to_vec()),
    ))
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
    Ok(DsaKeyData::new(
        level,
        data[4..4 + pk_len].to_vec(),
        Zeroizing::new(data[4 + pk_len..].to_vec()),
    ))
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
        assert_eq!(bundle.version(), 1);
        assert_eq!(bundle.kind(), "kem");
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
    fn test_bundle_has_version_field() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let bundle = EncryptedKeyBundle::seal_kem(&kp, b"version-test").unwrap();
        let json = bundle.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], 1, "Bundle must include version field");
        assert!(parsed.get("kind").is_some());
        assert!(parsed.get("salt").is_some());
        assert!(parsed.get("nonce").is_some());
        assert!(parsed.get("ciphertext").is_some());
    }

    #[test]
    fn test_wrong_bundle_kind_rejected() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let bundle = EncryptedKeyBundle::seal_kem(&kp, b"kind-test").unwrap();
        assert!(
            EncryptedKeyBundle::from_json(&bundle.to_json())
                .unwrap()
                .unseal_dsa(b"kind-test")
                .is_err(),
            "KEM bundle must be rejected by unseal_dsa"
        );
    }
}
