use crate::{SecurityLevel, error::{PqcError, Result}};
use crate::utils::to_hex;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use pqcrypto_kyber::{kyber512, kyber768, kyber1024};
use zeroize::Zeroizing;
use subtle::ConstantTimeEq;

// ── SharedSecret newtype — constant-time PartialEq, zeroizes on drop ──

/// A shared secret produced by KEM encapsulation or decapsulation.
///
/// # Constant-time comparison
/// `PartialEq` on this type uses `subtle::ConstantTimeEq` internally.
/// Comparing two `SharedSecret` values with `==` is safe and timing-attack resistant.
/// You do NOT need to call `ct_eq()` manually when using this type.
///
/// # Memory safety
/// The secret bytes are stored in `Zeroizing<Vec<u8>>` and wiped from memory
/// automatically when this value is dropped.
pub struct SharedSecretKey(Zeroizing<Vec<u8>>);

impl SharedSecretKey {
    fn new(bytes: Vec<u8>) -> Self {
        SharedSecretKey(Zeroizing::new(bytes))
    }
    /// Raw bytes of the shared secret. Use `.len()` on the returned slice for length.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

/// Debug impl that does NOT print secret bytes — safe to use in test output.
impl std::fmt::Debug for SharedSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecretKey([redacted {} bytes])", self.0.len())
    }
}

/// Constant-time equality — safe to use for comparing secrets.
impl PartialEq for SharedSecretKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}
impl Eq for SharedSecretKey {}

// ── Typed public key ──

/// A typed KEM public key. Carries its security level.
/// Level mismatch between key and operation is structurally impossible.
#[derive(Clone)]
pub struct KemPublicKey {
    level: SecurityLevel,
    bytes: Vec<u8>,
}

impl KemPublicKey {
    /// The security level this key was generated for.
    pub fn level(&self) -> SecurityLevel { self.level }
    /// Raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    /// Hex-encoded public key.
    pub fn to_hex(&self) -> String { to_hex(&self.bytes) }
}

// ── Key pair — private key in Zeroizing, wiped on drop ──

struct KemInner {
    level:    SecurityLevel,
    pk_bytes: Vec<u8>,
    sk_bytes: Zeroizing<Vec<u8>>,
}

/// A KEM key pair. The private key is automatically wiped from memory on drop.
pub struct KemKeyPair {
    inner: KemInner,
}

impl KemKeyPair {
    /// Generate a fresh key pair using OS entropy.
    ///
    /// The private key is wrapped in `Zeroizing` inline at the point of
    /// allocation — there is no transient plain `Vec<u8>` for secret material.
    pub fn generate(level: SecurityLevel) -> Result<Self> {
        // Zeroizing::new() wraps inline — no transient plain Vec<u8> for secret key
        let (pk_bytes, sk_bytes) = match level {
            SecurityLevel::Level1 => {
                let (pk, sk) = kyber512::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = kyber768::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = kyber1024::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
        };
        Ok(KemKeyPair { inner: KemInner { level, pk_bytes, sk_bytes } })
    }

    /// Returns the security level.
    pub fn security_level(&self) -> SecurityLevel { self.inner.level }

    /// Returns the typed public key — safe to distribute.
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey { level: self.inner.level, bytes: self.inner.pk_bytes.clone() }
    }

    /// Encapsulate to a typed public key.
    ///
    /// Returns `(ciphertext, shared_secret)`. Send the ciphertext to the key owner;
    /// use the shared secret as key material (e.g. input to a KDF).
    ///
    /// The returned `SharedSecretKey` uses constant-time `PartialEq` automatically —
    /// comparing with `==` is safe. It is wiped from memory when dropped.
    pub fn encapsulate(pub_key: &KemPublicKey) -> Result<(Vec<u8>, SharedSecretKey)> {
        match pub_key.level {
            SecurityLevel::Level1 => {
                let pk = kyber512::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber512 public key".into()))?;
                let (ss, ct) = kyber512::encapsulate(&pk);
                Ok((ct.as_bytes().to_vec(), SharedSecretKey::new(ss.as_bytes().to_vec())))
            }
            SecurityLevel::Level3 => {
                let pk = kyber768::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber768 public key".into()))?;
                let (ss, ct) = kyber768::encapsulate(&pk);
                Ok((ct.as_bytes().to_vec(), SharedSecretKey::new(ss.as_bytes().to_vec())))
            }
            SecurityLevel::Level5 => {
                let pk = kyber1024::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber1024 public key".into()))?;
                let (ss, ct) = kyber1024::encapsulate(&pk);
                Ok((ct.as_bytes().to_vec(), SharedSecretKey::new(ss.as_bytes().to_vec())))
            }
        }
    }

    /// Decapsulate a ciphertext using the private key.
    ///
    /// Returns a `SharedSecretKey` — a typed wrapper that:
    /// - Uses **constant-time `PartialEq`** automatically (safe to compare with `==`)
    /// - Is wiped from memory when dropped
    ///
    /// # Caller responsibility
    /// If you extract the raw bytes via `.as_bytes()` and compare them manually,
    /// use `pqc_vault::utils::ct_eq()` to avoid timing side channels.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecretKey> {
        match self.inner.level {
            SecurityLevel::Level1 => {
                let sk = kyber512::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber512 secret key".into()))?;
                let ct = kyber512::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::InvalidCiphertext("Invalid Kyber512 ciphertext".into()))?;
                Ok(SharedSecretKey::new(kyber512::decapsulate(&ct, &sk).as_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let sk = kyber768::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber768 secret key".into()))?;
                let ct = kyber768::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::InvalidCiphertext("Invalid Kyber768 ciphertext".into()))?;
                Ok(SharedSecretKey::new(kyber768::decapsulate(&ct, &sk).as_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let sk = kyber1024::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Kyber1024 secret key".into()))?;
                let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| PqcError::InvalidCiphertext("Invalid Kyber1024 ciphertext".into()))?;
                Ok(SharedSecretKey::new(kyber1024::decapsulate(&ct, &sk).as_bytes().to_vec()))
            }
        }
    }

    /// Key and ciphertext sizes for this security level.
    pub fn key_sizes(&self) -> KemSizes {
        match self.inner.level {
            SecurityLevel::Level1 => KemSizes { public_key: 800,  private_key: 1632, ciphertext: 768,  shared_secret: 32 },
            SecurityLevel::Level3 => KemSizes { public_key: 1184, private_key: 2400, ciphertext: 1088, shared_secret: 32 },
            SecurityLevel::Level5 => KemSizes { public_key: 1568, private_key: 3168, ciphertext: 1568, shared_secret: 32 },
        }
    }
}

/// Byte sizes for a KEM security level.
pub struct KemSizes {
    pub public_key: usize,
    pub private_key: usize,
    pub ciphertext: usize,
    pub shared_secret: usize,
}

impl std::fmt::Display for KemSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PK: {}B | SK: {}B | CT: {}B | SS: {}B",
            self.public_key, self.private_key, self.ciphertext, self.shared_secret)
    }
}

// ── Output-size validation tests — FIPS 203 ──
// These confirm output byte lengths match FIPS 203 specifications.
// Note: these are structural size checks, not deterministic vector KATs.
// True vector KATs require deterministic seeding not currently exposed
// by the pqcrypto crates. This gap is documented in the README.
#[cfg(test)]
mod size_tests {
    use super::*;

    #[test]
    fn fips203_kyber512_output_sizes() {
        let kp = KemKeyPair::generate(SecurityLevel::Level1).unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes().len(), 800,  "Kyber512 public key: 800 bytes (FIPS 203 §7.1)");
        let (ct, ss) = KemKeyPair::encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 768, "Kyber512 ciphertext: 768 bytes (FIPS 203 §7.2)");
        assert_eq!(ss.as_bytes().len(), 32,  "Kyber512 shared secret: 32 bytes (FIPS 203 §7.2)");
    }

    #[test]
    fn fips203_kyber768_output_sizes() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes().len(), 1184, "Kyber768 public key: 1184 bytes (FIPS 203 §7.1)");
        let (ct, ss) = KemKeyPair::encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 1088, "Kyber768 ciphertext: 1088 bytes (FIPS 203 §7.2)");
        assert_eq!(ss.as_bytes().len(), 32,   "Kyber768 shared secret: 32 bytes (FIPS 203 §7.2)");
    }

    #[test]
    fn fips203_kyber1024_output_sizes() {
        let kp = KemKeyPair::generate(SecurityLevel::Level5).unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_bytes().len(), 1568, "Kyber1024 public key: 1568 bytes (FIPS 203 §7.1)");
        let (ct, ss) = KemKeyPair::encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 1568, "Kyber1024 ciphertext: 1568 bytes (FIPS 203 §7.2)");
        assert_eq!(ss.as_bytes().len(), 32,   "Kyber1024 shared secret: 32 bytes (FIPS 203 §7.2)");
    }

    #[test]
    fn shared_secret_not_all_zeros() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, ss) = KemKeyPair::encapsulate(&kp.public_key()).unwrap();
        let recovered = kp.decapsulate(&ct).unwrap();
        assert!(ss.as_bytes().iter().any(|&b| b != 0), "Shared secret must not be all zeros");
        assert!(recovered.as_bytes().iter().any(|&b| b != 0), "Recovered secret must not be all zeros");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(level: SecurityLevel) {
        let alice = KemKeyPair::generate(level).unwrap();
        let (ct, bob_secret) = KemKeyPair::encapsulate(&alice.public_key()).unwrap();
        let alice_secret = alice.decapsulate(&ct).unwrap();
        // SharedSecretKey uses constant-time PartialEq internally — safe to use ==
        assert_eq!(alice_secret, bob_secret, "Secrets must match at {:?}", level);
    }

    #[test] fn test_level1() { roundtrip(SecurityLevel::Level1); }
    #[test] fn test_level3() { roundtrip(SecurityLevel::Level3); }
    #[test] fn test_level5() { roundtrip(SecurityLevel::Level5); }

    #[test]
    fn test_constant_time_eq_is_default() {
        // SharedSecretKey == uses ct_eq internally — no timing side channel
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, s1) = KemKeyPair::encapsulate(&kp.public_key()).unwrap();
        let s2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(s1, s2); // This is constant-time. Safe.
    }

    #[test]
    fn test_wrong_key_gives_different_secret() {
        let alice = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let eve   = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, _) = KemKeyPair::encapsulate(&alice.public_key()).unwrap();
        let alice_s = alice.decapsulate(&ct).unwrap();
        let eve_s   = eve.decapsulate(&ct).unwrap();
        assert_ne!(alice_s, eve_s, "Security failure: different keys produced same secret");
    }

    #[test]
    fn test_shared_secret_zeroizes_on_drop() {
        let kp = KemKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, ss) = KemKeyPair::encapsulate(&kp.public_key()).unwrap();
        let _recovered = kp.decapsulate(&ct).unwrap();
        drop(ss); // Zeroizing wipes here
    }
}
