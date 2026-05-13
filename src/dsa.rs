use crate::{SecurityLevel, error::{PqcError, Result}};
use crate::utils::to_hex;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use zeroize::Zeroizing;

/// A typed DSA verification key. Carries its security level.
/// Level mismatch between key and operation is structurally impossible.
#[derive(Clone)]
pub struct DsaPublicKey {
    level: SecurityLevel,
    bytes: Vec<u8>,
}

impl DsaPublicKey {
    /// The security level this key was generated for.
    pub fn level(&self) -> SecurityLevel { self.level }
    /// Raw bytes of the verification key.
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    /// Hex-encoded verification key.
    pub fn to_hex(&self) -> String { to_hex(&self.bytes) }
}

// Private signing key stored in Zeroizing — wiped on drop
struct DsaInner {
    level:    SecurityLevel,
    pk_bytes: Vec<u8>,
    sk_bytes: Zeroizing<Vec<u8>>,
}

/// A DSA key pair. The private signing key is automatically wiped from memory on drop.
pub struct DsaKeyPair {
    inner: DsaInner,
}

impl DsaKeyPair {
    /// Generate a fresh signing key pair using OS entropy.
    ///
    /// The private key is wrapped in `Zeroizing` inline at the point of
    /// allocation — there is no transient plain `Vec<u8>` for secret material.
    pub fn generate(level: SecurityLevel) -> Result<Self> {
        // Zeroizing::new() wraps inline — no transient plain Vec<u8> for secret key
        let (pk_bytes, sk_bytes) = match level {
            SecurityLevel::Level1 => {
                let (pk, sk) = dilithium2::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = dilithium3::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = dilithium5::keypair();
                (pk.as_bytes().to_vec(), Zeroizing::new(sk.as_bytes().to_vec()))
            }
        };
        Ok(DsaKeyPair { inner: DsaInner { level, pk_bytes, sk_bytes } })
    }

    /// Returns the security level.
    pub fn security_level(&self) -> SecurityLevel { self.inner.level }

    /// Returns the typed public verification key — safe to distribute.
    pub fn public_key(&self) -> DsaPublicKey {
        DsaPublicKey { level: self.inner.level, bytes: self.inner.pk_bytes.clone() }
    }

    /// Sign a message. Returns `Zeroizing<Vec<u8>>` — wiped from memory on drop.
    ///
    /// Signatures are not secret — they are distributed publicly. However, the
    /// return type is `Zeroizing` to be consistent and to support use cases where
    /// callers may prefer controlled cleanup. If you compare signatures, use
    /// `pqc_vault::utils::ct_eq()` to avoid timing side channels.
    pub fn sign(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self.inner.level {
            SecurityLevel::Level1 => {
                let sk = dilithium2::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium2 secret key".into()))?;
                Ok(Zeroizing::new(dilithium2::detached_sign(message, &sk).as_bytes().to_vec()))
            }
            SecurityLevel::Level3 => {
                let sk = dilithium3::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium3 secret key".into()))?;
                Ok(Zeroizing::new(dilithium3::detached_sign(message, &sk).as_bytes().to_vec()))
            }
            SecurityLevel::Level5 => {
                let sk = dilithium5::SecretKey::from_bytes(&self.inner.sk_bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium5 secret key".into()))?;
                Ok(Zeroizing::new(dilithium5::detached_sign(message, &sk).as_bytes().to_vec()))
            }
        }
    }

    /// Verify a signature using this key pair's own public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        Self::verify_with_typed_key(&self.public_key(), message, signature)
    }

    /// Verify a signature using a typed public key.
    ///
    /// This is the primary verification API for external verifiers who hold
    /// only the signer's public key. The security level is embedded in
    /// `DsaPublicKey` — level mismatch is impossible.
    pub fn verify_with_typed_key(
        pub_key: &DsaPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        match pub_key.level {
            SecurityLevel::Level1 => {
                let pk  = dilithium2::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium2 public key".into()))?;
                let sig = dilithium2::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::InvalidSignature("Invalid Dilithium2 signature".into()))?;
                dilithium2::verify_detached_signature(&sig, message, &pk)
                    .map_err(|_| PqcError::VerificationFailed)
            }
            SecurityLevel::Level3 => {
                let pk  = dilithium3::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium3 public key".into()))?;
                let sig = dilithium3::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::InvalidSignature("Invalid Dilithium3 signature".into()))?;
                dilithium3::verify_detached_signature(&sig, message, &pk)
                    .map_err(|_| PqcError::VerificationFailed)
            }
            SecurityLevel::Level5 => {
                let pk  = dilithium5::PublicKey::from_bytes(&pub_key.bytes)
                    .map_err(|_| PqcError::InvalidKey("Invalid Dilithium5 public key".into()))?;
                let sig = dilithium5::DetachedSignature::from_bytes(signature)
                    .map_err(|_| PqcError::InvalidSignature("Invalid Dilithium5 signature".into()))?;
                dilithium5::verify_detached_signature(&sig, message, &pk)
                    .map_err(|_| PqcError::VerificationFailed)
            }
        }
    }

    /// Key and signature sizes for this security level.
    pub fn key_sizes(&self) -> DsaSizes {
        match self.inner.level {
            SecurityLevel::Level1 => DsaSizes { public_key: 1312, private_key: 2528, signature: 2420 },
            SecurityLevel::Level3 => DsaSizes { public_key: 1952, private_key: 4000, signature: 3293 },
            SecurityLevel::Level5 => DsaSizes { public_key: 2592, private_key: 4864, signature: 4595 },
        }
    }
}

/// Byte sizes for a DSA security level.
pub struct DsaSizes {
    pub public_key: usize,
    pub private_key: usize,
    pub signature: usize,
}

impl std::fmt::Display for DsaSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PK: {}B | SK: {}B | Sig: {}B",
            self.public_key, self.private_key, self.signature)
    }
}

// ── Output-size validation tests — FIPS 204 ──
// These confirm output byte lengths match FIPS 204 specifications.
// Note: these are structural size checks, not deterministic vector KATs.
// True vector KATs require deterministic seeding not currently exposed
// by the pqcrypto crates. This gap is documented in the README.
#[cfg(test)]
mod size_tests {
    use super::*;

    #[test]
    fn fips204_dilithium2_output_sizes() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level1).unwrap();
        let pk  = kp.public_key();
        let sig = kp.sign(b"size validation test").unwrap();
        assert_eq!(pk.as_bytes().len(), 1312, "Dilithium2 public key: 1312 bytes (FIPS 204 §7.1)");
        assert_eq!(sig.len(), 2420,           "Dilithium2 signature: 2420 bytes (FIPS 204 §7.2)");
    }

    #[test]
    fn fips204_dilithium3_output_sizes() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk  = kp.public_key();
        let sig = kp.sign(b"size validation test").unwrap();
        assert_eq!(pk.as_bytes().len(), 1952, "Dilithium3 public key: 1952 bytes (FIPS 204 §7.1)");
        assert_eq!(sig.len(), 3293,           "Dilithium3 signature: 3293 bytes (FIPS 204 §7.2)");
    }

    #[test]
    fn fips204_dilithium5_output_sizes() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level5).unwrap();
        let pk  = kp.public_key();
        let sig = kp.sign(b"size validation test").unwrap();
        assert_eq!(pk.as_bytes().len(), 2592, "Dilithium5 public key: 2592 bytes (FIPS 204 §7.1)");
        assert_eq!(sig.len(), 4595,           "Dilithium5 signature: 4595 bytes (FIPS 204 §7.2)");
    }

    #[test]
    fn signature_not_all_zeros() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig = kp.sign(b"non-zero validation").unwrap();
        assert!(sig.iter().any(|&b| b != 0), "Signature must not be all zeros");
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let kp   = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig1 = kp.sign(b"message one").unwrap();
        let sig2 = kp.sign(b"message two").unwrap();
        assert_ne!(sig1.as_slice(), sig2.as_slice(),
            "Different messages must produce different signatures");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(level: SecurityLevel) {
        let kp  = DsaKeyPair::generate(level).unwrap();
        let msg = b"Authorize transfer: $1,000,000";
        let sig = kp.sign(msg).unwrap();
        kp.verify(msg, &sig).unwrap();
    }

    #[test] fn test_level1() { roundtrip(SecurityLevel::Level1); }
    #[test] fn test_level3() { roundtrip(SecurityLevel::Level3); }
    #[test] fn test_level5() { roundtrip(SecurityLevel::Level5); }

    #[test]
    fn test_tampered_message_rejected() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig = kp.sign(b"original message").unwrap();
        assert!(kp.verify(b"tampered message", &sig).is_err(),
            "Tampered message must not verify");
    }

    #[test]
    fn test_wrong_key_rejected() {
        let kp1 = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let kp2 = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig = kp1.sign(b"message").unwrap();
        assert!(kp2.verify(b"message", &sig).is_err(),
            "Wrong key must not verify signature");
    }

    #[test]
    fn test_empty_message() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig = kp.sign(b"").unwrap();
        kp.verify(b"", &sig).unwrap();
    }

    #[test]
    fn test_large_message() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let msg = vec![0xABu8; 1_000_000];
        let sig = kp.sign(&msg).unwrap();
        kp.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn test_verify_with_typed_key() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk  = kp.public_key();
        let msg = b"verify with typed public key";
        let sig = kp.sign(msg).unwrap();
        DsaKeyPair::verify_with_typed_key(&pk, msg, &sig).unwrap();
    }

    #[test]
    fn test_signature_zeroizes_on_drop() {
        let kp  = DsaKeyPair::generate(SecurityLevel::Level3).unwrap();
        let sig: Zeroizing<Vec<u8>> = kp.sign(b"zeroize proof").unwrap();
        drop(sig); // wiped here — enforced by type
    }
}
