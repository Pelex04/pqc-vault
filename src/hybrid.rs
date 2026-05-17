//! Hybrid key exchange: X25519 + ML-KEM (Kyber).
//!
//! Combines classical Diffie-Hellman (X25519) with post-quantum KEM (Kyber).
//! The resulting shared secret is secure against both classical and quantum
//! attackers — an adversary must break both X25519 and Kyber to recover it.
//!
//! # Combiner
//!
//! ```text
//! prk    = HKDF-Extract(salt=None, ikm = x25519_shared || kyber_shared)
//! output = HKDF-Expand(prk, info = b"pqc_vault hybrid v1", len = 32)
//! ```
//!
//! Follows IETF draft-ietf-tls-hybrid-design and NIST SP 800-227.
//!
//! # Serialisation
//!
//! `HybridCiphertext` implements `to_hex()` and `from_hex()` so it can be
//! transmitted between processes and machines. Format:
//!
//! ```text
//! <x25519_pub_hex (64 chars)><kyber_ct_hex (variable)>
//! ```
//!
//! The X25519 component is always 32 bytes (64 hex chars), so the split
//! is unambiguous without a length prefix.

use crate::kem::KemKeyPair;
use crate::kem::KemPublicKey;
use crate::{
    error::{PqcError, Result},
    SecurityLevel,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const HKDF_INFO: &[u8] = b"pqc_vault hybrid v1";
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// A hybrid X25519 + Kyber public key. Share with the other party.
pub struct HybridPublicKey {
    pub(crate) x25519: X25519PublicKey,
    pub(crate) kyber: KemPublicKey,
}

impl HybridPublicKey {
    /// X25519 component bytes (32 bytes).
    pub fn x25519_bytes(&self) -> &[u8] {
        self.x25519.as_bytes()
    }
    /// Kyber component.
    pub fn kyber_key(&self) -> &KemPublicKey {
        &self.kyber
    }
}

/// The ciphertext from a hybrid encapsulation.
///
/// Serialises to/from hex so it can be transmitted between processes and machines.
pub struct HybridCiphertext {
    /// Bob's ephemeral X25519 public key (32 bytes)
    x25519_ephemeral: X25519PublicKey,
    /// Kyber ciphertext
    kyber_ct: Vec<u8>,
}

impl HybridCiphertext {
    /// Encode the ciphertext as a hex string for transmission.
    ///
    /// Format: `<x25519_ephemeral_hex (64 chars)><kyber_ct_hex>`
    /// The X25519 component is always 32 bytes, so the boundary is fixed.
    pub fn to_hex(&self) -> String {
        format!(
            "{}{}",
            hex::encode(self.x25519_ephemeral.as_bytes()),
            hex::encode(&self.kyber_ct)
        )
    }

    /// Decode a ciphertext from a hex string produced by `to_hex()`.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim())
            .map_err(|_| PqcError::InvalidCiphertext("Invalid hex in HybridCiphertext".into()))?;
        if bytes.len() <= X25519_PUBLIC_KEY_LEN {
            return Err(PqcError::InvalidCiphertext(
                "HybridCiphertext too short — missing Kyber component".into(),
            ));
        }
        let x25519_bytes: [u8; X25519_PUBLIC_KEY_LEN] =
            bytes[..X25519_PUBLIC_KEY_LEN]
                .try_into()
                .map_err(|_| PqcError::InvalidCiphertext("Invalid X25519 component".into()))?;
        let kyber_ct = bytes[X25519_PUBLIC_KEY_LEN..].to_vec();
        Ok(HybridCiphertext {
            x25519_ephemeral: X25519PublicKey::from(x25519_bytes),
            kyber_ct,
        })
    }

    /// Length of the ciphertext in bytes.
    pub fn len(&self) -> usize {
        X25519_PUBLIC_KEY_LEN + self.kyber_ct.len()
    }

    /// Returns true if the ciphertext is empty (should never happen in practice).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A hybrid X25519 + Kyber key pair.
pub struct HybridKeyPair {
    x25519_secret: Zeroizing<[u8; 32]>,
    x25519_public: X25519PublicKey,
    kyber: KemKeyPair,
}

impl HybridKeyPair {
    /// Generate a fresh hybrid key pair using OS entropy.
    pub fn generate(level: SecurityLevel) -> Result<Self> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let secret_bytes = Zeroizing::new(*secret.as_bytes());
        let kyber = KemKeyPair::generate(level)?;
        Ok(HybridKeyPair {
            x25519_secret: secret_bytes,
            x25519_public: public,
            kyber,
        })
    }

    /// Returns the combined public key. X25519 public key was stored at
    /// generation time — no secret key reconstruction occurs here.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519: self.x25519_public,
            kyber: self.kyber.public_key(),
        }
    }

    /// Encapsulate to a remote hybrid public key.
    ///
    /// Returns `(ciphertext, shared_secret)`. The ciphertext can be
    /// serialised with `.to_hex()` and sent to the key pair holder.
    /// The shared secret is derived via HKDF with domain separation.
    pub fn encapsulate(
        remote_pub: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, Zeroizing<Vec<u8>>)> {
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral);
        let x25519_shared = ephemeral.diffie_hellman(&remote_pub.x25519);
        let (kyber_ct, kyber_shared) = KemKeyPair::encapsulate(&remote_pub.kyber)?;
        let combined = combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;
        Ok((
            HybridCiphertext {
                x25519_ephemeral: ephemeral_pub,
                kyber_ct,
            },
            combined,
        ))
    }

    /// Decapsulate a hybrid ciphertext. Returns the shared secret.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<Zeroizing<Vec<u8>>> {
        let static_secret = StaticSecret::from(*self.x25519_secret);
        let x25519_shared = static_secret.diffie_hellman(&ct.x25519_ephemeral);
        let kyber_shared = self.kyber.decapsulate(&ct.kyber_ct)?;
        combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())
    }

    /// Security level of the Kyber component.
    pub fn security_level(&self) -> SecurityLevel {
        self.kyber.security_level()
    }
}

fn combine_secrets(x25519: &[u8], kyber: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x25519.len() + kyber.len()));
    ikm.extend_from_slice(x25519);
    ikm.extend_from_slice(kyber);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(HKDF_INFO, &mut output)
        .map_err(|_| PqcError::Other("HKDF expand failed".into()))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(level: SecurityLevel) {
        let alice = HybridKeyPair::generate(level).unwrap();
        let (ct, bob) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let alice_s = alice.decapsulate(&ct).unwrap();
        assert_eq!(alice_s.as_slice(), bob.as_slice());
    }

    #[test]
    fn test_hybrid_level1() {
        roundtrip(SecurityLevel::Level1);
    }
    #[test]
    fn test_hybrid_level3() {
        roundtrip(SecurityLevel::Level3);
    }
    #[test]
    fn test_hybrid_level5() {
        roundtrip(SecurityLevel::Level5);
    }

    #[test]
    fn test_ciphertext_hex_roundtrip() {
        // Encapsulate, serialise the ciphertext to hex, deserialise, then
        // decapsulate — and assert the recovered secret matches what Bob got.
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct_original, bob_secret) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();

        // Serialise to hex (simulates network/file transmission)
        let hex = ct_original.to_hex();
        assert!(
            hex.len() > 64,
            "hex must include X25519 (64 chars) + Kyber components"
        );

        // Deserialise
        let ct_restored = HybridCiphertext::from_hex(&hex).unwrap();

        // Decapsulate from the restored ciphertext — must recover Bob's secret
        let alice_secret = alice.decapsulate(&ct_restored).unwrap();
        assert_eq!(
            alice_secret.as_slice(),
            bob_secret.as_slice(),
            "Secret recovered from deserialised ciphertext must match original"
        );
    }

    #[test]
    fn test_ciphertext_cross_process_simulation() {
        // Simulate: Alice generates keys, Bob encapsulates on a different machine,
        // sends ciphertext as hex string, Alice decapsulates.
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let alice_pub = alice.public_key();

        // Bob's side: encapsulate and serialise
        let (ct_bob, bob_secret) = HybridKeyPair::encapsulate(&alice_pub).unwrap();
        let ct_hex = ct_bob.to_hex(); // This string can be sent over the network

        // Alice's side: deserialise and decapsulate
        let ct_alice = HybridCiphertext::from_hex(&ct_hex).unwrap();
        let alice_secret = alice.decapsulate(&ct_alice).unwrap();

        assert_eq!(
            alice_secret.as_slice(),
            bob_secret.as_slice(),
            "Cross-process hybrid exchange must produce matching secrets"
        );
    }

    #[test]
    fn test_hybrid_secret_is_32_bytes() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, secret) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(alice.decapsulate(&ct).unwrap().len(), 32);
    }

    #[test]
    fn test_wrong_key_gives_different_secret() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let eve = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, _) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let alice_s = alice.decapsulate(&ct).unwrap();
        let eve_s = eve
            .decapsulate(&ct)
            .unwrap_or(Zeroizing::new(vec![0u8; 32]));
        assert_ne!(alice_s.as_slice(), eve_s.as_slice());
    }

    #[test]
    fn test_two_encapsulations_give_different_secrets() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (_, s1) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let (_, s2) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        assert_ne!(s1.as_slice(), s2.as_slice());
    }

    #[test]
    fn test_public_key_no_reconstruction() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk1 = alice.public_key();
        let pk2 = alice.public_key();
        assert_eq!(pk1.x25519_bytes(), pk2.x25519_bytes());
    }

    #[test]
    fn test_invalid_hex_rejected() {
        assert!(HybridCiphertext::from_hex("not-valid-hex").is_err());
        assert!(HybridCiphertext::from_hex("deadbeef").is_err()); // too short
    }
}
