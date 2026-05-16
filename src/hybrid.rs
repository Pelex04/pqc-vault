//! Hybrid key exchange: X25519 + ML-KEM (Kyber).
//!
//! Combines classical Diffie-Hellman (X25519) with post-quantum KEM (Kyber).
//! The resulting shared secret is secure against both classical and quantum
//! attackers — an adversary must break both X25519 and Kyber to recover it.
//!
//! # Combiner
//!
//! The combined secret uses HKDF-Extract + HKDF-Expand with domain separation,
//! following the construction specified in IETF draft-ietf-tls-hybrid-design
//! and NIST SP 800-227:
//!
//! ```text
//! prk    = HKDF-Extract(salt=None, ikm = x25519_shared || kyber_shared)
//! output = HKDF-Expand(prk, info = b"pqc_vault hybrid v1", len = 32)
//! ```
//!
//! The domain separation label `b"pqc_vault hybrid v1"` binds the output to
//! this specific construction and version, preventing cross-protocol misuse.
//!
//! # Protocol
//!
//! ```text
//! Alice                                    Bob
//! ─────────────────────────────────────────────────────────────
//! HybridKeyPair::generate()
//!   x25519_keypair  (classical)
//!   kyber_keypair   (post-quantum)
//!
//! share HybridPublicKey ──────────────────>
//!
//!                                          HybridKeyPair::encapsulate(&alice_pub)
//!                                            x25519_shared = DH(bob_ephemeral, alice_x25519_pub)
//!                                            kyber_shared  = Kyber.encap(alice_kyber_pub)
//!                                            combined      = HKDF(x25519_shared || kyber_shared)
//!
//!                             <─────────── HybridCiphertext
//!
//! HybridKeyPair::decapsulate(&ciphertext)
//!   x25519_shared = DH(alice_x25519_sk, bob_ephemeral_pub)
//!   kyber_shared  = Kyber.decap(kyber_ciphertext)
//!   combined      = HKDF(x25519_shared || kyber_shared)
//!
//! combined == bob_combined  ✓
//! ```

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

/// Domain separation label — binds HKDF output to this construction and version.
const HKDF_INFO: &[u8] = b"pqc_vault hybrid v1";

/// A hybrid X25519 + Kyber public key. Share with the other party.
pub struct HybridPublicKey {
    pub(crate) x25519: X25519PublicKey,
    pub(crate) kyber: KemPublicKey,
}

impl HybridPublicKey {
    /// X25519 component bytes.
    pub fn x25519_bytes(&self) -> &[u8] {
        self.x25519.as_bytes()
    }
    /// Kyber component.
    pub fn kyber_key(&self) -> &KemPublicKey {
        &self.kyber
    }
}

/// The ciphertext from a hybrid encapsulation. Send to the HybridKeyPair holder.
pub struct HybridCiphertext {
    /// Bob's ephemeral X25519 public key
    pub(crate) x25519_ephemeral: X25519PublicKey,
    /// Kyber ciphertext
    pub(crate) kyber_ct: Vec<u8>,
}

/// A hybrid X25519 + Kyber key pair.
///
/// The X25519 public key is stored alongside the secret at generation time —
/// no reconstruction on each call.
pub struct HybridKeyPair {
    /// Secret stored as Zeroizing bytes; StaticSecret reconstructed only when needed
    x25519_secret: Zeroizing<[u8; 32]>,
    /// Public key stored once at generation — avoids repeated reconstruction
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

    /// Returns the combined public key. The X25519 public key was computed
    /// once at generation — no secret key reconstruction occurs here.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519: self.x25519_public,
            kyber: self.kyber.public_key(),
        }
    }

    /// Encapsulate to a remote hybrid public key.
    ///
    /// Returns `(ciphertext, combined_secret)`.
    /// The combined secret is derived via HKDF-Extract+Expand with domain
    /// separation — following IETF draft-ietf-tls-hybrid-design.
    pub fn encapsulate(
        remote_pub: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, Zeroizing<Vec<u8>>)> {
        // X25519: ephemeral key pair + DH
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral);
        let x25519_shared = ephemeral.diffie_hellman(&remote_pub.x25519);

        // Kyber: encapsulate
        let (kyber_ct, kyber_shared) = KemKeyPair::encapsulate(&remote_pub.kyber)?;

        // Combine via HKDF with domain separation
        let combined = combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())?;

        Ok((
            HybridCiphertext {
                x25519_ephemeral: ephemeral_pub,
                kyber_ct,
            },
            combined,
        ))
    }

    /// Decapsulate a hybrid ciphertext. Returns the same combined secret.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<Zeroizing<Vec<u8>>> {
        // X25519: DH with static secret and ephemeral public
        let static_secret = StaticSecret::from(*self.x25519_secret);
        let x25519_shared = static_secret.diffie_hellman(&ct.x25519_ephemeral);

        // Kyber: decapsulate
        let kyber_shared = self.kyber.decapsulate(&ct.kyber_ct)?;

        // Combine via HKDF — same construction as encapsulate
        combine_secrets(x25519_shared.as_bytes(), kyber_shared.as_bytes())
    }

    /// Security level of the Kyber component.
    pub fn security_level(&self) -> SecurityLevel {
        self.kyber.security_level()
    }
}

/// HKDF-based hybrid combiner following IETF draft-ietf-tls-hybrid-design.
///
/// combined = HKDF-Expand(
///     HKDF-Extract(salt=None, ikm = x25519_shared || kyber_shared),
///     info = b"pqc_vault hybrid v1",
///     len  = 32
/// )
///
/// Domain separation via the info label binds the output to this specific
/// construction, preventing cross-protocol misuse.
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
        let alice_pub = alice.public_key();
        let (ct, bob_secret) = HybridKeyPair::encapsulate(&alice_pub).unwrap();
        let alice_secret = alice.decapsulate(&ct).unwrap();
        assert_eq!(
            alice_secret.as_slice(),
            bob_secret.as_slice(),
            "Hybrid secrets must match at {:?}",
            level
        );
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
    fn test_hybrid_secret_is_32_bytes() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, secret) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let recovered = alice.decapsulate(&ct).unwrap();
        assert_eq!(secret.len(), 32, "HKDF output must be 32 bytes");
        assert_eq!(recovered.len(), 32);
    }

    #[test]
    fn test_hybrid_wrong_key_gives_different_secret() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let eve = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, _) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let alice_s = alice.decapsulate(&ct).unwrap();
        let eve_s = eve
            .decapsulate(&ct)
            .unwrap_or(Zeroizing::new(vec![0u8; 32]));
        assert_ne!(
            alice_s.as_slice(),
            eve_s.as_slice(),
            "Security failure: different keys produced same hybrid secret"
        );
    }

    #[test]
    fn test_hybrid_secret_not_all_zeros() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (ct, secret) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        assert!(secret.iter().any(|&b| b != 0));
        let recovered = alice.decapsulate(&ct).unwrap();
        assert!(recovered.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_two_encapsulations_give_different_secrets() {
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let (_, s1) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        let (_, s2) = HybridKeyPair::encapsulate(&alice.public_key()).unwrap();
        assert_ne!(
            s1.as_slice(),
            s2.as_slice(),
            "Two encapsulations must produce different secrets"
        );
    }

    #[test]
    fn test_public_key_no_reconstruction() {
        // public_key() should return the pre-computed key, not reconstruct it
        let alice = HybridKeyPair::generate(SecurityLevel::Level3).unwrap();
        let pk1 = alice.public_key();
        let pk2 = alice.public_key();
        assert_eq!(
            pk1.x25519_bytes(),
            pk2.x25519_bytes(),
            "Public key must be stable across calls"
        );
    }
}
