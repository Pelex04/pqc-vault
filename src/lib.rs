//! # PQC Vault v0.9.0
//!
//! Post-quantum cryptography library implementing:
//! - **ML-KEM** (CRYSTALS-Kyber) — NIST FIPS 203 — Key Encapsulation
//! - **ML-DSA** (CRYSTALS-Dilithium) — NIST FIPS 204 — Digital Signatures
//! - **Hybrid X25519 + ML-KEM** — quantum-safe key exchange with classical fallback
//! - **Key serialisation** — encrypted persistence via AES-256-GCM + Argon2id
//! - **PEM format** — standard public key export/import
//!
//! ## What changed in v0.8.0
//!
//! - Added `serial` module: export/import key pairs; `EncryptedKeyBundle` persists
//!   keys to disk encrypted with AES-256-GCM, key derived via Argon2id
//! - Added `pem` module: PEM encode/decode for public keys (ML-KEM and ML-DSA)
//! - Added `hybrid` module: X25519 + Kyber hybrid key exchange — secure against
//!   both classical and quantum attackers simultaneously
//! - Added `KemKeyPair::export()`, `KemKeyPair::from_bytes()`,
//!   `DsaKeyPair::export()`, `DsaKeyPair::from_bytes()`
//! - Added `KemPublicKey::from_raw()`, `DsaPublicKey::from_raw()`
//!
//! ## What changed in v0.6.0
//!
//! - Corrected lib.rs changelog: v0.3.0 and v0.4.0 entries were swapped.
//!
//! ## What changed in v0.5.0
//!
//! - Version strings verified by CI — stale versions fail the pipeline
//! - criterion in dev-dependencies — reproducible benchmark builds
//! - CI actions pinned to commit SHAs
//! - README test count corrected
//!
//! ## What changed in v0.4.0
//!
//! - SharedSecretKey::len() removed
//! - CI pipeline added: test, clippy, fmt, bench-compile
//! - Upstream KAT issue filed
//!
//! ## What changed in v0.3.0
//!
//! - Transient plaintext window eliminated
//! - SharedSecretKey newtype with constant-time PartialEq
//! - Key persistence guidance in README
//! - Test modules renamed to size_tests
//!
//! ## What changed in v0.2.0
//!
//! - Zeroizing applied throughout
//! - Typed KemPublicKey / DsaPublicKey
//! - secure_zero() removed
//! - README corrected on NIST provenance

#![warn(clippy::all)]

pub mod dsa;
pub mod error;
pub mod hybrid;
pub mod kem;
pub mod pem;
pub mod serial;
pub mod utils;

pub use error::{PqcError, Result};

/// Security level for both KEM and DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Kyber512 / Dilithium2 — ~AES-128. Smallest keys, constrained devices.
    Level1,
    /// Kyber768 / Dilithium3 — ~AES-192. Recommended default.
    Level3,
    /// Kyber1024 / Dilithium5 — ~AES-256. Maximum, long-term secrets.
    Level5,
}

impl SecurityLevel {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "Level1: Kyber512/Dilithium2 (~AES-128)",
            SecurityLevel::Level3 => "Level3: Kyber768/Dilithium3 (~AES-192) — Recommended",
            SecurityLevel::Level5 => "Level5: Kyber1024/Dilithium5 (~AES-256) — Maximum",
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}
