//! # PQC Vault v0.13.0
//!
//! Post-quantum cryptography library implementing:
//! - **ML-KEM** (CRYSTALS-Kyber) — NIST FIPS 203 — Key Encapsulation
//! - **ML-DSA** (CRYSTALS-Dilithium) — NIST FIPS 204 — Digital Signatures
//! - **Hybrid X25519 + ML-KEM** — secure against classical and quantum attackers
//! - **Key serialisation** — `serial` module, `EncryptedKeyBundle`, AES-256-GCM + Argon2id
//! - **PEM format** — `pem` module, standard public key export/import
//! - **CLI** — `pqc-vault` binary: keygen, sign, verify, encapsulate, decapsulate, inspect
//!
//! ## What changed in v0.13.0
//!
//! - `README.md` Key Persistence section rewritten — the section previously stated
//!   "This library does not serialise keys" which has been false since v0.7.0;
//!   now correctly documents `EncryptedKeyBundle` with a usage example
//! - `README.md` Known Gaps: removed serialisation, hybrid mode, and PEM — all three
//!   have been implemented since v0.7.0 and should never have appeared here
//! - `README.md` test count corrected from 50 to 55
//! - `lib.rs` v0.12.0 entry corrected: it falsely claimed the README Key Persistence
//!   fix shipped in v0.12.0; the record now accurately reflects when it shipped
//!
//! ## What changed in v0.12.0
//!
//! - `test_ciphertext_hex_roundtrip`: was a no-op — now asserts recovered secret
//!   matches the encapsulated secret, proving serialisation correctness end-to-end
//! - CLI: `version` string uses `env!("CARGO_PKG_VERSION")` — was hardcoded at
//!   "0.9.0" two versions behind; the CI version check does not cover the binary
//! - `Cargo.toml`: removed duplicate `clap` and `rpassword` dependency entries
//! - `lib.rs`: changelog rewritten in full
//! - NOTE: the v0.12.0 changelog entry originally claimed the README Key Persistence
//!   section was corrected. That correction was not made in v0.12.0. It shipped in v0.13.0.
//!
//! ## What changed in v0.11.0
//!
//! - `HybridCiphertext`: `to_hex()` / `from_hex()` — usable between processes
//! - `KemKeyData` / `DsaKeyData`: secret key fields made private
//! - `EncryptedKeyBundle`: `"version": 1` field in JSON for forward compatibility
//! - Argon2id parallelism raised from p=1 to p=4 (OWASP recommended)
//! - `from_validated()` on public key types — validates through pqcrypto;
//!   `from_raw()` restricted to `pub(crate)` internal use
//!
//! ## What changed in v0.10.0
//!
//! - CLI binary `pqc-vault`: keygen, encapsulate, decapsulate, sign, verify, inspect
//! - Examples: key_exchange, signing, hybrid_exchange, key_persistence
//!
//! ## What changed in v0.9.0
//!
//! - Changelog corrected: v0.8.0 had been describing v0.7.0 work
//! - Duplicate `[dev-dependencies]` block removed from Cargo.toml
//! - README test count corrected
//!
//! ## What changed in v0.8.0
//!
//! - Hybrid combiner: bare SHA-256 replaced with HKDF-Extract+Expand,
//!   domain label `b"pqc_vault hybrid v1"` — IETF draft-ietf-tls-hybrid-design
//! - X25519 public key stored at generation time — no reconstruction on `public_key()`
//! - Hand-rolled JSON parser replaced with `serde_json`
//! - Argon2id p=1 tradeoff documented
//!
//! ## What changed in v0.7.0
//!
//! - `serial` module: `EncryptedKeyBundle`, `KemKeyData`, `DsaKeyData`
//! - `pem` module: PEM encode/decode for public keys
//! - `hybrid` module: X25519 + Kyber via HKDF combiner
//! - `export()` and `from_bytes()` on `KemKeyPair` and `DsaKeyPair`
//!
//! ## What changed in v0.6.0
//!
//! - Changelog corrected: v0.3.0 and v0.4.0 entries were swapped in lib.rs
//!
//! ## What changed in v0.5.0
//!
//! - CI version-check job: lib.rs and README.md verified against Cargo.toml on every push
//! - `criterion` in `[dev-dependencies]` — reproducible benchmark builds
//! - CI action references pinned to immutable commit SHAs
//!
//! ## What changed in v0.4.0
//!
//! - `SharedSecretKey::len()` removed — resolves `clippy::len_without_is_empty`
//! - CI pipeline added: test, clippy, fmt, bench-compile, version-check
//! - Upstream KAT issue filed with pqcrypto maintainers
//!
//! ## What changed in v0.3.0
//!
//! - Transient plaintext window eliminated: `Zeroizing::new()` wraps inline at allocation
//! - `SharedSecretKey` newtype with constant-time `PartialEq` — `==` is safe by default
//! - Test modules renamed `size_tests` — accurately reflects scope vs vector KATs
//!
//! ## What changed in v0.2.0
//!
//! - `Zeroizing<Vec<u8>>` applied to all private key storage
//! - `decapsulate()` and `sign()` return `Zeroizing<Vec<u8>>`
//! - `secure_zero()` deleted — `compiler_fence` does not stop LLVM dead store elimination
//! - Typed `KemPublicKey` / `DsaPublicKey` — level mismatch is structurally impossible
//! - `key_info()` removed — could log partial secret bytes
//! - README corrected: pqcrypto community crates, not the official NIST submission

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
