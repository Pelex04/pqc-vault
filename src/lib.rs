//! # PQC Vault v0.6.0
//!
//! Post-quantum cryptography library implementing:
//! - **ML-KEM** (CRYSTALS-Kyber) — NIST FIPS 203 — Key Encapsulation
//! - **ML-DSA** (CRYSTALS-Dilithium) — NIST FIPS 204 — Digital Signatures
//!
//! ## What changed in v0.6.0
//!
//! - Corrected lib.rs changelog: v0.3.0 and v0.4.0 entries were swapped.
//!   History now matches README.md exactly.
//!
//! ## What changed in v0.5.0
//!
//! - Version strings in `lib.rs` and `README.md` verified by CI on every push —
//!   stale versions cause pipeline failure before merge
//! - `criterion` moved to `[dev-dependencies]` — benchmark builds are reproducible
//! - CI action references pinned to immutable commit SHAs
//! - README test count corrected to 31
//!
//! ## What changed in v0.4.0
//!
//! - `SharedSecretKey::len()` removed — resolves `clippy::len_without_is_empty`
//! - `lib.rs` version comment updated to match Cargo.toml
//! - GitHub Actions CI pipeline added: test, clippy, fmt, bench-compile
//! - Upstream KAT issue filed and documented in README
//!
//! ## What changed in v0.3.0
//!
//! - Transient plaintext window eliminated: `Zeroizing::new()` wraps secret key
//!   bytes inline at allocation — no intermediate plain `Vec<u8>` binding
//! - `SharedSecretKey` newtype: constant-time `PartialEq` built in — `==` is safe
//! - Redacting `Debug` impl on `SharedSecretKey` — prints byte count, not bytes
//! - Benchmark file updated to typed API
//! - Key persistence guidance added to README
//! - Test modules renamed `size_tests` — accurately reflects scope vs vector KATs
//!
//! ## What changed in v0.2.0
//!
//! - Private keys wrapped in `Zeroizing<Vec<u8>>` — actually wiped on drop
//! - `decapsulate()` and `sign()` return `Zeroizing<Vec<u8>>`
//! - `secure_zero()` deleted — `compiler_fence` does not stop LLVM dead store elimination
//! - Typed `KemPublicKey` / `DsaPublicKey` structs — level mismatch impossible
//! - `encapsulate_for()` replaced with typed API
//! - Output-size validation tests added for all 6 parameter sets
//! - README corrected: pqcrypto community crates, not official NIST submission
//! - `key_info()` removed — prevented accidental logging of secret material

#![warn(clippy::all)]

pub mod kem;
pub mod dsa;
pub mod error;
pub mod utils;

pub use error::{PqcError, Result};

/// Security level for both KEM and DSA operations.
///
/// Note: Level1 maps to Kyber512 (KEM) and Dilithium2 (DSA).
/// Level3 maps to Kyber768 and Dilithium3.
/// Level5 maps to Kyber1024 and Dilithium5.
/// These are described as AES-equivalent but operate on different
/// mathematical assumptions — see individual module docs for details.
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
