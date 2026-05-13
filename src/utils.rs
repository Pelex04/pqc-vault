//! Utility functions for constant-time comparison and hex encoding.
//!
//! # Note on secure memory zeroing
//! `secure_zero()` was intentionally removed in v0.2.0. The prior implementation
//! used `compiler_fence(SeqCst)` which does NOT prevent LLVM dead store
//! elimination — the zeroing loop could be silently removed by the optimizer.
//! All secret zeroing is now handled exclusively by `zeroize::Zeroizing<T>`,
//! which uses `write_volatile` internally and is correct on all platforms.
//!
//! # Caller responsibility for constant-time comparison
//! When comparing shared secrets extracted via `.as_bytes()`, always use
//! `ct_eq()` from this module rather than `==` on raw byte slices.
//! `Vec<u8>` equality is NOT constant-time and introduces timing side channels.
//!
//! The `SharedSecretKey` type in `kem` module implements `PartialEq` using
//! `ct_eq` internally — if you use that type, `==` is already safe.

use crate::error::{PqcError, Result};
use subtle::ConstantTimeEq;

/// Encode bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode a hex string to bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| PqcError::HexDecodeError(e.to_string()))
}

/// Constant-time byte slice comparison.
///
/// **Use this when comparing shared secrets or any sensitive byte material.**
/// Standard `==` on `Vec<u8>` or `&[u8]` is variable-time and introduces
/// timing side channels that can leak secret values.
///
/// Returns `true` only if both slices have identical length and content.
/// The comparison time is proportional to the length of the slices,
/// not to how many bytes differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = b"pqc_vault_test_data_12345";
        assert_eq!(from_hex(&to_hex(data)).unwrap(), data.to_vec());
    }

    #[test]
    fn test_hex_empty() {
        assert_eq!(to_hex(b""), "");
        assert_eq!(from_hex("").unwrap(), b"");
    }

    #[test]
    fn test_ct_eq_same() {
        assert!(ct_eq(b"same_secret_value", b"same_secret_value"));
    }

    #[test]
    fn test_ct_eq_different() {
        assert!(!ct_eq(b"secret_a_value__", b"secret_b_value__"));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        assert!(!ct_eq(b"short", b"longer string here"));
    }

    #[test]
    fn test_ct_eq_empty() {
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn test_ct_eq_single_bit_difference() {
        // Ensure a single-bit flip is detected
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[15] = 1;
        assert!(!ct_eq(&a, &b));
    }
}
