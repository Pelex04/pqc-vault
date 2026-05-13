//! Error types for all PQC Vault operations.

use std::fmt;

/// Result type used throughout the library.
pub type Result<T> = std::result::Result<T, PqcError>;

/// All possible errors from PQC Vault operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    /// Key generation failed.
    KeyGenerationFailed,
    /// Encapsulation failed.
    EncapsulationFailed,
    /// Decapsulation failed — ciphertext may be malformed or tampered.
    DecapsulationFailed,
    /// Signing operation failed.
    SigningFailed,
    /// Signature verification failed — message or key mismatch.
    VerificationFailed,
    /// Provided key is invalid or wrong length.
    InvalidKey(String),
    /// Provided ciphertext is invalid or wrong length.
    InvalidCiphertext(String),
    /// Provided signature is invalid or wrong length.
    InvalidSignature(String),
    /// Hex decode error.
    HexDecodeError(String),
    /// Generic error.
    Other(String),
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PqcError::KeyGenerationFailed => write!(f, "Key generation failed"),
            PqcError::EncapsulationFailed => write!(f, "Encapsulation failed"),
            PqcError::DecapsulationFailed => write!(f, "Decapsulation failed"),
            PqcError::SigningFailed => write!(f, "Signing failed"),
            PqcError::VerificationFailed => write!(f, "Signature verification failed"),
            PqcError::InvalidKey(m) => write!(f, "Invalid key: {}", m),
            PqcError::InvalidCiphertext(m) => write!(f, "Invalid ciphertext: {}", m),
            PqcError::InvalidSignature(m) => write!(f, "Invalid signature: {}", m),
            PqcError::HexDecodeError(m) => write!(f, "Hex decode error: {}", m),
            PqcError::Other(m) => write!(f, "Error: {}", m),
        }
    }
}

impl std::error::Error for PqcError {}
