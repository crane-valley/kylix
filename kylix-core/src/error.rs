//! Error types for Kylix cryptographic operations.

use core::fmt;

/// Result type alias using [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid key length provided.
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length provided.
        actual: usize,
    },

    /// Invalid ciphertext length.
    InvalidCiphertextLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length provided.
        actual: usize,
    },

    /// Invalid signature length.
    InvalidSignatureLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length provided.
        actual: usize,
    },

    /// Decapsulation failed (implicit rejection).
    DecapsulationFailed,

    /// Signature verification failed.
    VerificationFailed,

    /// Insufficient randomness provided.
    InsufficientRandomness,

    /// Encoding or decoding error.
    EncodingError,

    /// Parameter set not supported.
    UnsupportedParameterSet,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKeyLength { expected, actual } => {
                write!(f, "invalid key length: expected {expected}, got {actual}")
            }
            Error::InvalidCiphertextLength { expected, actual } => {
                write!(
                    f,
                    "invalid ciphertext length: expected {expected}, got {actual}"
                )
            }
            Error::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "invalid signature length: expected {expected}, got {actual}"
                )
            }
            Error::DecapsulationFailed => write!(f, "decapsulation failed"),
            Error::VerificationFailed => write!(f, "signature verification failed"),
            Error::InsufficientRandomness => write!(f, "insufficient randomness provided"),
            Error::EncodingError => write!(f, "encoding or decoding error"),
            Error::UnsupportedParameterSet => write!(f, "unsupported parameter set"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
