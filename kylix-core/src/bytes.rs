//! Macros for byte-backed public API wrappers.

/// Implement `from_bytes` and `as_bytes` for a fixed-size `bytes` field.
///
/// The target type must store its serialized representation in a field named
/// `bytes` with type `[u8; SIZE]`.
#[macro_export]
macro_rules! impl_fixed_bytes {
    (
        for $name:ident,
        size: $size:expr,
        error: $error_variant:ident,
        as_bytes: $as_bytes_ty:ty
    ) => {
        impl $name {
            /// Create from bytes.
            ///
            /// Writes directly into the struct to avoid intermediate buffers
            /// that could leave sensitive material on the stack.
            pub fn from_bytes(bytes: &[u8]) -> ::kylix_core::Result<Self> {
                if bytes.len() != $size {
                    return Err(::kylix_core::Error::$error_variant {
                        expected: $size,
                        actual: bytes.len(),
                    });
                }

                let mut result = Self {
                    bytes: [0u8; $size],
                };
                result.bytes.copy_from_slice(bytes);
                Ok(result)
            }

            /// Get the raw bytes.
            pub fn as_bytes(&self) -> $as_bytes_ty {
                &self.bytes
            }
        }
    };
}
