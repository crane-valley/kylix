//! ML-DSA-65 (NIST Level 3) implementation

use crate::params::ml_dsa_65::*;

crate::types::define_ml_dsa_variant! {
    marker_doc: {
        /// ML-DSA-65 algorithm marker.
    },
    variant_name: MlDsa65,
    verify_expanded_doc: {
        /// Verify signature using pre-expanded verification key.
        ///
        /// This is faster than [`Signer::verify`] when verifying multiple signatures
        /// with the same public key.
        ///
        /// # Performance
        ///
        /// | Method | Time per verify |
        /// |--------|-----------------|
        /// | `verify()` | ~101 µs |
        /// | `verify_expanded()` | ~38 µs |
        /// | `expand()` (one-time) | ~68 µs |
        ///
        /// Break-even: 2 verifications with the same key.
        ///
        /// # Example
        ///
        /// ```ignore
        /// // Expand the verification key once
        /// let expanded = pk.expand()?;
        ///
        /// // Verify multiple (message, signature) pairs efficiently
        /// for (message, signature) in messages_and_signatures {
        ///     MlDsa65::verify_expanded(&expanded, message, &signature)?;
        /// }
        /// ```
    },
    sk_size: 4032,
    pk_size: 1952,
    sig_size: 3309,
    message: b"Hello, ML-DSA-65!"
}
