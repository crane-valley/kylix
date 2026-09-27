//! ML-DSA-44 (NIST Level 2) implementation

use crate::params::ml_dsa_44::*;

crate::types::define_ml_dsa_variant! {
    marker_doc: {
        /// ML-DSA-44 algorithm marker.
    },
    variant_name: MlDsa44,
    verify_expanded_doc: {
        /// Verify signature using pre-expanded verification key.
        ///
        /// This is faster than [`Signer::verify`] when verifying multiple signatures
        /// with the same public key.
    },
    sk_size: 2560,
    pk_size: 1312,
    sig_size: 2420,
    message: b"Hello, ML-DSA-44!"
}
