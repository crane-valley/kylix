//! ML-DSA-87 (NIST Level 5) implementation

use crate::params::ml_dsa_87::*;

crate::types::define_ml_dsa_variant! {
    marker_doc: {
        /// ML-DSA-87 algorithm marker.
    },
    variant_name: MlDsa87,
    verify_expanded_doc: {
        /// Verify signature using pre-expanded verification key.
        ///
        /// See [`crate::ml_dsa_65::MlDsa65::verify_expanded`] for details.
    },
    sk_size: 4896,
    pk_size: 2592,
    sig_size: 4627,
    message: b"Hello, ML-DSA-87!"
}
