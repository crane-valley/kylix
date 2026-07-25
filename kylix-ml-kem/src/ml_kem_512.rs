//! ML-KEM-512 implementation (NIST Security Level 1).
//!
//! This module provides the ML-KEM-512 parameter set, which offers
//! 128-bit classical security (NIST Security Level 1).

use crate::params::ml_kem_512::*;

crate::types::define_ml_kem_variant! {
    variant_doc: {
        /// ML-KEM-512 key encapsulation mechanism.
        ///
        /// Provides NIST Security Level 1 (128-bit classical security).
    },
    variant_name: MlKem512,
    dk_size: 1632,
    ek_size: 800,
    ct_size: 768,
    ss_size: 32
}
