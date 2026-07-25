//! ML-KEM-1024 implementation (NIST Security Level 5).
//!
//! This module provides the ML-KEM-1024 parameter set, which offers
//! 256-bit classical security (NIST Security Level 5).

use crate::params::ml_kem_1024::*;

crate::types::define_ml_kem_variant! {
    variant_doc: {
        /// ML-KEM-1024 key encapsulation mechanism.
        ///
        /// Provides NIST Security Level 5 (256-bit classical security).
    },
    variant_name: MlKem1024,
    dk_size: 3168,
    ek_size: 1568,
    ct_size: 1568,
    ss_size: 32
}
