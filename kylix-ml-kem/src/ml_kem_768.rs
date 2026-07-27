//! ML-KEM-768 implementation (NIST Security Level 3).
//!
//! This module provides the ML-KEM-768 parameter set, which offers
//! 192-bit classical security (NIST Security Level 3).

use crate::params::ml_kem_768::*;

crate::types::define_ml_kem_variant! {
    variant_doc: {
        /// ML-KEM-768 key encapsulation mechanism.
        ///
        /// Provides NIST Security Level 3 (192-bit classical security).
    },
    variant_name: MlKem768,
    dk_size: 2400,
    ek_size: 1184,
    ct_size: 1088,
    ss_size: 32
}
