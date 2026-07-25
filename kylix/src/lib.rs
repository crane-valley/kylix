//! # Kylix
//!
//! `kylix-pqc` is a pure Rust post-quantum cryptography library implementing
//! NIST FIPS 203, 204, and 205.
//!
//! The facade crate re-exports the main algorithms behind feature flags:
//!
//! - [`ml_kem`] for ML-KEM key encapsulation
//! - [`ml_dsa`] for ML-DSA signatures
//! - [`slh_dsa`] for SLH-DSA stateless hash-based signatures
//!
//! This library is experimental and has not been audited. Do not use it in
//! production.
//!
//! ## Quick Start
//!
//! Add the facade crate:
//!
//! ```toml
//! [dependencies]
//! kylix-pqc = "0.5"
//! rand = "0.9"
//! ```
//!
//! Enable SHA2-based SLH-DSA variants when needed. On the facade crate,
//! `slh-dsa-sha2` augments `slh-dsa`, so SHA2-only configurations with
//! `default-features = false` should enable both flags:
//!
//! ```toml
//! [dependencies]
//! kylix-pqc = { version = "0.5", default-features = false, features = ["slh-dsa", "slh-dsa-sha2"] }
//! rand = "0.9"
//! ```
//!
//! ## Feature Flags
//!
//! - `std` (default): enable standard library support
//! - `ml-kem` (default): enable all ML-KEM variants
//! - `ml-dsa` (default): enable all ML-DSA variants
//! - `slh-dsa` (default): enable SHAKE-based SLH-DSA variants
//! - `slh-dsa-sha2`: enable SHA2-based SLH-DSA variants; on the facade crate,
//!   keep `slh-dsa` enabled as well
//!
//! ## Choosing An Algorithm
//!
//! - Use `MlKem768` for a general-purpose Level 3 key encapsulation mechanism.
//! - Use `MlDsa65` for a general-purpose Level 3 signature scheme.
//! - Use `SlhDsaShake128f` when you want stateless hash-based signatures and can
//!   accept larger signatures for faster signing.
//!
//! ## Examples
//!
//! ML-KEM key exchange:
//!
//! ```no_run
//! # fn main() -> kylix_pqc::Result<()> {
//! use kylix_pqc::ml_kem::{Kem, MlKem768};
//! use rand::rng;
//!
//! let mut rng = rng();
//! let (dk, ek) = MlKem768::keygen(&mut rng)?;
//! let (ct, ss_sender) = MlKem768::encaps(&ek, &mut rng)?;
//! let ss_receiver = MlKem768::decaps(&dk, &ct)?;
//!
//! assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
//! # Ok(())
//! # }
//! ```
//!
//! ML-DSA sign and verify:
//!
//! ```no_run
//! # #[cfg(feature = "ml-dsa")]
//! # fn main() -> kylix_pqc::Result<()> {
//! use kylix_pqc::ml_dsa::{MlDsa65, Signer};
//! use rand::rng;
//!
//! let mut rng = rng();
//! let (sk, pk) = MlDsa65::keygen(&mut rng)?;
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa65::sign(&sk, message)?;
//!
//! MlDsa65::verify(&pk, message, &signature)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "ml-dsa"))]
//! # fn main() {}
//! ```
//!
//! ## `no_std`
//!
//! Disable default features and select only the algorithms you need:
//!
//! ```toml
//! [dependencies]
//! kylix-pqc = { version = "0.5", default-features = false, features = ["ml-kem"] }
//! ```
//!
//! Individual algorithm crates expose finer-grained per-variant feature flags if
//! you need tighter binary-size control.
//!
//! ## More Documentation
//!
//! - [Repository README](https://github.com/crane-valley/kylix/blob/main/README.md)
//! - [Architecture Overview](https://github.com/crane-valley/kylix/blob/main/ARCHITECTURE.md)
//! - [Security Policy](https://github.com/crane-valley/kylix/blob/main/SECURITY.md)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub use kylix_core::{Error, Result};

/// Core traits for cryptographic primitives.
pub mod traits {
    pub use kylix_core::{Kem, Signer};
}

// The facade re-exports each algorithm crate item by item rather than with a
// glob. A glob would republish every future `pub` item of the algorithm crates
// as supported `kylix-pqc` API, which is how internals such as `Poly` and the
// `params` modules leaked into 0.4.x. Adding an item here must be a deliberate
// act; do not reintroduce `pub use <crate>::*`.

/// ML-KEM (FIPS 203) key encapsulation mechanism.
#[cfg(feature = "ml-kem")]
pub mod ml_kem {
    pub use kylix_core::Kem;

    pub use kylix_ml_kem::{ml_kem_1024, ml_kem_512, ml_kem_768};
    pub use kylix_ml_kem::{MlKem1024, MlKem512, MlKem768};

    #[doc(hidden)]
    pub use kylix_ml_kem::kem;
}

/// ML-DSA (FIPS 204) digital signature algorithm.
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa {
    pub use kylix_core::Signer;

    pub use kylix_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
    pub use kylix_ml_dsa::{Error, MlDsa44, MlDsa65, MlDsa87, Result};

    // Dropping the deprecated aliases from the facade would break facade users
    // outright instead of warning them, so they are re-exported until removal.
    #[allow(deprecated)]
    pub use kylix_ml_dsa::{dsa44, dsa65, dsa87};

    #[doc(hidden)]
    pub use kylix_ml_dsa::sign;
}

/// SLH-DSA (FIPS 205) stateless hash-based digital signature algorithm.
#[cfg(feature = "slh-dsa")]
pub mod slh_dsa {
    pub use kylix_core::Signer;

    pub use kylix_slh_dsa::{hash_shake, Shake128Hash, Shake192Hash, Shake256Hash};
    pub use kylix_slh_dsa::{Address, AdrsType, Error, HashSuite, Result};

    pub use kylix_slh_dsa::{
        slh_dsa_shake_128f, slh_dsa_shake_128s, slh_dsa_shake_192f, slh_dsa_shake_192s,
        slh_dsa_shake_256f, slh_dsa_shake_256s,
    };
    pub use kylix_slh_dsa::{
        SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
        SlhDsaShake256s,
    };

    #[cfg(feature = "slh-dsa-sha2")]
    pub use kylix_slh_dsa::{hash_sha2, Sha2_128Hash, Sha2_192Hash, Sha2_256Hash};
    #[cfg(feature = "slh-dsa-sha2")]
    pub use kylix_slh_dsa::{
        slh_dsa_sha2_128f, slh_dsa_sha2_128s, slh_dsa_sha2_192f, slh_dsa_sha2_192s,
        slh_dsa_sha2_256f, slh_dsa_sha2_256s,
    };
    #[cfg(feature = "slh-dsa-sha2")]
    pub use kylix_slh_dsa::{
        SlhDsaSha2_128f, SlhDsaSha2_128s, SlhDsaSha2_192f, SlhDsaSha2_192s, SlhDsaSha2_256f,
        SlhDsaSha2_256s,
    };

    #[doc(hidden)]
    pub use kylix_slh_dsa::sign;
}
