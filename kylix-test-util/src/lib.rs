//! Test scaffolding shared by the Kylix algorithm crates.
//!
//! This crate is dev-only (`publish = false`) and is consumed through
//! path-only dev-dependencies, so it cannot become a registry dependency.
//!
//! It holds the parts of the ACVP harness that are identical across
//! kylix-ml-kem, kylix-ml-dsa and kylix-slh-dsa: vector-directory
//! discovery, the skip macro used when the vectors are absent, hex
//! decoding, the JSON loader, and the file/group envelope types. Vector
//! shapes that differ per algorithm stay in the crate that uses them.

pub mod acvp;
pub mod proptest_util;
