//! Shared NIST ACVP vector-loading scaffolding.
//!
//! Official vectors live under `<crate>/tests/acvp/` and are excluded from
//! the published packages, so every ACVP test must degrade to a skip when
//! the directory is missing.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Path to the ACVP test vectors directory, relative to the crate root.
pub const ACVP_DIR: &str = "tests/acvp";

/// Check if ACVP test vectors are available.
/// Returns false when running from crates.io package where vectors are excluded.
pub fn vectors_available() -> bool {
    Path::new(ACVP_DIR).exists()
}

/// Skip the enclosing test (returning early) if ACVP vectors are not available.
#[macro_export]
macro_rules! skip_if_no_vectors {
    () => {
        if !$crate::acvp::vectors_available() {
            eprintln!(
                "Skipping ACVP test: test vectors not available (excluded from crates.io package)"
            );
            return;
        }
    };
}

/// Decode a hex string from an ACVP vector field.
pub fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

/// Load and deserialize an ACVP prompt or expected-results JSON file.
pub fn load_json<T: DeserializeOwned>(path: &str) -> T {
    let content = fs::read_to_string(path).expect("Failed to read ACVP prompt file");
    serde_json::from_str(&content).expect("Failed to parse ACVP prompt JSON")
}

/// Envelope of an ACVP prompt or expected-results file: a list of test groups.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcvpFile<G> {
    pub test_groups: Vec<G>,
}

/// Test group in an expected-results file (no `parameterSet`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedGroup<T> {
    pub tg_id: u32,
    pub tests: Vec<T>,
}

/// KeyGen expected result, shared by ML-DSA and SLH-DSA.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenExpected {
    pub tc_id: u32,
    pub pk: String,
    pub sk: String,
}

/// SigVer prompt test case (internal interface with message).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerInternalPrompt {
    pub tc_id: u32,
    pub pk: String,
    pub message: String,
    pub signature: String,
}

/// SigVer expected result.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerExpected {
    pub tc_id: u32,
    pub test_passed: bool,
}
