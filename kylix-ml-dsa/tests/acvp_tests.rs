//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for ML-DSA.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! Note: These tests are skipped when the test vectors are not present
//! (e.g., when running from crates.io package where they are excluded).

use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Path to the ACVP test vectors directory
const ACVP_DIR: &str = "tests/acvp";

/// Check if ACVP test vectors are available.
/// Returns false when running from crates.io package where vectors are excluded.
fn acvp_vectors_available() -> bool {
    Path::new(ACVP_DIR).exists()
}

/// Macro to skip test if ACVP vectors are not available
macro_rules! skip_if_no_vectors {
    () => {
        if !acvp_vectors_available() {
            eprintln!("Skipping ACVP test: test vectors not available (excluded from crates.io package)");
            return;
        }
    };
}

/// ACVP prompt file structure for KeyGen
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpKeyGenPromptFile {
    test_groups: Vec<KeyGenPromptGroup>,
}

/// ACVP expected results file structure for KeyGen
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpKeyGenExpectedFile {
    test_groups: Vec<KeyGenExpectedGroup>,
}

/// KeyGen test group in prompt file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPromptGroup {
    tg_id: u32,
    parameter_set: String,
    tests: Vec<KeyGenPrompt>,
}

/// KeyGen test group in expected results file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpectedGroup {
    tg_id: u32,
    tests: Vec<KeyGenExpected>,
}

/// KeyGen prompt test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPrompt {
    tc_id: u32,
    seed: String,
}

/// KeyGen expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpected {
    tc_id: u32,
    pk: String,
    sk: String,
}

/// ACVP prompt file structure for SigVer
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigVerPromptFile {
    test_groups: Vec<SigVerPromptGroup>,
}

/// ACVP expected results file structure for SigVer
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigVerExpectedFile {
    test_groups: Vec<SigVerExpectedGroup>,
}

/// SigVer test group in prompt file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerPromptGroup {
    tg_id: u32,
    parameter_set: String,
    signature_interface: String,
    #[serde(default)]
    #[allow(dead_code)]
    pre_hash: Option<String>,
    tests: Vec<serde_json::Value>,
}

/// SigVer test group in expected results file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerExpectedGroup {
    tg_id: u32,
    tests: Vec<SigVerExpected>,
}

/// SigVer prompt test case (internal interface with message)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerInternalPrompt {
    tc_id: u32,
    pk: String,
    message: String,
    signature: String,
}

/// SigVer expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerExpected {
    tc_id: u32,
    test_passed: bool,
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

fn load_keygen_prompt_file(path: &str) -> AcvpKeyGenPromptFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP prompt file");
    serde_json::from_str(&content).expect("Failed to parse ACVP prompt JSON")
}

fn load_keygen_expected_file(path: &str) -> AcvpKeyGenExpectedFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP expected file");
    serde_json::from_str(&content).expect("Failed to parse ACVP expected JSON")
}

fn load_sigver_prompt_file(path: &str) -> AcvpSigVerPromptFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP prompt file");
    serde_json::from_str(&content).expect("Failed to parse ACVP prompt JSON")
}

fn load_sigver_expected_file(path: &str) -> AcvpSigVerExpectedFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP expected file");
    serde_json::from_str(&content).expect("Failed to parse ACVP expected JSON")
}

// ============================================================================
// KeyGen Tests
// ============================================================================

#[cfg(feature = "ml-dsa-44")]
mod keygen_44 {
    use super::*;
    use kylix_ml_dsa::dsa44::{SigningKey, VerificationKey};

    #[test]
    fn test_acvp_keygen_ml_dsa_44() {
        skip_if_no_vectors!();
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-DSA-44")
            .expect("ML-DSA-44 test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let seed: [u8; 32] = hex_decode(&prompt.seed)
                .try_into()
                .expect("Invalid seed length");

            // Use internal keygen function with deterministic seed
            let (sk_bytes, pk_bytes) = kylix_ml_dsa::sign::ml_dsa_keygen::<4, 4, 2>(&seed);

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk_bytes, expected_pk,
                "ML-DSA-44 KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk_bytes, expected_sk,
                "ML-DSA-44 KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            // Also verify the key types can be constructed
            let _sk = SigningKey::from_bytes(&sk_bytes).expect("Invalid signing key");
            let _pk = VerificationKey::from_bytes(&pk_bytes).expect("Invalid verification key");

            passed += 1;
        }
        println!("ML-DSA-44 KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-dsa-65")]
mod keygen_65 {
    use super::*;
    use kylix_ml_dsa::dsa65::{SigningKey, VerificationKey};

    #[test]
    fn test_acvp_keygen_ml_dsa_65() {
        skip_if_no_vectors!();
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-DSA-65")
            .expect("ML-DSA-65 test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let seed: [u8; 32] = hex_decode(&prompt.seed)
                .try_into()
                .expect("Invalid seed length");

            let (sk_bytes, pk_bytes) = kylix_ml_dsa::sign::ml_dsa_keygen::<6, 5, 4>(&seed);

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk_bytes, expected_pk,
                "ML-DSA-65 KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk_bytes, expected_sk,
                "ML-DSA-65 KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            let _sk = SigningKey::from_bytes(&sk_bytes).expect("Invalid signing key");
            let _pk = VerificationKey::from_bytes(&pk_bytes).expect("Invalid verification key");

            passed += 1;
        }
        println!("ML-DSA-65 KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-dsa-87")]
mod keygen_87 {
    use super::*;
    use kylix_ml_dsa::dsa87::{SigningKey, VerificationKey};

    #[test]
    fn test_acvp_keygen_ml_dsa_87() {
        skip_if_no_vectors!();
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-DSA-87")
            .expect("ML-DSA-87 test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let seed: [u8; 32] = hex_decode(&prompt.seed)
                .try_into()
                .expect("Invalid seed length");

            let (sk_bytes, pk_bytes) = kylix_ml_dsa::sign::ml_dsa_keygen::<8, 7, 2>(&seed);

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk_bytes, expected_pk,
                "ML-DSA-87 KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk_bytes, expected_sk,
                "ML-DSA-87 KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            let _sk = SigningKey::from_bytes(&sk_bytes).expect("Invalid signing key");
            let _pk = VerificationKey::from_bytes(&pk_bytes).expect("Invalid verification key");

            passed += 1;
        }
        println!("ML-DSA-87 KeyGen: {} ACVP tests passed", passed);
    }
}

// ============================================================================
// SigVer Tests
// ============================================================================

#[cfg(feature = "ml-dsa-44")]
mod sigver_44 {
    use super::*;
    use kylix_ml_dsa::sign::ml_dsa_verify;

    #[test]
    fn test_acvp_sigver_ml_dsa_44() {
        skip_if_no_vectors!();
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        // Find internal interface test groups with message (not mu)
        // These match our current implementation which uses raw message input
        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "ML-DSA-44"
                    && g.signature_interface == "internal"
                    && g.tests.first().and_then(|t| t.get("message")).is_some()
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("ML-DSA-44 SigVer: No internal/message test groups found, skipping");
            return;
        }

        let mut total_passed = 0;
        for prompt_group in prompt_groups {
            let expected_group = expected_file
                .test_groups
                .iter()
                .find(|g| g.tg_id == prompt_group.tg_id)
                .expect("Expected test group not found");

            for (prompt_val, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter())
            {
                let prompt: SigVerInternalPrompt =
                    serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
                assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

                let pk = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                // ML-DSA-44 parameters
                const BETA: i32 = 78;
                const GAMMA1: i32 = 1 << 17;
                const GAMMA2: i32 = 95232;
                const TAU: usize = 39;
                const OMEGA: usize = 80;
                const C_TILDE_BYTES: usize = 32;

                let result = ml_dsa_verify::<4, 4, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "ML-DSA-44 SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!("ML-DSA-44 SigVer: {} ACVP tests passed", total_passed);
    }
}

#[cfg(feature = "ml-dsa-65")]
mod sigver_65 {
    use super::*;
    use kylix_ml_dsa::sign::ml_dsa_verify;

    #[test]
    fn test_acvp_sigver_ml_dsa_65() {
        skip_if_no_vectors!();
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "ML-DSA-65"
                    && g.signature_interface == "internal"
                    && g.tests.first().and_then(|t| t.get("message")).is_some()
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("ML-DSA-65 SigVer: No internal/message test groups found, skipping");
            return;
        }

        let mut total_passed = 0;
        for prompt_group in prompt_groups {
            let expected_group = expected_file
                .test_groups
                .iter()
                .find(|g| g.tg_id == prompt_group.tg_id)
                .expect("Expected test group not found");

            for (prompt_val, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter())
            {
                let prompt: SigVerInternalPrompt =
                    serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
                assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

                let pk = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                // ML-DSA-65 parameters
                const BETA: i32 = 196;
                const GAMMA1: i32 = 1 << 19;
                const GAMMA2: i32 = 261888;
                const TAU: usize = 49;
                const OMEGA: usize = 55;
                const C_TILDE_BYTES: usize = 48;

                let result = ml_dsa_verify::<6, 5, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "ML-DSA-65 SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!("ML-DSA-65 SigVer: {} ACVP tests passed", total_passed);
    }
}

#[cfg(feature = "ml-dsa-87")]
mod sigver_87 {
    use super::*;
    use kylix_ml_dsa::sign::ml_dsa_verify;

    #[test]
    fn test_acvp_sigver_ml_dsa_87() {
        skip_if_no_vectors!();
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "ML-DSA-87"
                    && g.signature_interface == "internal"
                    && g.tests.first().and_then(|t| t.get("message")).is_some()
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("ML-DSA-87 SigVer: No internal/message test groups found, skipping");
            return;
        }

        let mut total_passed = 0;
        for prompt_group in prompt_groups {
            let expected_group = expected_file
                .test_groups
                .iter()
                .find(|g| g.tg_id == prompt_group.tg_id)
                .expect("Expected test group not found");

            for (prompt_val, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter())
            {
                let prompt: SigVerInternalPrompt =
                    serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
                assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

                let pk = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                // ML-DSA-87 parameters
                const BETA: i32 = 120;
                const GAMMA1: i32 = 1 << 19;
                const GAMMA2: i32 = 261888;
                const TAU: usize = 60;
                const OMEGA: usize = 75;
                const C_TILDE_BYTES: usize = 64;

                let result = ml_dsa_verify::<8, 7, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "ML-DSA-87 SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!("ML-DSA-87 SigVer: {} ACVP tests passed", total_passed);
    }
}
