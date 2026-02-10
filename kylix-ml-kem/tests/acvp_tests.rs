// Helpers and structs are used by feature-gated test functions; allow dead_code
// when compiling without variant features (e.g., --no-default-features).
#![allow(dead_code, unused_macros, unused_imports)]

//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for ML-KEM.
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
            eprintln!(
                "Skipping ACVP test: test vectors not available (excluded from crates.io package)"
            );
            return;
        }
    };
}

/// ACVP prompt file structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpPromptFile {
    test_groups: Vec<PromptTestGroup>,
}

/// ACVP expected results file structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpExpectedFile {
    test_groups: Vec<ExpectedTestGroup>,
}

/// Test group in prompt file (has parameterSet)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PromptTestGroup {
    tg_id: u32,
    parameter_set: String,
    #[serde(default)]
    function: Option<String>,
    tests: Vec<serde_json::Value>,
}

/// Test group in expected results file (no parameterSet)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedTestGroup {
    tg_id: u32,
    tests: Vec<serde_json::Value>,
}

/// KeyGen prompt test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPrompt {
    tc_id: u32,
    d: String,
    z: String,
}

/// KeyGen expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenExpected {
    tc_id: u32,
    ek: String,
    dk: String,
}

/// EncapDecap encapsulation prompt
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapsPrompt {
    tc_id: u32,
    ek: String,
    m: String,
}

/// EncapDecap encapsulation expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncapsExpected {
    tc_id: u32,
    c: String,
    k: String,
}

/// EncapDecap decapsulation prompt
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecapsPrompt {
    tc_id: u32,
    dk: String,
    c: String,
}

/// EncapDecap decapsulation expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecapsExpected {
    tc_id: u32,
    k: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("Invalid hex string")
}

fn load_prompt_file(path: &str) -> AcvpPromptFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP prompt file");
    serde_json::from_str(&content).expect("Failed to parse ACVP prompt JSON")
}

fn load_expected_file(path: &str) -> AcvpExpectedFile {
    let content = fs::read_to_string(path).expect("Failed to read ACVP expected file");
    serde_json::from_str(&content).expect("Failed to parse ACVP expected JSON")
}

// ============================================================================
// KeyGen Tests
// ============================================================================

#[cfg(feature = "ml-kem-512")]
mod keygen_512 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_keygen;

    #[test]
    fn test_acvp_keygen_ml_kem_512() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_expected_file("tests/acvp/keygen_expected.json");

        // Find ML-KEM-512 test group in prompt
        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-KEM-512")
            .expect("ML-KEM-512 test group not found in prompt");

        // Find corresponding expected group by tgId
        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: KeyGenPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: KeyGenExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let d: [u8; 32] = hex_decode(&prompt.d).try_into().expect("Invalid d length");
            let z: [u8; 32] = hex_decode(&prompt.z).try_into().expect("Invalid z length");

            let (dk, ek) = ml_kem_keygen::<2, 3>(&d, &z);

            let expected_ek = hex_decode(&expected.ek);
            let expected_dk = hex_decode(&expected.dk);

            assert_eq!(
                ek, expected_ek,
                "ML-KEM-512 KeyGen tcId={}: ek mismatch",
                prompt.tc_id
            );
            assert_eq!(
                dk, expected_dk,
                "ML-KEM-512 KeyGen tcId={}: dk mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-512 KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-768")]
mod keygen_768 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_keygen;

    #[test]
    fn test_acvp_keygen_ml_kem_768() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-KEM-768")
            .expect("ML-KEM-768 test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: KeyGenPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: KeyGenExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let d: [u8; 32] = hex_decode(&prompt.d).try_into().expect("Invalid d length");
            let z: [u8; 32] = hex_decode(&prompt.z).try_into().expect("Invalid z length");

            let (dk, ek) = ml_kem_keygen::<3, 2>(&d, &z);

            let expected_ek = hex_decode(&expected.ek);
            let expected_dk = hex_decode(&expected.dk);

            assert_eq!(
                ek, expected_ek,
                "ML-KEM-768 KeyGen tcId={}: ek mismatch",
                prompt.tc_id
            );
            assert_eq!(
                dk, expected_dk,
                "ML-KEM-768 KeyGen tcId={}: dk mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-768 KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-1024")]
mod keygen_1024 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_keygen;

    #[test]
    fn test_acvp_keygen_ml_kem_1024() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "ML-KEM-1024")
            .expect("ML-KEM-1024 test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: KeyGenPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: KeyGenExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let d: [u8; 32] = hex_decode(&prompt.d).try_into().expect("Invalid d length");
            let z: [u8; 32] = hex_decode(&prompt.z).try_into().expect("Invalid z length");

            let (dk, ek) = ml_kem_keygen::<4, 2>(&d, &z);

            let expected_ek = hex_decode(&expected.ek);
            let expected_dk = hex_decode(&expected.dk);

            assert_eq!(
                ek, expected_ek,
                "ML-KEM-1024 KeyGen tcId={}: ek mismatch",
                prompt.tc_id
            );
            assert_eq!(
                dk, expected_dk,
                "ML-KEM-1024 KeyGen tcId={}: dk mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-1024 KeyGen: {} ACVP tests passed", passed);
    }
}

// ============================================================================
// Encapsulation Tests
// ============================================================================

#[cfg(feature = "ml-kem-512")]
mod encaps_512 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_encaps;

    #[test]
    fn test_acvp_encaps_ml_kem_512() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-512" && g.function.as_deref() == Some("encapsulation")
            })
            .expect("ML-KEM-512 encapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: EncapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: EncapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let ek = hex_decode(&prompt.ek);
            let m: [u8; 32] = hex_decode(&prompt.m).try_into().expect("Invalid m length");

            let (ct, ss) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();

            let expected_c = hex_decode(&expected.c);
            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ct, expected_c,
                "ML-KEM-512 Encaps tcId={}: ciphertext mismatch",
                prompt.tc_id
            );
            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-512 Encaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-512 Encaps: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-768")]
mod encaps_768 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_encaps;

    #[test]
    fn test_acvp_encaps_ml_kem_768() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-768" && g.function.as_deref() == Some("encapsulation")
            })
            .expect("ML-KEM-768 encapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: EncapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: EncapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let ek = hex_decode(&prompt.ek);
            let m: [u8; 32] = hex_decode(&prompt.m).try_into().expect("Invalid m length");

            let (ct, ss) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &m).unwrap();

            let expected_c = hex_decode(&expected.c);
            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ct, expected_c,
                "ML-KEM-768 Encaps tcId={}: ciphertext mismatch",
                prompt.tc_id
            );
            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-768 Encaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-768 Encaps: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-1024")]
mod encaps_1024 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_encaps;

    #[test]
    fn test_acvp_encaps_ml_kem_1024() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-1024" && g.function.as_deref() == Some("encapsulation")
            })
            .expect("ML-KEM-1024 encapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: EncapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: EncapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let ek = hex_decode(&prompt.ek);
            let m: [u8; 32] = hex_decode(&prompt.m).try_into().expect("Invalid m length");

            let (ct, ss) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &m).unwrap();

            let expected_c = hex_decode(&expected.c);
            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ct, expected_c,
                "ML-KEM-1024 Encaps tcId={}: ciphertext mismatch",
                prompt.tc_id
            );
            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-1024 Encaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-1024 Encaps: {} ACVP tests passed", passed);
    }
}

// ============================================================================
// Decapsulation Tests
// ============================================================================

#[cfg(feature = "ml-kem-512")]
mod decaps_512 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_decaps;

    #[test]
    fn test_acvp_decaps_ml_kem_512() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-512" && g.function.as_deref() == Some("decapsulation")
            })
            .expect("ML-KEM-512 decapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: DecapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: DecapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let dk = hex_decode(&prompt.dk);
            let ct = hex_decode(&prompt.c);

            let ss = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &ct).unwrap();

            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-512 Decaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-512 Decaps: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-768")]
mod decaps_768 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_decaps;

    #[test]
    fn test_acvp_decaps_ml_kem_768() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-768" && g.function.as_deref() == Some("decapsulation")
            })
            .expect("ML-KEM-768 decapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: DecapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: DecapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let dk = hex_decode(&prompt.dk);
            let ct = hex_decode(&prompt.c);

            let ss = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &ct).unwrap();

            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-768 Decaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-768 Decaps: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "ml-kem-1024")]
mod decaps_1024 {
    use super::*;
    use kylix_ml_kem::kem::ml_kem_decaps;

    #[test]
    fn test_acvp_decaps_ml_kem_1024() {
        skip_if_no_vectors!();
        let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
        let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| {
                g.parameter_set == "ML-KEM-1024" && g.function.as_deref() == Some("decapsulation")
            })
            .expect("ML-KEM-1024 decapsulation test group not found");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt_val, expected_val) in prompt_group.tests.iter().zip(expected_group.tests.iter())
        {
            let prompt: DecapsPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
            let expected: DecapsExpected =
                serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

            assert_eq!(prompt.tc_id, expected.tc_id);

            let dk = hex_decode(&prompt.dk);
            let ct = hex_decode(&prompt.c);

            let ss = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &ct).unwrap();

            let expected_k = hex_decode(&expected.k);

            assert_eq!(
                ss.as_slice(),
                expected_k.as_slice(),
                "ML-KEM-1024 Decaps tcId={}: shared secret mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
        println!("ML-KEM-1024 Decaps: {} ACVP tests passed", passed);
    }
}
