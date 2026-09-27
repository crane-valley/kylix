// Skip compilation entirely when no variant features are enabled
// (e.g., --no-default-features), since all test functions are feature-gated.
#![cfg(any(
    feature = "ml-kem-512",
    feature = "ml-kem-768",
    feature = "ml-kem-1024"
))]

//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for ML-KEM.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! These tests are skipped when a partial source archive omits the vectors.

use kylix_test_util::acvp::{hex_decode, load_json, AcvpFile, ExpectedGroup};
use kylix_test_util::skip_if_no_vectors;
use serde::Deserialize;

/// ACVP prompt file structure
type AcvpPromptFile = AcvpFile<PromptTestGroup>;

/// ACVP expected results file structure
type AcvpExpectedFile = AcvpFile<ExpectedGroup<serde_json::Value>>;

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

fn load_prompt_file(path: &str) -> AcvpPromptFile {
    load_json(path)
}

fn load_expected_file(path: &str) -> AcvpExpectedFile {
    load_json(path)
}

/// Pair prompt and expected test cases, failing if the counts differ so a
/// truncated or mismatched file cannot silently skip cases.
fn paired_tests<'a>(
    prompt_group: &'a PromptTestGroup,
    expected_group: &'a ExpectedGroup<serde_json::Value>,
) -> impl Iterator<Item = (&'a serde_json::Value, &'a serde_json::Value)> {
    assert!(
        !prompt_group.tests.is_empty(),
        "tgId={}: empty test group",
        prompt_group.tg_id
    );
    assert_eq!(
        prompt_group.tests.len(),
        expected_group.tests.len(),
        "tgId={}: prompt/expected test count mismatch",
        prompt_group.tg_id
    );
    prompt_group.tests.iter().zip(expected_group.tests.iter())
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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
        for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
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

// ============================================================================
// Key Check Tests (FIPS 203 Sections 7.2 and 7.3)
// ============================================================================

/// Key check prompt: `ek` for encapsulationKeyCheck, `dk` for decapsulationKeyCheck
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyCheckPrompt {
    tc_id: u32,
    #[serde(alias = "ek", alias = "dk")]
    key: String,
}

/// Key check expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyCheckExpected {
    tc_id: u32,
    test_passed: bool,
}

/// There is no standalone key-check API: the FIPS 203 input checks run inside
/// encapsulation (Section 7.2) and decapsulation (Section 7.3), so `accepts`
/// drives those and reports whether the key was accepted.
fn run_key_check(parameter_set: &str, function: &str, accepts: impl Fn(&[u8]) -> bool) {
    let prompt_file = load_prompt_file("tests/acvp/encapdecap_prompt.json");
    let expected_file = load_expected_file("tests/acvp/encapdecap_expected.json");

    let prompt_group = prompt_file
        .test_groups
        .iter()
        .find(|g| g.parameter_set == parameter_set && g.function.as_deref() == Some(function))
        .unwrap_or_else(|| panic!("{} {} test group not found", parameter_set, function));

    let expected_group = expected_file
        .test_groups
        .iter()
        .find(|g| g.tg_id == prompt_group.tg_id)
        .expect("Expected test group not found");

    let (mut accepted, mut rejected) = (0, 0);
    for (prompt_val, expected_val) in paired_tests(prompt_group, expected_group) {
        let prompt: KeyCheckPrompt =
            serde_json::from_value(prompt_val.clone()).expect("Failed to parse prompt");
        let expected: KeyCheckExpected =
            serde_json::from_value(expected_val.clone()).expect("Failed to parse expected");

        assert_eq!(prompt.tc_id, expected.tc_id);

        let key = hex_decode(&prompt.key);
        assert_eq!(
            accepts(&key),
            expected.test_passed,
            "{} {} tcId={}: key check result mismatch",
            parameter_set,
            function,
            prompt.tc_id
        );
        if expected.test_passed {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(
        accepted > 0 && rejected > 0,
        "{} {}: expected both valid and invalid keys",
        parameter_set,
        function
    );
    println!(
        "{} {}: {} ACVP tests passed ({} rejected)",
        parameter_set,
        function,
        accepted + rejected,
        rejected
    );
}

#[cfg(feature = "ml-kem-512")]
mod key_check_512 {
    use super::*;
    use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps};

    #[test]
    fn test_acvp_encaps_key_check_ml_kem_512() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-512", "encapsulationKeyCheck", |ek| {
            ml_kem_encaps::<2, 3, 2, 10, 4>(ek, &[0u8; 32]).is_ok()
        });
    }

    #[test]
    fn test_acvp_decaps_key_check_ml_kem_512() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-512", "decapsulationKeyCheck", |dk| {
            ml_kem_decaps::<2, 3, 2, 10, 4>(dk, &[0u8; 768]).is_ok()
        });
    }
}

#[cfg(feature = "ml-kem-768")]
mod key_check_768 {
    use super::*;
    use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps};

    #[test]
    fn test_acvp_encaps_key_check_ml_kem_768() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-768", "encapsulationKeyCheck", |ek| {
            ml_kem_encaps::<3, 2, 2, 10, 4>(ek, &[0u8; 32]).is_ok()
        });
    }

    #[test]
    fn test_acvp_decaps_key_check_ml_kem_768() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-768", "decapsulationKeyCheck", |dk| {
            ml_kem_decaps::<3, 2, 2, 10, 4>(dk, &[0u8; 1088]).is_ok()
        });
    }
}

#[cfg(feature = "ml-kem-1024")]
mod key_check_1024 {
    use super::*;
    use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps};

    #[test]
    fn test_acvp_encaps_key_check_ml_kem_1024() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-1024", "encapsulationKeyCheck", |ek| {
            ml_kem_encaps::<4, 2, 2, 11, 5>(ek, &[0u8; 32]).is_ok()
        });
    }

    #[test]
    fn test_acvp_decaps_key_check_ml_kem_1024() {
        skip_if_no_vectors!();
        run_key_check("ML-KEM-1024", "decapsulationKeyCheck", |dk| {
            ml_kem_decaps::<4, 2, 2, 11, 5>(dk, &[0u8; 1568]).is_ok()
        });
    }
}
