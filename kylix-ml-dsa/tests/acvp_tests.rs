// Skip compilation entirely when no variant features are enabled
// (e.g., --no-default-features), since all test functions are feature-gated.
#![cfg(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]

//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for ML-DSA.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! Note: These tests are skipped when the test vectors are not present
//! (e.g., when running from crates.io package where they are excluded).

use kylix_test_util::acvp::{
    hex_decode, load_json, AcvpFile, ExpectedGroup, KeyGenExpected, SigVerExpected,
    SigVerInternalPrompt,
};
use kylix_test_util::skip_if_no_vectors;
use serde::Deserialize;

/// ACVP prompt file structure for KeyGen
type AcvpKeyGenPromptFile = AcvpFile<KeyGenPromptGroup>;

/// ACVP expected results file structure for KeyGen
type AcvpKeyGenExpectedFile = AcvpFile<ExpectedGroup<KeyGenExpected>>;

/// KeyGen test group in prompt file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPromptGroup {
    tg_id: u32,
    parameter_set: String,
    tests: Vec<KeyGenPrompt>,
}

/// KeyGen prompt test case
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPrompt {
    tc_id: u32,
    seed: String,
}

/// ACVP prompt file structure for SigVer
type AcvpSigVerPromptFile = AcvpFile<SigVerPromptGroup>;

/// ACVP expected results file structure for SigVer
type AcvpSigVerExpectedFile = AcvpFile<ExpectedGroup<SigVerExpected>>;

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
    #[serde(default)]
    external_mu: bool,
    tests: Vec<serde_json::Value>,
}

/// ACVP prompt file structure for SigGen
type AcvpSigGenPromptFile = AcvpFile<SigGenPromptGroup>;

/// ACVP expected results file structure for SigGen
type AcvpSigGenExpectedFile = AcvpFile<ExpectedGroup<SigGenExpected>>;

/// SigGen test group in prompt file
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenPromptGroup {
    tg_id: u32,
    parameter_set: String,
    deterministic: bool,
    signature_interface: String,
    #[serde(default)]
    external_mu: bool,
    tests: Vec<serde_json::Value>,
}

/// SigGen prompt test case (internal interface with raw message)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenInternalPrompt {
    tc_id: u32,
    sk: String,
    message: String,
}

/// SigGen expected result
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenExpected {
    tc_id: u32,
    signature: String,
}

fn load_keygen_prompt_file(path: &str) -> AcvpKeyGenPromptFile {
    load_json(path)
}

fn load_keygen_expected_file(path: &str) -> AcvpKeyGenExpectedFile {
    load_json(path)
}

fn load_sigver_prompt_file(path: &str) -> AcvpSigVerPromptFile {
    load_json(path)
}

fn load_sigver_expected_file(path: &str) -> AcvpSigVerExpectedFile {
    load_json(path)
}

fn load_siggen_prompt_file(path: &str) -> AcvpSigGenPromptFile {
    load_json(path)
}

fn load_siggen_expected_file(path: &str) -> AcvpSigGenExpectedFile {
    load_json(path)
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

// ============================================================================
// SigGen Tests
//
// Scope: only vector groups the current internal API can drive without
// guessing, i.e. signatureInterface == "internal" AND deterministic == true
// AND externalMu == false. Deterministic internal signing is defined with
// rnd = 0^32. External / context / preHash / externalMu groups are counted
// and reported as unsupported rather than silently dropped.
// ============================================================================

/// Drive the in-scope ACVP SigGen groups for one parameter set.
///
/// `expected_groups` / `expected_cases` / `expected_excluded` pin the
/// vector-selection result so a filter that silently matches nothing (or too
/// much, or quietly starts dropping groups) fails the test.
fn run_acvp_siggen<
    const K: usize,
    const L: usize,
    const ETA: usize,
    const BETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const TAU: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    parameter_set: &str,
    expected_groups: usize,
    expected_cases: usize,
    expected_excluded: usize,
) {
    let prompt_file = load_siggen_prompt_file("tests/acvp/siggen_prompt.json");
    let expected_file = load_siggen_expected_file("tests/acvp/siggen_expected.json");

    let mut in_scope = Vec::new();
    let mut excluded = 0usize;
    for group in &prompt_file.test_groups {
        if group.parameter_set != parameter_set {
            continue;
        }
        if group.signature_interface == "internal" && group.deterministic && !group.external_mu {
            in_scope.push(group);
        } else {
            excluded += 1;
        }
    }

    println!(
        "{} SigGen: {} in-scope group(s); {} group(s) excluded as unsupported by the current internal API (external interface, context, preHash, or externalMu)",
        parameter_set,
        in_scope.len(),
        excluded
    );
    assert_eq!(
        in_scope.len(),
        expected_groups,
        "{}: unexpected number of in-scope SigGen groups",
        parameter_set
    );
    assert_eq!(
        excluded, expected_excluded,
        "{}: unexpected number of excluded SigGen groups",
        parameter_set
    );

    // FIPS 204 deterministic variant of ML-DSA.Sign_internal.
    let rnd = [0u8; 32];
    let mut total_cases = 0usize;

    for group in in_scope {
        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .unwrap_or_else(|| panic!("Expected SigGen group tgId={} not found", group.tg_id));

        for prompt_val in &group.tests {
            let prompt: SigGenInternalPrompt = serde_json::from_value(prompt_val.clone())
                .expect("Failed to parse SigGen internal prompt");
            let expected = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == prompt.tc_id)
                .unwrap_or_else(|| {
                    panic!(
                        "Expected SigGen case tgId={} tcId={} not found",
                        group.tg_id, prompt.tc_id
                    )
                });

            let sk = hex_decode(&prompt.sk);
            let message = hex_decode(&prompt.message);
            let expected_sig = hex_decode(&expected.signature);

            let signature = kylix_ml_dsa::sign::ml_dsa_sign::<
                K,
                L,
                ETA,
                BETA,
                GAMMA1,
                GAMMA2,
                TAU,
                OMEGA,
                C_TILDE_BYTES,
            >(&sk, &message, &rnd)
            .unwrap_or_else(|| {
                panic!(
                    "{} SigGen tgId={} tcId={}: signing returned None",
                    parameter_set, group.tg_id, prompt.tc_id
                )
            });

            assert_eq!(
                signature, expected_sig,
                "{} SigGen tgId={} tcId={}: signature mismatch",
                parameter_set, group.tg_id, prompt.tc_id
            );
            total_cases += 1;
        }
    }

    assert_eq!(
        total_cases, expected_cases,
        "{}: unexpected number of in-scope SigGen cases",
        parameter_set
    );
    println!(
        "{} SigGen: {} ACVP tests passed",
        parameter_set, total_cases
    );
}

#[cfg(feature = "ml-dsa-44")]
#[test]
fn test_acvp_siggen_ml_dsa_44() {
    skip_if_no_vectors!();
    run_acvp_siggen::<4, 4, 2, 78, { 1 << 17 }, 95232, 39, 80, 32>("ML-DSA-44", 1, 15, 7);
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_acvp_siggen_ml_dsa_65() {
    skip_if_no_vectors!();
    run_acvp_siggen::<6, 5, 4, 196, { 1 << 19 }, 261888, 49, 55, 48>("ML-DSA-65", 1, 15, 7);
}

#[cfg(feature = "ml-dsa-87")]
#[test]
fn test_acvp_siggen_ml_dsa_87() {
    skip_if_no_vectors!();
    run_acvp_siggen::<8, 7, 2, 120, { 1 << 19 }, 261888, 60, 75, 64>("ML-DSA-87", 1, 15, 7);
}

// ============================================================================
// Expanded-verify equivalence characterization
//
// Pins that ml_dsa_verify_expanded agrees with ml_dsa_verify AND with the
// ACVP expected result on every in-scope SigVer case, including the invalid
// ones (malformed hints, non-canonical encodings, out-of-range z). Scoped like
// SigGen: internal interface, externalMu == false, raw message present.
// ============================================================================

/// Drive the in-scope ACVP SigVer groups through both verification entry
/// points for one parameter set.
fn run_expanded_verify_equivalence<
    const K: usize,
    const L: usize,
    const BETA: i32,
    const GAMMA1: i32,
    const GAMMA2: i32,
    const TAU: usize,
    const OMEGA: usize,
    const C_TILDE_BYTES: usize,
>(
    parameter_set: &str,
    expected_groups: usize,
    expected_cases: usize,
    expected_excluded: usize,
) {
    let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
    let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

    let mut in_scope = Vec::new();
    let mut excluded = 0usize;
    for group in &prompt_file.test_groups {
        if group.parameter_set != parameter_set {
            continue;
        }
        let has_message = group.tests.first().and_then(|t| t.get("message")).is_some();
        if group.signature_interface == "internal" && !group.external_mu && has_message {
            in_scope.push(group);
        } else {
            excluded += 1;
        }
    }

    println!(
        "{} expanded-verify equivalence: {} in-scope group(s); {} group(s) excluded as undrivable through the expanded API (external interface, context, preHash, or externalMu)",
        parameter_set,
        in_scope.len(),
        excluded
    );
    assert_eq!(
        in_scope.len(),
        expected_groups,
        "{}: unexpected number of in-scope SigVer groups",
        parameter_set
    );
    assert_eq!(
        excluded, expected_excluded,
        "{}: unexpected number of excluded SigVer groups",
        parameter_set
    );

    let mut total_cases = 0usize;
    for group in in_scope {
        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .unwrap_or_else(|| panic!("Expected SigVer group tgId={} not found", group.tg_id));

        for prompt_val in &group.tests {
            let prompt: SigVerInternalPrompt = serde_json::from_value(prompt_val.clone())
                .expect("Failed to parse SigVer internal prompt");
            let expected = expected_group
                .tests
                .iter()
                .find(|t| t.tc_id == prompt.tc_id)
                .unwrap_or_else(|| {
                    panic!(
                        "Expected SigVer case tgId={} tcId={} not found",
                        group.tg_id, prompt.tc_id
                    )
                });

            let pk = hex_decode(&prompt.pk);
            let message = hex_decode(&prompt.message);
            let signature = hex_decode(&prompt.signature);

            let plain = kylix_ml_dsa::sign::ml_dsa_verify::<
                K,
                L,
                BETA,
                GAMMA1,
                GAMMA2,
                TAU,
                OMEGA,
                C_TILDE_BYTES,
            >(&pk, &message, &signature);
            assert_eq!(
                plain, expected.test_passed,
                "{} SigVer tgId={} tcId={}: plain verify disagrees with ACVP",
                parameter_set, group.tg_id, prompt.tc_id
            );

            match kylix_ml_dsa::sign::expand_verification_key::<K, L>(&pk) {
                Some(exp_key) => {
                    let expanded = kylix_ml_dsa::sign::ml_dsa_verify_expanded::<
                        K,
                        L,
                        BETA,
                        GAMMA1,
                        GAMMA2,
                        TAU,
                        OMEGA,
                        C_TILDE_BYTES,
                    >(&exp_key, &message, &signature);
                    assert_eq!(
                        expanded, plain,
                        "{} SigVer tgId={} tcId={}: expanded verify disagrees with plain verify",
                        parameter_set, group.tg_id, prompt.tc_id
                    );
                }
                None => {
                    // A public key the expanded path refuses to parse must also
                    // be rejected by the plain path.
                    assert!(
                        !plain,
                        "{} SigVer tgId={} tcId={}: plain verify accepted a pk the expanded path rejects",
                        parameter_set, group.tg_id, prompt.tc_id
                    );
                }
            }
            total_cases += 1;
        }
    }

    assert_eq!(
        total_cases, expected_cases,
        "{}: unexpected number of in-scope SigVer cases",
        parameter_set
    );
    println!(
        "{} expanded-verify equivalence: {} ACVP cases agreed",
        parameter_set, total_cases
    );
}

#[cfg(feature = "ml-dsa-44")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_44() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<4, 4, 78, { 1 << 17 }, 95232, 39, 80, 32>(
        "ML-DSA-44",
        1,
        15,
        3,
    );
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_65() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<6, 5, 196, { 1 << 19 }, 261888, 49, 55, 48>(
        "ML-DSA-65",
        1,
        15,
        3,
    );
}

#[cfg(feature = "ml-dsa-87")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_87() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<8, 7, 120, { 1 << 19 }, 261888, 60, 75, 64>(
        "ML-DSA-87",
        1,
        15,
        3,
    );
}
