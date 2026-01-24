//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for SLH-DSA.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

use serde::Deserialize;
use std::fs;

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
    sk_seed: String,
    sk_prf: String,
    pk_seed: String,
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
// KeyGen Tests - SHAKE Variants
// ============================================================================

#[cfg(feature = "slh-dsa-shake-128s")]
mod keygen_shake_128s {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake128Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const H_PRIME: usize = 9;
    const D: usize = 7;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_128s() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-128s")
            .expect("SLH-DSA-SHAKE-128s test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-128s KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-128s KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-128s KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "slh-dsa-shake-128f")]
mod keygen_shake_128f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake128Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const H_PRIME: usize = 3;
    const D: usize = 22;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_128f() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-128f")
            .expect("SLH-DSA-SHAKE-128f test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake128Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-128f KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-128f KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-128f KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "slh-dsa-shake-192s")]
mod keygen_shake_192s {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake192Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 24;
    const WOTS_LEN: usize = 51;
    const H_PRIME: usize = 9;
    const D: usize = 7;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_192s() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-192s")
            .expect("SLH-DSA-SHAKE-192s test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake192Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-192s KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-192s KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-192s KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "slh-dsa-shake-192f")]
mod keygen_shake_192f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake192Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 24;
    const WOTS_LEN: usize = 51;
    const H_PRIME: usize = 3;
    const D: usize = 22;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_192f() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-192f")
            .expect("SLH-DSA-SHAKE-192f test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake192Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-192f KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-192f KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-192f KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "slh-dsa-shake-256s")]
mod keygen_shake_256s {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake256Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 32;
    const WOTS_LEN: usize = 67;
    const H_PRIME: usize = 8;
    const D: usize = 8;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_256s() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-256s")
            .expect("SLH-DSA-SHAKE-256s test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake256Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-256s KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-256s KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-256s KeyGen: {} ACVP tests passed", passed);
    }
}

#[cfg(feature = "slh-dsa-shake-256f")]
mod keygen_shake_256f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake256Hash;
    use kylix_slh_dsa::sign::slh_keygen_internal;

    const N: usize = 32;
    const WOTS_LEN: usize = 67;
    const H_PRIME: usize = 4;
    const D: usize = 17;

    #[test]
    fn test_acvp_keygen_slh_dsa_shake_256f() {
        let prompt_file = load_keygen_prompt_file("tests/acvp/keygen_prompt.json");
        let expected_file = load_keygen_expected_file("tests/acvp/keygen_expected.json");

        let prompt_group = prompt_file
            .test_groups
            .iter()
            .find(|g| g.parameter_set == "SLH-DSA-SHAKE-256f")
            .expect("SLH-DSA-SHAKE-256f test group not found in prompt");

        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == prompt_group.tg_id)
            .expect("Expected test group not found");

        let mut passed = 0;
        for (prompt, expected) in prompt_group.tests.iter().zip(expected_group.tests.iter()) {
            assert_eq!(prompt.tc_id, expected.tc_id, "Test case ID mismatch");

            let sk_seed: [u8; N] = hex_decode(&prompt.sk_seed)
                .try_into()
                .expect("Invalid sk_seed length");
            let sk_prf: [u8; N] = hex_decode(&prompt.sk_prf)
                .try_into()
                .expect("Invalid sk_prf length");
            let pk_seed: [u8; N] = hex_decode(&prompt.pk_seed)
                .try_into()
                .expect("Invalid pk_seed length");

            let (sk, pk) = slh_keygen_internal::<Shake256Hash, N, WOTS_LEN, H_PRIME, D>(
                sk_seed, sk_prf, pk_seed,
            );

            let expected_pk = hex_decode(&expected.pk);
            let expected_sk = hex_decode(&expected.sk);

            assert_eq!(
                pk.to_bytes(),
                expected_pk,
                "SLH-DSA-SHAKE-256f KeyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk.to_bytes(),
                expected_sk,
                "SLH-DSA-SHAKE-256f KeyGen tcId={}: sk mismatch",
                prompt.tc_id
            );

            passed += 1;
        }
        println!("SLH-DSA-SHAKE-256f KeyGen: {} ACVP tests passed", passed);
    }
}

// ============================================================================
// SigVer Tests - SHAKE Variants
// ============================================================================

#[cfg(feature = "slh-dsa-shake-128f")]
mod sigver_shake_128f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake128Hash;
    use kylix_slh_dsa::sign::{slh_verify, PublicKey};

    const N: usize = 16;
    const WOTS_LEN: usize = 35;
    const WOTS_LEN1: usize = 32;
    const H_PRIME: usize = 3;
    const D: usize = 22;
    const K: usize = 33;
    const A: usize = 6;

    #[test]
    fn test_acvp_sigver_slh_dsa_shake_128f() {
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "SLH-DSA-SHAKE-128f" && g.signature_interface == "internal"
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("SLH-DSA-SHAKE-128f SigVer: No internal test groups found, skipping");
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

                let pk_bytes = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                let pk = match PublicKey::<N>::from_bytes(&pk_bytes) {
                    Some(pk) => pk,
                    None => {
                        assert!(
                            !expected.test_passed,
                            "tcId={}: Invalid PK should fail",
                            prompt.tc_id
                        );
                        total_passed += 1;
                        continue;
                    }
                };

                let result = slh_verify::<Shake128Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "SLH-DSA-SHAKE-128f SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!(
            "SLH-DSA-SHAKE-128f SigVer: {} ACVP tests passed",
            total_passed
        );
    }
}

#[cfg(feature = "slh-dsa-shake-192f")]
mod sigver_shake_192f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake192Hash;
    use kylix_slh_dsa::sign::{slh_verify, PublicKey};

    const N: usize = 24;
    const WOTS_LEN: usize = 51;
    const WOTS_LEN1: usize = 48;
    const H_PRIME: usize = 3;
    const D: usize = 22;
    const K: usize = 33;
    const A: usize = 8;

    #[test]
    fn test_acvp_sigver_slh_dsa_shake_192f() {
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "SLH-DSA-SHAKE-192f" && g.signature_interface == "internal"
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("SLH-DSA-SHAKE-192f SigVer: No internal test groups found, skipping");
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

                let pk_bytes = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                let pk = match PublicKey::<N>::from_bytes(&pk_bytes) {
                    Some(pk) => pk,
                    None => {
                        assert!(
                            !expected.test_passed,
                            "tcId={}: Invalid PK should fail",
                            prompt.tc_id
                        );
                        total_passed += 1;
                        continue;
                    }
                };

                let result = slh_verify::<Shake192Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "SLH-DSA-SHAKE-192f SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!(
            "SLH-DSA-SHAKE-192f SigVer: {} ACVP tests passed",
            total_passed
        );
    }
}

#[cfg(feature = "slh-dsa-shake-256f")]
mod sigver_shake_256f {
    use super::*;
    use kylix_slh_dsa::hash_shake::Shake256Hash;
    use kylix_slh_dsa::sign::{slh_verify, PublicKey};

    const N: usize = 32;
    const WOTS_LEN: usize = 67;
    const WOTS_LEN1: usize = 64;
    const H_PRIME: usize = 4;
    const D: usize = 17;
    const K: usize = 35;
    const A: usize = 9;

    #[test]
    fn test_acvp_sigver_slh_dsa_shake_256f() {
        let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
        let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

        let prompt_groups: Vec<_> = prompt_file
            .test_groups
            .iter()
            .filter(|g| {
                g.parameter_set == "SLH-DSA-SHAKE-256f" && g.signature_interface == "internal"
            })
            .collect();

        if prompt_groups.is_empty() {
            println!("SLH-DSA-SHAKE-256f SigVer: No internal test groups found, skipping");
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

                let pk_bytes = hex_decode(&prompt.pk);
                let message = hex_decode(&prompt.message);
                let signature = hex_decode(&prompt.signature);

                let pk = match PublicKey::<N>::from_bytes(&pk_bytes) {
                    Some(pk) => pk,
                    None => {
                        assert!(
                            !expected.test_passed,
                            "tcId={}: Invalid PK should fail",
                            prompt.tc_id
                        );
                        total_passed += 1;
                        continue;
                    }
                };

                let result = slh_verify::<Shake256Hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                    &pk, &message, &signature,
                );

                assert_eq!(
                    result, expected.test_passed,
                    "SLH-DSA-SHAKE-256f SigVer tcId={}: expected {}, got {}",
                    prompt.tc_id, expected.test_passed, result
                );
                total_passed += 1;
            }
        }
        println!(
            "SLH-DSA-SHAKE-256f SigVer: {} ACVP tests passed",
            total_passed
        );
    }
}
