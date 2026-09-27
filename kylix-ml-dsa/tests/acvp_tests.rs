// Skip compilation entirely when no variant features are enabled
// (e.g., --no-default-features), since all test functions are feature-gated.
#![cfg(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87"))]

//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for ML-DSA.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! These tests are skipped when a partial source archive omits the vectors.

use kylix_test_util::acvp::{
    hex_decode, load_json, AcvpFile, ExpectedGroup, KeyGenExpected, SigVerExpected,
    SigVerInternalPrompt,
};
use kylix_test_util::skip_if_no_vectors;
use serde::Deserialize;
use std::collections::BTreeMap;

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
    pre_hash: Option<String>,
    #[serde(default)]
    external_mu: bool,
    tests: Vec<serde_json::Value>,
}

/// Per-case signer input; which fields are present depends on the group.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageFields {
    message: Option<String>,
    mu: Option<String>,
    context: Option<String>,
    hash_alg: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigGenPrompt {
    tc_id: u32,
    sk: String,
    rnd: Option<String>,
    #[serde(flatten)]
    input: MessageFields,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerPrompt {
    tc_id: u32,
    pk: String,
    signature: String,
    #[serde(flatten)]
    input: MessageFields,
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
    use kylix_ml_dsa::ml_dsa_44::{SigningKey, VerificationKey};

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
    use kylix_ml_dsa::ml_dsa_65::{SigningKey, VerificationKey};

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
    use kylix_ml_dsa::ml_dsa_87::{SigningKey, VerificationKey};

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
// SigGen / SigVer over every ACVP group
//
// FIPS 204 reduces every signature interface to Sign_internal/Verify_internal:
// the external pure and preHash interfaces pass M' (Algorithms 2-5), and the
// externalMu groups pass mu itself. The harness builds that input per group,
// so each group in the vector files runs; unknown group shapes panic.
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKind {
    Internal,
    ExternalMu,
    ExternalPure,
    ExternalPreHash,
}

fn group_kind(signature_interface: &str, pre_hash: Option<&str>, external_mu: bool) -> GroupKind {
    match (signature_interface, pre_hash, external_mu) {
        ("internal", _, false) => GroupKind::Internal,
        ("internal", _, true) => GroupKind::ExternalMu,
        ("external", Some("pure"), false) => GroupKind::ExternalPure,
        ("external", Some("preHash"), false) => GroupKind::ExternalPreHash,
        other => panic!("unsupported ACVP group shape {other:?}"),
    }
}

enum InternalInput {
    Message(Vec<u8>),
    Mu([u8; 64]),
}

fn required(field: &Option<String>, name: &str) -> Vec<u8> {
    hex_decode(
        field
            .as_deref()
            .unwrap_or_else(|| panic!("ACVP case is missing `{name}`")),
    )
}

fn fixed_digest<D: sha2::Digest>(msg: &[u8]) -> Vec<u8> {
    D::digest(msg).to_vec()
}

fn xof_digest<X>(msg: &[u8], len: usize) -> Vec<u8>
where
    X: Default + sha3::digest::Update + sha3::digest::ExtendableOutput,
{
    let mut xof = X::default();
    sha3::digest::Update::update(&mut xof, msg);
    let mut out = vec![0u8; len];
    xof.finalize_xof_into(&mut out);
    out
}

/// Last byte of the DER OID 2.16.840.1.101.3.4.2.x and PH(M) per FIPS 204
/// Algorithm 4.
fn pre_hash(hash_alg: &str, msg: &[u8]) -> (u8, Vec<u8>) {
    match hash_alg {
        "SHA2-256" => (0x01, fixed_digest::<sha2::Sha256>(msg)),
        "SHA2-384" => (0x02, fixed_digest::<sha2::Sha384>(msg)),
        "SHA2-512" => (0x03, fixed_digest::<sha2::Sha512>(msg)),
        "SHA2-224" => (0x04, fixed_digest::<sha2::Sha224>(msg)),
        "SHA2-512/224" => (0x05, fixed_digest::<sha2::Sha512_224>(msg)),
        "SHA2-512/256" => (0x06, fixed_digest::<sha2::Sha512_256>(msg)),
        "SHA3-224" => (0x07, fixed_digest::<sha3::Sha3_224>(msg)),
        "SHA3-256" => (0x08, fixed_digest::<sha3::Sha3_256>(msg)),
        "SHA3-384" => (0x09, fixed_digest::<sha3::Sha3_384>(msg)),
        "SHA3-512" => (0x0a, fixed_digest::<sha3::Sha3_512>(msg)),
        "SHAKE-128" => (0x0b, xof_digest::<sha3::Shake128>(msg, 32)),
        "SHAKE-256" => (0x0c, xof_digest::<sha3::Shake256>(msg, 64)),
        other => panic!("unsupported ACVP hashAlg {other}"),
    }
}

fn internal_input(kind: GroupKind, fields: &MessageFields) -> InternalInput {
    match kind {
        GroupKind::Internal => InternalInput::Message(required(&fields.message, "message")),
        GroupKind::ExternalMu => InternalInput::Mu(
            required(&fields.mu, "mu")
                .try_into()
                .expect("mu must be 64 bytes"),
        ),
        GroupKind::ExternalPure | GroupKind::ExternalPreHash => {
            let ctx = required(&fields.context, "context");
            let msg = required(&fields.message, "message");
            let mut m_prime = vec![
                u8::from(kind == GroupKind::ExternalPreHash),
                u8::try_from(ctx.len()).expect("context longer than 255 bytes"),
            ];
            m_prime.extend_from_slice(&ctx);
            if kind == GroupKind::ExternalPure {
                m_prime.extend_from_slice(&msg);
            } else {
                let hash_alg = fields.hash_alg.as_deref().expect("missing hashAlg");
                let (oid_last, digest) = pre_hash(hash_alg, &msg);
                m_prime.extend_from_slice(&[
                    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid_last,
                ]);
                m_prime.extend_from_slice(&digest);
            }
            InternalInput::Message(m_prime)
        }
    }
}

/// Drive every ACVP SigGen group for one parameter set.
///
/// `expected_groups` / `expected_cases` pin the vector-selection result so a
/// loader that silently matches nothing (or drops groups) fails the test.
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
) {
    let prompt_file = load_siggen_prompt_file("tests/acvp/siggen_prompt.json");
    let expected_file = load_siggen_expected_file("tests/acvp/siggen_expected.json");

    let mut groups = 0usize;
    let mut per_kind = BTreeMap::<(GroupKind, bool), usize>::new();
    for group in prompt_file
        .test_groups
        .iter()
        .filter(|g| g.parameter_set == parameter_set)
    {
        groups += 1;
        let kind = group_kind(
            &group.signature_interface,
            group.pre_hash.as_deref(),
            group.external_mu,
        );
        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .unwrap_or_else(|| panic!("Expected SigGen group tgId={} not found", group.tg_id));

        for prompt_val in &group.tests {
            let prompt: SigGenPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse SigGen prompt");
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
            // The deterministic variant of ML-DSA.Sign_internal uses rnd = 0^32.
            let rnd: [u8; 32] = if group.deterministic {
                [0u8; 32]
            } else {
                required(&prompt.rnd, "rnd")
                    .try_into()
                    .expect("rnd must be 32 bytes")
            };
            let expected_sig = hex_decode(&expected.signature);

            let signature = match internal_input(kind, &prompt.input) {
                InternalInput::Message(m) => kylix_ml_dsa::sign::ml_dsa_sign::<
                    K,
                    L,
                    ETA,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(&sk, &m, &rnd),
                InternalInput::Mu(mu) => kylix_ml_dsa::sign::ml_dsa_sign_mu::<
                    K,
                    L,
                    ETA,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(&sk, &mu, &rnd),
            }
            .unwrap_or_else(|| {
                panic!(
                    "{} SigGen tgId={} tcId={}: signing returned None",
                    parameter_set, group.tg_id, prompt.tc_id
                )
            });

            assert_eq!(
                signature, expected_sig,
                "{} SigGen tgId={} tcId={} ({:?}): signature mismatch",
                parameter_set, group.tg_id, prompt.tc_id, kind
            );
            *per_kind.entry((kind, group.deterministic)).or_default() += 1;
        }
    }

    let total_cases: usize = per_kind.values().sum();
    println!(
        "{} SigGen: {} group(s), {} ACVP tests passed; (kind, deterministic) -> cases: {:?}",
        parameter_set, groups, total_cases, per_kind
    );
    assert_eq!(
        groups, expected_groups,
        "{}: unexpected number of SigGen groups",
        parameter_set
    );
    assert_eq!(
        total_cases, expected_cases,
        "{}: unexpected number of SigGen cases",
        parameter_set
    );
}

#[cfg(feature = "ml-dsa-44")]
#[test]
fn test_acvp_siggen_ml_dsa_44() {
    skip_if_no_vectors!();
    run_acvp_siggen::<4, 4, 2, 78, { 1 << 17 }, 95232, 39, 80, 32>("ML-DSA-44", 8, 120);
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_acvp_siggen_ml_dsa_65() {
    skip_if_no_vectors!();
    run_acvp_siggen::<6, 5, 4, 196, { 1 << 19 }, 261888, 49, 55, 48>("ML-DSA-65", 8, 120);
}

#[cfg(feature = "ml-dsa-87")]
#[test]
fn test_acvp_siggen_ml_dsa_87() {
    skip_if_no_vectors!();
    run_acvp_siggen::<8, 7, 2, 120, { 1 << 19 }, 261888, 60, 75, 64>("ML-DSA-87", 8, 120);
}

/// Drive every ACVP SigVer group for one parameter set through plain
/// verification, and every group with a message through the pre-expanded
/// entry point as well (it has no external-mu variant).
///
/// Pins that ml_dsa_verify_expanded agrees with ml_dsa_verify AND with the
/// ACVP expected result, including the invalid cases (malformed hints,
/// non-canonical encodings, out-of-range z).
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
) {
    let prompt_file = load_sigver_prompt_file("tests/acvp/sigver_prompt.json");
    let expected_file = load_sigver_expected_file("tests/acvp/sigver_expected.json");

    let mut groups = 0usize;
    let mut per_kind = BTreeMap::<GroupKind, usize>::new();
    for group in prompt_file
        .test_groups
        .iter()
        .filter(|g| g.parameter_set == parameter_set)
    {
        groups += 1;
        let kind = group_kind(
            &group.signature_interface,
            group.pre_hash.as_deref(),
            group.external_mu,
        );
        let expected_group = expected_file
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .unwrap_or_else(|| panic!("Expected SigVer group tgId={} not found", group.tg_id));

        for prompt_val in &group.tests {
            let prompt: SigVerPrompt =
                serde_json::from_value(prompt_val.clone()).expect("Failed to parse SigVer prompt");
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
            let signature = hex_decode(&prompt.signature);

            match internal_input(kind, &prompt.input) {
                InternalInput::Mu(mu) => {
                    let plain = kylix_ml_dsa::sign::ml_dsa_verify_mu::<
                        K,
                        L,
                        BETA,
                        GAMMA1,
                        GAMMA2,
                        TAU,
                        OMEGA,
                        C_TILDE_BYTES,
                    >(&pk, &mu, &signature);
                    assert_eq!(
                        plain, expected.test_passed,
                        "{} SigVer tgId={} tcId={} ({:?}): verify disagrees with ACVP",
                        parameter_set, group.tg_id, prompt.tc_id, kind
                    );
                }
                InternalInput::Message(message) => {
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
                        "{} SigVer tgId={} tcId={} ({:?}): plain verify disagrees with ACVP",
                        parameter_set, group.tg_id, prompt.tc_id, kind
                    );

                    match kylix_ml_dsa::sign::expand_verification_key::<K, L>(&pk) {
                        Some(exp_key) => {
                            let expanded =
                                kylix_ml_dsa::sign::ml_dsa_verify_expanded::<
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
                }
            }
            *per_kind.entry(kind).or_default() += 1;
        }
    }

    let total_cases: usize = per_kind.values().sum();
    println!(
        "{} SigVer: {} group(s), {} ACVP cases agreed; kind -> cases: {:?}",
        parameter_set, groups, total_cases, per_kind
    );
    assert_eq!(
        groups, expected_groups,
        "{}: unexpected number of SigVer groups",
        parameter_set
    );
    assert_eq!(
        total_cases, expected_cases,
        "{}: unexpected number of SigVer cases",
        parameter_set
    );
}

#[cfg(feature = "ml-dsa-44")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_44() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<4, 4, 78, { 1 << 17 }, 95232, 39, 80, 32>("ML-DSA-44", 4, 60);
}

#[cfg(feature = "ml-dsa-65")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_65() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<6, 5, 196, { 1 << 19 }, 261888, 49, 55, 48>(
        "ML-DSA-65",
        4,
        60,
    );
}

#[cfg(feature = "ml-dsa-87")]
#[test]
fn test_expanded_verify_equivalence_ml_dsa_87() {
    skip_if_no_vectors!();
    run_expanded_verify_equivalence::<8, 7, 120, { 1 << 19 }, 261888, 60, 75, 64>(
        "ML-DSA-87",
        4,
        60,
    );
}
