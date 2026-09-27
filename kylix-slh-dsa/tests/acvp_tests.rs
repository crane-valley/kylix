// Skip compilation when no SLH-DSA variant feature is enabled
// (e.g., --no-default-features). The `any-variant` meta-feature is activated
// by each concrete variant feature (slh-dsa-shake-*, slh-dsa-sha2-*).
#![cfg(feature = "any-variant")]

//! NIST ACVP (Automated Cryptographic Validation Protocol) tests for SLH-DSA.
//!
//! These tests use official NIST test vectors from:
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//!
//! Every keyGen group and every sigVer group (internal, external/pure and
//! external/preHash) is run for each enabled parameter set. The external
//! groups are driven through the internal verify entry point with M' built
//! here as specified in FIPS 205, Algorithms 24 and 25.
//!
//! These tests are skipped when a partial source archive omits the vectors.

use kylix_test_util::acvp::{
    hex_decode, load_json, AcvpFile, ExpectedGroup, KeyGenExpected, SigVerExpected,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPromptGroup {
    tg_id: u32,
    parameter_set: String,
    tests: Vec<KeyGenPrompt>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenPrompt {
    tc_id: u32,
    sk_seed: String,
    sk_prf: String,
    pk_seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerPromptGroup {
    tg_id: u32,
    parameter_set: String,
    signature_interface: String,
    pre_hash: Option<String>,
    tests: Vec<SigVerPrompt>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigVerPrompt {
    tc_id: u32,
    pk: String,
    message: String,
    signature: String,
    context: Option<String>,
    hash_alg: Option<String>,
}

type KeyGenFn<'a> = &'a dyn Fn(&[u8], &[u8], &[u8]) -> (Vec<u8>, Vec<u8>);

type VerifyFn<'a> = &'a dyn Fn(&[u8], &[u8], &[u8]) -> bool;

fn run_keygen(parameter_set: &str, keygen: KeyGenFn<'_>) -> usize {
    let prompt: AcvpFile<KeyGenPromptGroup> = load_json("tests/acvp/keygen_prompt.json");
    let expected: AcvpFile<ExpectedGroup<KeyGenExpected>> =
        load_json("tests/acvp/keygen_expected.json");

    let mut passed = 0;
    for group in prompt
        .test_groups
        .iter()
        .filter(|g| g.parameter_set == parameter_set)
    {
        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .expect("expected keyGen group not found");
        assert_eq!(
            group.tests.len(),
            expected_group.tests.len(),
            "{parameter_set} keyGen tgId={}: prompt/expected test count mismatch",
            group.tg_id
        );

        for (prompt, expected) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(prompt.tc_id, expected.tc_id, "test case ID mismatch");
            let (pk, sk) = keygen(
                &hex_decode(&prompt.sk_seed),
                &hex_decode(&prompt.sk_prf),
                &hex_decode(&prompt.pk_seed),
            );
            assert_eq!(
                pk,
                hex_decode(&expected.pk),
                "{parameter_set} keyGen tcId={}: pk mismatch",
                prompt.tc_id
            );
            assert_eq!(
                sk,
                hex_decode(&expected.sk),
                "{parameter_set} keyGen tcId={}: sk mismatch",
                prompt.tc_id
            );
            passed += 1;
        }
    }
    assert!(passed > 0, "no keyGen vectors for {parameter_set}");
    passed
}

/// Returns OID || PH(M) for HashSLH-DSA (FIPS 205, Algorithms 23 and 25).
///
/// The OIDs are the DER encodings of the NIST hash algorithm arc
/// 2.16.840.1.101.3.4.2.x.
fn pre_hash_body(hash_alg: &str, message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    fn xof<X: Default + Update + ExtendableOutput>(message: &[u8], len: usize) -> Vec<u8> {
        let mut hasher = X::default();
        hasher.update(message);
        let mut out = vec![0u8; len];
        hasher.finalize_xof().read(&mut out);
        out
    }

    let (oid_last, digest) = match hash_alg {
        "SHA2-256" => (0x01, sha2::Sha256::digest(message).to_vec()),
        "SHA2-384" => (0x02, sha2::Sha384::digest(message).to_vec()),
        "SHA2-512" => (0x03, sha2::Sha512::digest(message).to_vec()),
        "SHA2-224" => (0x04, sha2::Sha224::digest(message).to_vec()),
        "SHA2-512/224" => (0x05, sha2::Sha512_224::digest(message).to_vec()),
        "SHA2-512/256" => (0x06, sha2::Sha512_256::digest(message).to_vec()),
        "SHA3-224" => (0x07, sha3::Sha3_224::digest(message).to_vec()),
        "SHA3-256" => (0x08, sha3::Sha3_256::digest(message).to_vec()),
        "SHA3-384" => (0x09, sha3::Sha3_384::digest(message).to_vec()),
        "SHA3-512" => (0x0A, sha3::Sha3_512::digest(message).to_vec()),
        "SHAKE-128" => (0x0B, xof::<sha3::Shake128>(message, 32)),
        "SHAKE-256" => (0x0C, xof::<sha3::Shake256>(message, 64)),
        other => panic!("unsupported preHash algorithm {other}"),
    };
    let mut body = vec![
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid_last,
    ];
    body.extend_from_slice(&digest);
    body
}

/// M' = toByte(domain, 1) || toByte(|ctx|, 1) || ctx || body.
fn external_message(domain: u8, context: &[u8], body: &[u8]) -> Vec<u8> {
    let context_len = u8::try_from(context.len()).expect("context longer than 255 bytes");
    let mut m_prime = vec![domain, context_len];
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(body);
    m_prime
}

/// Expected M' values were computed outside this crate: the OID DER bytes by
/// `openssl asn1parse -genstr OID:2.16.840.1.101.3.4.2.<11|7>` (OpenSSL
/// 3.6.0), PH(M) by Python `hashlib.shake_128(m).digest(32)` and
/// `hashlib.sha3_224(m).digest()`. These two algorithms have no expected-accept
/// preHash case in the ACVP vectors, and OpenSSL 3.6.0 rejects HashSLH-DSA
/// (`pkeyutl -digest` is not supported with SLH-DSA), so this pins them instead.
#[test]
fn pre_hash_message_known_answers() {
    const CONTEXT: &[u8] = b"kylix-ctx";
    const MESSAGE: &[u8] = b"kylix-prehash-v1";
    for (hash_alg, expected) in [
        (
            "SHAKE-128",
            "01096b796c69782d637478060960864801650304020b1518d2368bffe798135b88ceac97b54bcdcdfc373e88f58e78f3479b918c4dff",
        ),
        (
            "SHA3-224",
            "01096b796c69782d637478060960864801650304020735630613c8770cc478d791bfe5d01797f32492fba32eef5111d19269",
        ),
    ] {
        let m_prime = external_message(1, CONTEXT, &pre_hash_body(hash_alg, MESSAGE));
        assert_eq!(hex::encode(m_prime), expected, "{hash_alg} M' mismatch");
    }
}

#[test]
fn pre_hash_algorithms_have_positive_vectors() {
    kylix_test_util::skip_if_no_vectors!();
    const PINNED_WITHOUT_POSITIVES: [&str; 2] = ["SHAKE-128", "SHA3-224"];

    let prompt: AcvpFile<SigVerPromptGroup> = load_json("tests/acvp/sigver_prompt.json");
    let expected: AcvpFile<ExpectedGroup<SigVerExpected>> =
        load_json("tests/acvp/sigver_expected.json");

    let mut accepted = std::collections::BTreeMap::<&str, usize>::new();
    for group in prompt
        .test_groups
        .iter()
        .filter(|g| g.pre_hash.as_deref() == Some("preHash"))
    {
        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .expect("expected sigVer group not found");
        for (prompt, expected) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(prompt.tc_id, expected.tc_id, "test case ID mismatch");
            let hash_alg = prompt.hash_alg.as_deref().expect("preHash without hashAlg");
            *accepted.entry(hash_alg).or_default() += usize::from(expected.test_passed);
        }
    }
    const ALL_PRE_HASH_ALGS: [&str; 12] = [
        "SHA2-224",
        "SHA2-256",
        "SHA2-384",
        "SHA2-512",
        "SHA2-512/224",
        "SHA2-512/256",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "SHAKE-128",
        "SHAKE-256",
    ];
    let present: Vec<&str> = accepted.keys().copied().collect();
    let mut expected_algs = ALL_PRE_HASH_ALGS;
    expected_algs.sort_unstable();
    assert_eq!(
        present, expected_algs,
        "preHash algorithms in sigVer vectors"
    );
    for (hash_alg, count) in &accepted {
        assert!(
            *count > 0 || PINNED_WITHOUT_POSITIVES.contains(hash_alg),
            "preHash {hash_alg}: no expected-accept vector and no pinned M'"
        );
    }
}

#[derive(Default)]
struct SigVerCounts {
    internal: usize,
    pure: usize,
    pre_hash: usize,
    accepted: usize,
}

fn run_sigver(parameter_set: &str, verify: VerifyFn<'_>) -> SigVerCounts {
    let prompt: AcvpFile<SigVerPromptGroup> = load_json("tests/acvp/sigver_prompt.json");
    let expected: AcvpFile<ExpectedGroup<SigVerExpected>> =
        load_json("tests/acvp/sigver_expected.json");

    let mut counts = SigVerCounts::default();
    for group in prompt
        .test_groups
        .iter()
        .filter(|g| g.parameter_set == parameter_set)
    {
        let expected_group = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == group.tg_id)
            .expect("expected sigVer group not found");
        assert_eq!(
            group.tests.len(),
            expected_group.tests.len(),
            "{parameter_set} sigVer tgId={}: prompt/expected test count mismatch",
            group.tg_id
        );

        for (prompt, expected) in group.tests.iter().zip(&expected_group.tests) {
            assert_eq!(prompt.tc_id, expected.tc_id, "test case ID mismatch");

            let message = hex_decode(&prompt.message);
            let context = prompt
                .context
                .as_deref()
                .map(hex_decode)
                .unwrap_or_default();
            let (m_prime, counter) = match (
                group.signature_interface.as_str(),
                group.pre_hash.as_deref(),
            ) {
                ("internal", None) => (message, &mut counts.internal),
                ("external", Some("pure")) => {
                    (external_message(0, &context, &message), &mut counts.pure)
                }
                ("external", Some("preHash")) => {
                    let hash_alg = prompt.hash_alg.as_deref().expect("preHash without hashAlg");
                    (
                        external_message(1, &context, &pre_hash_body(hash_alg, &message)),
                        &mut counts.pre_hash,
                    )
                }
                (interface, pre_hash) => {
                    panic!("unsupported sigVer group: interface={interface}, preHash={pre_hash:?}")
                }
            };

            let result = verify(
                &hex_decode(&prompt.pk),
                &m_prime,
                &hex_decode(&prompt.signature),
            );
            assert_eq!(
                result, expected.test_passed,
                "{parameter_set} sigVer tgId={} tcId={}: expected {}, got {}",
                group.tg_id, prompt.tc_id, expected.test_passed, result
            );
            *counter += 1;
            if result {
                counts.accepted += 1;
            }
        }
    }
    assert!(
        counts.internal > 0 && counts.pure > 0 && counts.pre_hash > 0,
        "{parameter_set}: missing internal, external/pure or external/preHash sigVer vectors"
    );
    assert!(
        counts.accepted > 0,
        "{parameter_set}: no sigVer vector expected to verify"
    );
    counts
}

macro_rules! acvp_parameter_set {
    ($feature:literal, $mod_name:ident, $parameter_set:literal, $hash:ty, $params:ident) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use kylix_slh_dsa::params::$params::*;
            use kylix_slh_dsa::sign::{slh_keygen_internal, slh_verify, PublicKey};

            #[test]
            fn keygen() {
                kylix_test_util::skip_if_no_vectors!();
                let passed = super::run_keygen($parameter_set, &|sk_seed, sk_prf, pk_seed| {
                    let (sk, pk) = slh_keygen_internal::<$hash, N, WOTS_LEN, H_PRIME, D>(
                        sk_seed.try_into().expect("invalid sk_seed length"),
                        sk_prf.try_into().expect("invalid sk_prf length"),
                        pk_seed.try_into().expect("invalid pk_seed length"),
                    );
                    (pk.to_bytes(), sk.to_bytes().to_vec())
                });
                println!("{} keyGen: {passed} ACVP tests passed", $parameter_set);
            }

            #[test]
            fn sigver() {
                kylix_test_util::skip_if_no_vectors!();
                let counts = super::run_sigver($parameter_set, &|pk, message, signature| {
                    PublicKey::<N>::from_bytes(pk).is_some_and(|pk| {
                        slh_verify::<$hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(
                            &pk, message, signature,
                        )
                    })
                });
                println!(
                    "{} sigVer: internal {}, external/pure {}, external/preHash {} ACVP tests passed ({} accepted)",
                    $parameter_set, counts.internal, counts.pure, counts.pre_hash, counts.accepted
                );
            }
        }
    };
}

acvp_parameter_set!(
    "slh-dsa-shake-128s",
    shake_128s,
    "SLH-DSA-SHAKE-128s",
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128s
);
acvp_parameter_set!(
    "slh-dsa-shake-128f",
    shake_128f,
    "SLH-DSA-SHAKE-128f",
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128f
);
acvp_parameter_set!(
    "slh-dsa-shake-192s",
    shake_192s,
    "SLH-DSA-SHAKE-192s",
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192s
);
acvp_parameter_set!(
    "slh-dsa-shake-192f",
    shake_192f,
    "SLH-DSA-SHAKE-192f",
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192f
);
acvp_parameter_set!(
    "slh-dsa-shake-256s",
    shake_256s,
    "SLH-DSA-SHAKE-256s",
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256s
);
acvp_parameter_set!(
    "slh-dsa-shake-256f",
    shake_256f,
    "SLH-DSA-SHAKE-256f",
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256f
);
acvp_parameter_set!(
    "slh-dsa-sha2-128s",
    sha2_128s,
    "SLH-DSA-SHA2-128s",
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128s
);
acvp_parameter_set!(
    "slh-dsa-sha2-128f",
    sha2_128f,
    "SLH-DSA-SHA2-128f",
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128f
);
acvp_parameter_set!(
    "slh-dsa-sha2-192s",
    sha2_192s,
    "SLH-DSA-SHA2-192s",
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192s
);
acvp_parameter_set!(
    "slh-dsa-sha2-192f",
    sha2_192f,
    "SLH-DSA-SHA2-192f",
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192f
);
acvp_parameter_set!(
    "slh-dsa-sha2-256s",
    sha2_256s,
    "SLH-DSA-SHA2-256s",
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256s
);
acvp_parameter_set!(
    "slh-dsa-sha2-256f",
    sha2_256f,
    "SLH-DSA-SHA2-256f",
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256f
);
