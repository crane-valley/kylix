#![cfg(feature = "any-variant")]

//! Cross-check of the public `Signer::sign` path against OpenSSL 3.6.0.
//!
//! Each case derives the key from sk_seed = 0x01^n, sk_prf = 0x02^n,
//! pk_seed = 0x03^n, signs `MESSAGE` with pure SLH-DSA, an empty context and
//! deterministic signing (opt_rand = PK.seed), and pins the first 32 bytes of
//! `SHAKE256(signature)` as lowercase hex. The expected values were produced by
//! OpenSSL with exactly these inputs, not by this crate:
//!
//!   printf 'kylix-fixture-v1' > msg.bin
//!   openssl genpkey -algorithm SLH-DSA-<set> -pkeyopt hexseed:<01^n 02^n 03^n> -out key.pem
//!   openssl pkeyutl -sign -rawin -inkey key.pem -in msg.bin -pkeyopt deterministic:1 -out sig.bin
//!   python -c "import hashlib; print(hashlib.shake_256(open('sig.bin','rb').read()).hexdigest(32))"

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

const MESSAGE: &[u8] = b"kylix-fixture-v1";

fn digest_hex(signature: &[u8]) -> String {
    let mut xof = Shake256::default();
    xof.update(signature);
    let mut out = [0u8; 32];
    xof.finalize_xof().read(&mut out);
    hex::encode(out)
}

macro_rules! openssl_case {
    ($feature:literal, $mod_name:ident, $variant:ident, $variant_mod:ident, $hash:ty, $params:ident, $expected:literal) => {
        #[cfg(feature = $feature)]
        mod $mod_name {
            use super::{digest_hex, MESSAGE};
            use kylix_slh_dsa::params::$params::*;
            use kylix_slh_dsa::sign::slh_keygen_internal;
            use kylix_slh_dsa::$variant_mod::SigningKey;
            use kylix_slh_dsa::{$variant, Signer};

            #[test]
            fn signature_matches_openssl() {
                let (sk, _pk) = slh_keygen_internal::<$hash, N, WOTS_LEN, H_PRIME, D>(
                    [0x01u8; N],
                    [0x02u8; N],
                    [0x03u8; N],
                );
                let signing_key = SigningKey::from_bytes(&sk.to_bytes()).unwrap();

                let signature = $variant::sign(&signing_key, MESSAGE).unwrap();

                assert_eq!(signature.as_bytes().len(), SIG_BYTES);
                assert_eq!(digest_hex(signature.as_bytes()), $expected);
            }
        }
    };
}

openssl_case!(
    "slh-dsa-shake-128s",
    shake_128s,
    SlhDsaShake128s,
    slh_dsa_shake_128s,
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128s,
    "5c9ac343aa59a1dae4e6d86d80be7232068d1428a24479602560151c7926a5f5"
);
openssl_case!(
    "slh-dsa-shake-128f",
    shake_128f,
    SlhDsaShake128f,
    slh_dsa_shake_128f,
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128f,
    "cfa3b13a6b311971feffffdcb54f0f03d30c121fdc776625484c70724f623eee"
);
openssl_case!(
    "slh-dsa-shake-192s",
    shake_192s,
    SlhDsaShake192s,
    slh_dsa_shake_192s,
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192s,
    "76061b0d5bce70b72304fed3a7159f7f84dd88cdeeee59ae27af4cb7bf019430"
);
openssl_case!(
    "slh-dsa-shake-192f",
    shake_192f,
    SlhDsaShake192f,
    slh_dsa_shake_192f,
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192f,
    "f0b5362bf1c9811ad6de195938a12975df3ef6b02d0dfcf2ce62f90c20ff8c03"
);
openssl_case!(
    "slh-dsa-shake-256s",
    shake_256s,
    SlhDsaShake256s,
    slh_dsa_shake_256s,
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256s,
    "5118d0993fbb3bf925b8fdc47cf16cc87ffb471d50acacba212f5b9903426b2a"
);
openssl_case!(
    "slh-dsa-shake-256f",
    shake_256f,
    SlhDsaShake256f,
    slh_dsa_shake_256f,
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256f,
    "774685757ab518b650d1d179de41a61038316a14808c95f2fa6ffc590e8cdc68"
);
openssl_case!(
    "slh-dsa-sha2-128s",
    sha2_128s,
    SlhDsaSha2_128s,
    slh_dsa_sha2_128s,
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128s,
    "67a8485063ebf4c8ceb86e102d2e50818847ec91e4f589e33b0b9cf2af086634"
);
openssl_case!(
    "slh-dsa-sha2-128f",
    sha2_128f,
    SlhDsaSha2_128f,
    slh_dsa_sha2_128f,
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128f,
    "7fc556c73fbac1e44835322d8798f96475f42418a89f15a84495980754cf9d42"
);
openssl_case!(
    "slh-dsa-sha2-192s",
    sha2_192s,
    SlhDsaSha2_192s,
    slh_dsa_sha2_192s,
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192s,
    "7a521e8311077c5a48480d20b37b271890a6792930446895fa0b74704acb79a7"
);
openssl_case!(
    "slh-dsa-sha2-192f",
    sha2_192f,
    SlhDsaSha2_192f,
    slh_dsa_sha2_192f,
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192f,
    "1e14b9cf95d12f3c86418bdd554857b30c456b93c41337ac97cd938b3fab7e9c"
);
openssl_case!(
    "slh-dsa-sha2-256s",
    sha2_256s,
    SlhDsaSha2_256s,
    slh_dsa_sha2_256s,
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256s,
    "58d8e6f8138890700d6982ceb6ae88c558c630e89c45ddeb084c9058cbffdc74"
);
openssl_case!(
    "slh-dsa-sha2-256f",
    sha2_256f,
    SlhDsaSha2_256f,
    slh_dsa_sha2_256f,
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256f,
    "95a2cc82f77d8df774799025340e9efaad95986d9aad4002c97121cbeb4e7c20"
);
