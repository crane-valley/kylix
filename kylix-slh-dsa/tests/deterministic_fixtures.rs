// Requires every variant feature: the oracle is only meaningful when all 12
// parameter sets are covered, and gating the whole file keeps default and
// --no-default-features builds compiling.
#![cfg(all(
    feature = "slh-dsa-shake-128s",
    feature = "slh-dsa-shake-128f",
    feature = "slh-dsa-shake-192s",
    feature = "slh-dsa-shake-192f",
    feature = "slh-dsa-shake-256s",
    feature = "slh-dsa-shake-256f",
    feature = "slh-dsa-sha2-128s",
    feature = "slh-dsa-sha2-128f",
    feature = "slh-dsa-sha2-192s",
    feature = "slh-dsa-sha2-192f",
    feature = "slh-dsa-sha2-256s",
    feature = "slh-dsa-sha2-256f"
))]

//! Deterministic SLH-DSA signature fixtures for all 12 parameter sets.
//!
//! Every fixture derives a key pair from fixed seeds, signs a fixed message
//! with fixed `opt_rand`, and pins the first 32 bytes of
//! `SHAKE256(signature)` as lowercase hex. SHAKE-256 is variable length, so
//! fixing both the output length and the encoding makes the constant
//! unambiguous.
//!
//! The digests must be identical with and without the `parallel` feature:
//! the two arms are separate copies of the signing path, and this file is the
//! byte-level oracle that keeps them in agreement.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Fixed message for every fixture. Changing it invalidates all digests.
const MESSAGE: &[u8] = b"kylix-fixture-v1";

fn digest_hex(signature: &[u8]) -> String {
    let mut xof = Shake256::default();
    xof.update(signature);
    let mut out = [0u8; 32];
    xof.finalize_xof().read(&mut out);
    hex::encode(out)
}

macro_rules! fixture {
    ($mod_name:ident, $hash:ty, $params:ident, $expected:literal) => {
        mod $mod_name {
            use super::{digest_hex, MESSAGE};
            use kylix_slh_dsa::params::$params::*;
            use kylix_slh_dsa::sign::{slh_keygen_internal, slh_sign};

            #[test]
            fn deterministic_signature_digest() {
                let sk_seed = [0x01u8; N];
                let sk_prf = [0x02u8; N];
                let pk_seed = [0x03u8; N];
                let opt_rand = [0x04u8; N];

                let (sk, _pk) =
                    slh_keygen_internal::<$hash, N, WOTS_LEN, H_PRIME, D>(sk_seed, sk_prf, pk_seed);

                let signature = slh_sign::<
                    $hash,
                    N,
                    WOTS_LEN,
                    WOTS_LEN1,
                    H_PRIME,
                    D,
                    K,
                    A,
                    MD_BYTES,
                >(&sk, MESSAGE, Some(&opt_rand));

                assert_eq!(signature.len(), SIG_BYTES, "unexpected signature length");
                assert_eq!(
                    digest_hex(&signature),
                    $expected,
                    "signature bytes changed for {}",
                    stringify!($mod_name)
                );
            }
        }
    };
}

fixture!(
    shake_128s,
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128s,
    "cab906e46127c682618ee7063aabca8e2b33bd6160815d2a79b4b9d469568cba"
);
fixture!(
    shake_128f,
    kylix_slh_dsa::Shake128Hash,
    slh_dsa_shake_128f,
    "01fbaa2b8a01248d400d3473fa2b4988f5a89ad71d67e107351703f30ba4b6e2"
);
fixture!(
    shake_192s,
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192s,
    "1782386afb2b4aa2f7c55db086c4b28af82cdedb3fc455f3f5a114e992b41cc3"
);
fixture!(
    shake_192f,
    kylix_slh_dsa::Shake192Hash,
    slh_dsa_shake_192f,
    "c62f6bd5009505a20d4a45bda1e5ee0cf6dab501275369c57dd0d04d0094b0f0"
);
fixture!(
    shake_256s,
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256s,
    "1b7b5b619dc2c8a954ad8d19887effa0b64db4dc49dfa09b5abc4395be34e32c"
);
fixture!(
    shake_256f,
    kylix_slh_dsa::Shake256Hash,
    slh_dsa_shake_256f,
    "a99b87f2cca3df2bdc081f09b445a685faf59f81d36f51b873c9102235b3b4a0"
);
fixture!(
    sha2_128s,
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128s,
    "abe9de2f325020f58e8344f0ebd7eaaa97ed7590475df39955f400e3c96a99f5"
);
fixture!(
    sha2_128f,
    kylix_slh_dsa::Sha2_128Hash,
    slh_dsa_sha2_128f,
    "bc7838a4c2525aa351276d50cff0420609f849b31dc1d2b952b08fa4dd895bba"
);
fixture!(
    sha2_192s,
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192s,
    "05561ebf1eb80a95c517a0b75df2ca427f6778bfa01a4918ee92c871afddedfe"
);
fixture!(
    sha2_192f,
    kylix_slh_dsa::Sha2_192Hash,
    slh_dsa_sha2_192f,
    "640fd82970333e2e69c1991d9b78b45ff1b0bde64458ecc064f29fe2732e73fd"
);
fixture!(
    sha2_256s,
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256s,
    "69ce3f4e305fcd8e3dff78e742f1d3dc7bf6dc75d96af2b6947be83d32608d46"
);
fixture!(
    sha2_256f,
    kylix_slh_dsa::Sha2_256Hash,
    slh_dsa_sha2_256f,
    "a288c9fa5765467c3f5abc85a10fa5c5071eafc0dee2e1deed8adc565ad5bccd"
);
