//! Equivalence tests between the `HashSuite` allocating wrappers and the
//! required buffer-write `*_to` methods.
//!
//! The `*_to` methods are the required trait interface; `f`/`h`/`t_l`/`prf`/
//! `prf_msg`/`h_msg` are provided defaults layered on top of them. These tests
//! pin that layering so a hash suite cannot silently grow a second, divergent
//! hash body, and they prove the defaults are usable by an out-of-crate
//! implementor that supplies only the required methods.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kylix_slh_dsa::{Address, HashSuite, Shake128Hash, Shake192Hash, Shake256Hash};

#[cfg(feature = "any-sha2-variant")]
use kylix_slh_dsa::{Sha2_128Hash, Sha2_192Hash, Sha2_256Hash};

/// Digest lengths exercised for Hmsg: a short one and the longest length any
/// shipped parameter set requests.
const H_MSG_LENGTHS: [usize; 3] = [1, 30, 49];

fn check_suite<H: HashSuite>() {
    let n = H::N;
    let pk_seed = vec![0x11u8; n];
    let sk_seed = vec![0x22u8; n];
    let sk_prf = vec![0x33u8; n];
    let opt_rand = vec![0x44u8; n];
    let pk_root = vec![0x55u8; n];
    let r = vec![0x66u8; n];
    let m1 = vec![0x77u8; n];
    let m2 = vec![0x88u8; n];
    let m_wide = vec![0x99u8; n * 35];
    let message: &[u8] = b"kylix hash suite equivalence message";

    for adrs in [
        Address::new(),
        Address::wots_hash(1, 2, 3, 4, 5),
        Address::wots_prf(1, 2, 3, 4),
        Address::tree_node(1, 2, 3, 4),
    ] {
        let mut buf = vec![0u8; n];

        H::f_to(&mut buf, &pk_seed, &adrs, &m1);
        assert_eq!(buf, H::f(&pk_seed, &adrs, &m1), "f vs f_to");

        H::h_to(&mut buf, &pk_seed, &adrs, &m1, &m2);
        assert_eq!(buf, H::h(&pk_seed, &adrs, &m1, &m2), "h vs h_to");

        H::t_l_to(&mut buf, &pk_seed, &adrs, &m_wide);
        assert_eq!(buf, H::t_l(&pk_seed, &adrs, &m_wide), "t_l vs t_l_to");

        H::prf_to(&mut buf, &pk_seed, &sk_seed, &adrs);
        assert_eq!(buf, *H::prf(&pk_seed, &sk_seed, &adrs), "prf vs prf_to");
    }

    let mut buf = vec![0u8; n];
    H::prf_msg_to(&mut buf, &sk_prf, &opt_rand, message);
    assert_eq!(
        buf,
        *H::prf_msg(&sk_prf, &opt_rand, message),
        "prf_msg vs prf_msg_to"
    );

    for out_len in H_MSG_LENGTHS {
        let mut digest = vec![0u8; out_len];
        H::h_msg_to(&mut digest, &r, &pk_seed, &pk_root, message);
        assert_eq!(
            digest,
            H::h_msg(&r, &pk_seed, &pk_root, message, out_len),
            "h_msg vs h_msg_to at out_len={out_len}"
        );
    }

    // Streaming multi-part variants must agree with hashing the concatenation,
    // for an empty prefix and a non-empty one.
    for prefix in [b"".as_slice(), b"\x00\x00".as_slice(), b"prefix".as_slice()] {
        let mut combined = Vec::with_capacity(prefix.len() + message.len());
        combined.extend_from_slice(prefix);
        combined.extend_from_slice(message);

        let mut parts_out = vec![0u8; n];
        H::prf_msg_parts_to(&mut parts_out, &sk_prf, &opt_rand, prefix, message);
        assert_eq!(
            parts_out,
            *H::prf_msg(&sk_prf, &opt_rand, &combined),
            "prf_msg_parts_to vs prf_msg over concatenation, prefix len {}",
            prefix.len()
        );

        for out_len in H_MSG_LENGTHS {
            let mut digest = vec![0u8; out_len];
            H::h_msg_parts_to(&mut digest, &r, &pk_seed, &pk_root, prefix, message);
            assert_eq!(
                digest,
                H::h_msg(&r, &pk_seed, &pk_root, &combined, out_len),
                "h_msg_parts_to vs h_msg over concatenation, prefix len {}, out_len {out_len}",
                prefix.len()
            );
        }
    }
}

macro_rules! suite_equivalence_test {
    ($test_name:ident, $suite:ty, $n:expr) => {
        #[test]
        fn $test_name() {
            assert_eq!(<$suite as HashSuite>::N, $n);
            check_suite::<$suite>();
        }
    };
}

suite_equivalence_test!(test_hash_suite_equivalence_shake_128, Shake128Hash, 16);
suite_equivalence_test!(test_hash_suite_equivalence_shake_192, Shake192Hash, 24);
suite_equivalence_test!(test_hash_suite_equivalence_shake_256, Shake256Hash, 32);

#[cfg(feature = "any-sha2-variant")]
suite_equivalence_test!(test_hash_suite_equivalence_sha2_128, Sha2_128Hash, 16);
#[cfg(feature = "any-sha2-variant")]
suite_equivalence_test!(test_hash_suite_equivalence_sha2_192, Sha2_192Hash, 24);
#[cfg(feature = "any-sha2-variant")]
suite_equivalence_test!(test_hash_suite_equivalence_sha2_256, Sha2_256Hash, 32);

// ---------------------------------------------------------------------------
// Minimal out-of-crate implementor: only the required `*_to` methods.
// ---------------------------------------------------------------------------

/// A deliberately trivial, NON-CRYPTOGRAPHIC stand-in used only to prove that
/// implementing the six required `*_to` methods is enough to get working
/// `f`/`h`/`t_l`/`prf`/`prf_msg`/`h_msg` defaults.
struct MinimalSuite;

impl MinimalSuite {
    /// Fill `out` with a deterministic pattern derived from `tag` and `parts`.
    /// Distinct tags yield distinct output, so each default can be shown to
    /// dispatch to its own `*_to` method rather than a sibling.
    fn fill(out: &mut [u8], tag: u8, parts: &[&[u8]]) {
        let mut acc = tag;
        for part in parts {
            for b in *part {
                acc = acc.wrapping_mul(31).wrapping_add(*b);
            }
        }
        for (i, slot) in out.iter_mut().enumerate() {
            let i = u8::try_from(i % 256).unwrap();
            *slot = acc.wrapping_add(i).wrapping_mul(tag | 1);
        }
    }
}

impl HashSuite for MinimalSuite {
    const N: usize = 8;

    fn f_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8]) {
        Self::fill(out, 1, &[pk_seed, adrs.as_bytes(), m1]);
    }

    fn h_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) {
        Self::fill(out, 2, &[pk_seed, adrs.as_bytes(), m1, m2]);
    }

    fn t_l_to(out: &mut [u8], pk_seed: &[u8], adrs: &Address, m: &[u8]) {
        Self::fill(out, 3, &[pk_seed, adrs.as_bytes(), m]);
    }

    fn prf_to(out: &mut [u8], pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) {
        Self::fill(out, 4, &[pk_seed, adrs.as_bytes(), sk_seed]);
    }

    fn prf_msg_to(out: &mut [u8], sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) {
        Self::fill(out, 5, &[sk_prf, opt_rand, message]);
    }

    fn h_msg_to(out: &mut [u8], r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8]) {
        Self::fill(out, 6, &[r, pk_seed, pk_root, message]);
    }
}

#[test]
fn test_minimal_hash_suite_defaults_match_required_methods() {
    check_suite::<MinimalSuite>();
}

#[test]
fn test_minimal_hash_suite_defaults_dispatch_to_own_method() {
    let n = MinimalSuite::N;
    let seed = vec![0u8; n];
    let adrs = Address::new();

    // Same inputs through different defaults must differ, which can only hold
    // if each default calls its own `*_to` method.
    let f = MinimalSuite::f(&seed, &adrs, &seed);
    let t_l = MinimalSuite::t_l(&seed, &adrs, &seed);
    let prf = MinimalSuite::prf(&seed, &seed, &adrs);
    assert_ne!(f, t_l);
    assert_ne!(f, *prf);
    assert_ne!(t_l, *prf);

    // Vec-returning defaults must honour the suite's N and the requested Hmsg length.
    assert_eq!(f.len(), n);
    assert_eq!(MinimalSuite::h(&seed, &adrs, &seed, &seed).len(), n);
    assert_eq!(prf.len(), n);
    assert_eq!(MinimalSuite::prf_msg(&seed, &seed, b"m").len(), n);
    assert_eq!(MinimalSuite::h_msg(&seed, &seed, &seed, b"m", 49).len(), 49);
}
