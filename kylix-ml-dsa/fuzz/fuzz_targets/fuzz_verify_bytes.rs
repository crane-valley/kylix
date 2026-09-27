//! Fuzz target for ML-DSA verification of attacker-controlled keys and signatures.
//!
//! Input layout: `selector (1) || body`. Selector bits 0-1 pick the parameter
//! set, bits 2-3 the mode:
//! - 0, raw: `pk_len (u16 LE) || pk || sig_len (u16 LE) || sig || msg (rest)`,
//!   any lengths and contents.
//! - 1, fixed key: `sig_len (u16 LE) || sig || msg (rest)` against the
//!   reference key.
//! - 2, patched signature: `offset (u16 LE) || patch` (at most `PATCH_MAX`
//!   bytes used) XORed into the reference signature, verified over the
//!   reference message.
//! - 3, patched key: `offset (u16 LE) || patch` XORed into the reference key,
//!   verified with the reference signature and message.
//!
//! Every mode cross-checks `from_bytes`, `verify`, `expand` and
//! `verify_expanded` against the low-level functions, and the unmodified
//! reference triple must verify. Mode 1 has no accept/reject expectation:
//! the reference seed is public, so anyone can sign other messages. Modes 2
//! and 3 must reject every change to the signature or key.

#![no_main]

use std::sync::OnceLock;

use kylix_ml_dsa::sign::{
    expand_verification_key, ml_dsa_keygen, ml_dsa_verify, ml_dsa_verify_expanded,
};
use kylix_ml_dsa::Signer;
use libfuzzer_sys::fuzz_target;

const REF_MSG: &[u8] = b"kylix ml-dsa fuzz reference message";

// Another valid signature on REF_MSG, even one made with the public seed, has
// a fresh c_tilde and z, so it differs from the reference in far more than
// PATCH_MAX bytes. Accepting a bounded patch is thus a forgery or a
// non-canonical encoding; an unbounded patch could reach a re-signature.
const PATCH_MAX: usize = 64;

struct Fixed {
    pk: Vec<u8>,
    sig: Vec<u8>,
}

fn read_u16(data: &[u8]) -> (usize, &[u8]) {
    match data {
        [lo, hi, rest @ ..] => (usize::from(u16::from_le_bytes([*lo, *hi])), rest),
        _ => (0, &[]),
    }
}

fn take_prefixed(data: &[u8]) -> (&[u8], &[u8]) {
    let (len, rest) = read_u16(data);
    rest.split_at(len.min(rest.len()))
}

fn patch(base: &[u8], data: &[u8]) -> Vec<u8> {
    let (offset, patch) = read_u16(data);
    let mut out = base.to_vec();
    for (i, b) in patch.iter().enumerate() {
        let idx = (offset + i) % out.len();
        out[idx] ^= b;
    }
    out
}

macro_rules! run {
    ($variant:ident, $module:ident, $mode:expr, $body:expr) => {{
        use kylix_ml_dsa::params::$module::*;
        use kylix_ml_dsa::$module::{Signature, SigningKey, VerificationKey};
        use kylix_ml_dsa::$variant;

        static FIXED: OnceLock<Fixed> = OnceLock::new();
        let fixed = FIXED.get_or_init(|| {
            let (sk, pk) = ml_dsa_keygen::<K, L, ETA>(&[0x5a; 32]);
            let sk = SigningKey::from_bytes(&sk).unwrap();
            let sig = $variant::sign(&sk, REF_MSG).unwrap();
            Fixed {
                pk,
                sig: sig.as_bytes().to_vec(),
            }
        });

        let body: &[u8] = $body;
        let (pk, sig, msg): (Vec<u8>, Vec<u8>, &[u8]) = match $mode {
            0 => {
                let (pk, rest) = take_prefixed(body);
                let (sig, msg) = take_prefixed(rest);
                (pk.to_vec(), sig.to_vec(), msg)
            }
            1 => {
                let (sig, msg) = take_prefixed(body);
                (fixed.pk.clone(), sig.to_vec(), msg)
            }
            2 => {
                let body = &body[..body.len().min(2 + PATCH_MAX)];
                (fixed.pk.clone(), patch(&fixed.sig, body), REF_MSG)
            }
            _ => (patch(&fixed.pk, body), fixed.sig.clone(), REF_MSG),
        };

        let typed_pk = VerificationKey::from_bytes(&pk);
        let typed_sig = Signature::from_bytes(&sig);
        assert_eq!(typed_pk.is_ok(), pk.len() == PK_BYTES);
        assert_eq!(typed_sig.is_ok(), sig.len() == SIG_BYTES);
        if pk.len() != PK_BYTES {
            assert!(expand_verification_key::<K, L>(&pk).is_none());
        }

        // The typed API signs M' = 0 || 0 || M (empty context); the low-level
        // functions take M' directly.
        let mut prefixed = vec![0u8, 0u8];
        prefixed.extend_from_slice(msg);
        let raw = ml_dsa_verify::<K, L, BETA, GAMMA1, GAMMA2, TAU, OMEGA, C_TILDE_BYTES>(
            &pk, &prefixed, &sig,
        );

        match (&typed_pk, &typed_sig) {
            (Ok(tpk), Ok(tsig)) => {
                let typed = $variant::verify(tpk, msg, tsig).is_ok();
                assert_eq!(typed, raw, "typed and low-level verify disagree");

                let expanded = tpk.expand().unwrap();
                let typed_exp = $variant::verify_expanded(&expanded, msg, tsig).is_ok();
                assert_eq!(typed_exp, raw, "verify_expanded disagrees with verify");
                let raw_exp = ml_dsa_verify_expanded::<
                    K,
                    L,
                    BETA,
                    GAMMA1,
                    GAMMA2,
                    TAU,
                    OMEGA,
                    C_TILDE_BYTES,
                >(&expanded, &prefixed, &sig);
                assert_eq!(raw_exp, raw, "low-level verify_expanded disagrees");
            }
            _ => assert!(!raw, "accepted a wrongly sized key or signature"),
        }

        let reference = pk == fixed.pk && sig == fixed.sig && msg == REF_MSG;
        if reference {
            assert!(raw, "reference signature rejected");
        } else if $mode >= 2 {
            // Mode 3: tr = H(pk) enters mu, so the fixed c_tilde matching under
            // another key would need a hash preimage.
            assert!(!raw, "accepted a patched signature or key");
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mode = (selector >> 2) & 0x03;

    match selector & 0x03 {
        0 => run!(MlDsa44, ml_dsa_44, mode, body),
        1 => run!(MlDsa65, ml_dsa_65, mode, body),
        _ => run!(MlDsa87, ml_dsa_87, mode, body),
    }
});
