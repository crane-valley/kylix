//! Fuzz target for SLH-DSA verification of attacker-controlled keys and signatures.
//!
//! Input layout: `selector (1) || body`. Selector bit 0 picks SHAKE-128f or
//! SHA2-128f, bits 1-2 the mode:
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
//! Every mode cross-checks `from_bytes` and `verify` against the low-level
//! functions, and the unmodified reference triple must verify. Mode 1 has no
//! accept/reject expectation: the reference seeds are public, so anyone can
//! sign other messages. Modes 2 and 3 must reject every change to the
//! signature or key.

#![no_main]

use std::sync::OnceLock;

use kylix_slh_dsa::sign::{slh_keygen_internal, slh_verify, PublicKey};
use kylix_slh_dsa::{Sha2_128Hash, Shake128Hash, Signer};
use libfuzzer_sys::fuzz_target;

const REF_MSG: &[u8] = b"kylix slh-dsa fuzz reference message";

// For a fixed R the valid signature is unique up to hash second preimages, and
// a different R changes the FORS indices and hypertree path, so any other
// valid signature on REF_MSG differs from the reference in far more than
// PATCH_MAX bytes. An unbounded patch could reach a re-signature with opt_rand.
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
    ($variant:ident, $module:ident, $hash:ty, $mode:expr, $body:expr) => {{
        use kylix_slh_dsa::params::$module::*;
        use kylix_slh_dsa::$module::{Signature, SigningKey, VerificationKey};
        use kylix_slh_dsa::$variant;

        static FIXED: OnceLock<Fixed> = OnceLock::new();
        let fixed = FIXED.get_or_init(|| {
            let (sk, pk) = slh_keygen_internal::<$hash, N, WOTS_LEN, H_PRIME, D>(
                [0x11; N], [0x22; N], [0x33; N],
            );
            let sk = SigningKey::from_bytes(&sk.to_bytes()).unwrap();
            let sig = $variant::sign(&sk, REF_MSG).unwrap();
            Fixed {
                pk: pk.to_bytes(),
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
        let raw_pk = PublicKey::<N>::from_bytes(&pk);
        assert_eq!(typed_pk.is_ok(), pk.len() == PK_BYTES);
        assert_eq!(typed_sig.is_ok(), sig.len() == SIG_BYTES);
        assert_eq!(raw_pk.is_some(), pk.len() == PK_BYTES);

        // The typed API signs M' = 0 || 0 || M (empty context); the low-level
        // function takes M' directly.
        let mut prefixed = vec![0u8, 0u8];
        prefixed.extend_from_slice(msg);
        let raw = raw_pk.is_some_and(|p| {
            slh_verify::<$hash, N, WOTS_LEN, WOTS_LEN1, H_PRIME, D, K, A>(&p, &prefixed, &sig)
        });

        match (&typed_pk, &typed_sig) {
            (Ok(tpk), Ok(tsig)) => {
                let typed = $variant::verify(tpk, msg, tsig).is_ok();
                assert_eq!(typed, raw, "typed and low-level verify disagree");
            }
            _ => assert!(!raw, "accepted a wrongly sized key or signature"),
        }

        let reference = pk == fixed.pk && sig == fixed.sig && msg == REF_MSG;
        if reference {
            assert!(raw, "reference signature rejected");
        } else if $mode >= 2 {
            // Mode 3: PK.seed and PK.root enter H_msg and the root must equal
            // PK.root, so the fixed signature verifying under another key would
            // need a hash preimage or fixed point.
            assert!(!raw, "accepted a patched signature or key");
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mode = (selector >> 1) & 0x03;

    if selector & 0x01 == 0 {
        run!(
            SlhDsaShake128f,
            slh_dsa_shake_128f,
            Shake128Hash,
            mode,
            body
        )
    } else {
        run!(SlhDsaSha2_128f, slh_dsa_sha2_128f, Sha2_128Hash, mode, body)
    }
});
