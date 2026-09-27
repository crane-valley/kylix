//! Fuzz target for ML-KEM decapsulation with attacker-controlled inputs.
//!
//! Input layout: `selector (1) || body`. Selector bits 0-1 pick the parameter
//! set, bits 2-3 the mode:
//! - 0, raw: `dk_len (u16 LE) || dk (dk_len bytes) || ct (rest)`, any lengths.
//! - 1, structured dk: `dk_pke || ek || z || ct (rest)`; the target inserts
//!   H(ek) so the dk passes the hash check and arbitrary dk_pke contents reach
//!   decryption. Bit 4 reduces the ek coefficients modulo q.
//! - 2/3, fixed key: `ct (rest)`, or with bit 4 `offset (u16 LE) || patch`
//!   XORed into the reference ciphertext. The result must be the reference
//!   shared secret for the reference ciphertext and J(z || ct) otherwise.

#![no_main]

use std::sync::OnceLock;

use kylix_ml_kem::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};
use kylix_ml_kem::{Kem, MlKem1024, MlKem512, MlKem768};
use libfuzzer_sys::fuzz_target;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

const Q: u16 = 3329;

struct Fixed {
    dk: Vec<u8>,
    ct: Vec<u8>,
    ss: [u8; 32],
}

fn decode_pair(b: &[u8]) -> (u16, u16) {
    let c0 = u16::from(b[0]) | (u16::from(b[1] & 0x0f) << 8);
    let c1 = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
    (c0, c1)
}

fn coeffs_below_q(t_hat: &[u8]) -> bool {
    t_hat.chunks_exact(3).all(|b| {
        let (c0, c1) = decode_pair(b);
        c0 < Q && c1 < Q
    })
}

fn reduce_coeffs(t_hat: &mut [u8]) {
    for b in t_hat.chunks_exact_mut(3) {
        let (c0, c1) = decode_pair(b);
        let (c0, c1) = (c0 % Q, c1 % Q);
        b[0] = c0 as u8;
        b[1] = ((c0 >> 8) as u8) | ((c1 << 4) as u8);
        b[2] = (c1 >> 4) as u8;
    }
}

fn hash_h(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

fn hash_j(z: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(z);
    hasher.update(ct);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn read_u16(data: &[u8]) -> (usize, &[u8]) {
    match data {
        [lo, hi, rest @ ..] => (usize::from(u16::from_le_bytes([*lo, *hi])), rest),
        _ => (0, &[]),
    }
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
    ($variant:ident, $module:ident, $k:literal, $eta1:literal, $du:literal, $dv:literal,
     $mode:expr, $flag:expr, $body:expr) => {{
        static FIXED: OnceLock<Fixed> = OnceLock::new();
        let fixed = FIXED.get_or_init(|| {
            let (dk, ek) = ml_kem_keygen::<$k, $eta1>(&[0x11; 32], &[0x22; 32]);
            let (ct, ss) = ml_kem_encaps::<$k, $eta1, 2, $du, $dv>(&ek, &[0x33; 32]).unwrap();
            Fixed { dk, ct, ss }
        });

        let dk_size = <$variant as Kem>::DECAPSULATION_KEY_SIZE;
        let ct_size = <$variant as Kem>::CIPHERTEXT_SIZE;
        let pke_size = $k * 384;
        let ek_size = pke_size + 32;
        let body: &[u8] = $body;

        let (dk, ct) = match $mode {
            0 => {
                let (dk_len, rest) = read_u16(body);
                let (dk, ct) = rest.split_at(dk_len.min(rest.len()));
                (dk.to_vec(), ct.to_vec())
            }
            1 => {
                if body.len() < pke_size + ek_size + 32 {
                    return;
                }
                let (dk_pke, rest) = body.split_at(pke_size);
                let (ek, rest) = rest.split_at(ek_size);
                let (z, ct) = rest.split_at(32);
                let mut ek = ek.to_vec();
                if $flag {
                    reduce_coeffs(&mut ek[..pke_size]);
                }
                let mut dk = Vec::with_capacity(dk_size);
                dk.extend_from_slice(dk_pke);
                dk.extend_from_slice(&ek);
                dk.extend_from_slice(&hash_h(&ek));
                dk.extend_from_slice(z);
                (dk, ct.to_vec())
            }
            _ => {
                let ct = if $flag {
                    patch(&fixed.ct, body)
                } else {
                    body.to_vec()
                };
                (fixed.dk.clone(), ct)
            }
        };

        let expect_ok = dk.len() == dk_size && ct.len() == ct_size && {
            let ek = &dk[pke_size..pke_size + ek_size];
            let h = &dk[pke_size + ek_size..pke_size + ek_size + 32];
            hash_h(ek) == h && coeffs_below_q(&ek[..pke_size])
        };

        let raw = ml_kem_decaps::<$k, $eta1, 2, $du, $dv>(&dk, &ct);
        assert_eq!(raw.is_ok(), expect_ok, "decaps accept/reject mismatch");

        let typed_dk = kylix_ml_kem::$module::DecapsulationKey::from_bytes(&dk);
        let typed_ct = kylix_ml_kem::$module::Ciphertext::from_bytes(&ct);
        assert_eq!(typed_dk.is_ok(), dk.len() == dk_size);
        assert_eq!(typed_ct.is_ok(), ct.len() == ct_size);
        if let (Ok(tdk), Ok(tct)) = (&typed_dk, &typed_ct) {
            let typed = <$variant as Kem>::decaps(tdk, tct);
            assert_eq!(
                typed.as_ref().ok().map(|ss| ss.as_ref().to_vec()),
                raw.as_ref().ok().map(|ss| ss.to_vec()),
                "typed and low-level decaps disagree"
            );
        }

        if let Ok(ss) = raw {
            let again = ml_kem_decaps::<$k, $eta1, 2, $du, $dv>(&dk, &ct).unwrap();
            assert_eq!(ss, again, "Decaps should be deterministic");

            if $mode >= 2 {
                let expected = if ct == fixed.ct {
                    fixed.ss
                } else {
                    hash_j(&dk[dk_size - 32..], &ct)
                };
                assert_eq!(ss, expected, "wrong implicit-rejection result");
            }
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mode = (selector >> 2) & 0x03;
    let flag = selector & 0x10 != 0;

    match selector & 0x03 {
        0 => run!(MlKem512, ml_kem_512, 2, 3, 10, 4, mode, flag, body),
        1 => run!(MlKem768, ml_kem_768, 3, 2, 10, 4, mode, flag, body),
        _ => run!(MlKem1024, ml_kem_1024, 4, 2, 11, 5, mode, flag, body),
    }
});
