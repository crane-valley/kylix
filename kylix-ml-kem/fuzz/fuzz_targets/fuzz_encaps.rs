//! Fuzz target for ML-KEM encapsulation with attacker-controlled keys.
//!
//! Input layout: `selector (1) || m (32) || ek (rest, any length)`.
//! Selector bits 0-1 pick the parameter set. Bit 2 resizes `ek` to the
//! expected length and reduces every coefficient modulo q; random bytes almost
//! never pass the modulus check, so without it encryption is rarely reached.

#![no_main]

use kylix_ml_kem::kem::ml_kem_encaps;
use kylix_ml_kem::{Kem, MlKem1024, MlKem512, MlKem768};
use libfuzzer_sys::fuzz_target;

const Q: u16 = 3329;

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

macro_rules! check_encaps {
    ($variant:ident, $module:ident, $k:literal, $eta1:literal, $du:literal, $dv:literal,
     $ek:expr, $m:expr, $canonical:expr) => {{
        let ek_size = <$variant as Kem>::ENCAPSULATION_KEY_SIZE;
        let mut ek = $ek.to_vec();
        if $canonical {
            ek.resize(ek_size, 0);
            reduce_coeffs(&mut ek[..ek_size - 32]);
        }

        let typed = kylix_ml_kem::$module::EncapsulationKey::from_bytes(&ek);
        assert_eq!(typed.is_ok(), ek.len() == ek_size);
        if let Ok(key) = &typed {
            assert_eq!(key.as_bytes(), &ek[..]);
        }

        let expect_ok = ek.len() == ek_size && coeffs_below_q(&ek[..ek_size - 32]);
        match ml_kem_encaps::<$k, $eta1, 2, $du, $dv>(&ek, $m) {
            Ok((ct, ss)) => {
                assert!(expect_ok, "encaps accepted a malformed ek");
                assert_eq!(ct.len(), <$variant as Kem>::CIPHERTEXT_SIZE);
                let (ct2, ss2) = ml_kem_encaps::<$k, $eta1, 2, $du, $dv>(&ek, $m).unwrap();
                assert_eq!(ct, ct2, "Encaps should be deterministic");
                assert_eq!(ss, ss2, "Encaps should be deterministic");
            }
            Err(_) => assert!(!expect_ok, "encaps rejected a well-formed ek"),
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let selector = data[0];
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[1..33]);
    let ek = &data[33..];
    let canonical = selector & 0x04 != 0;

    match selector & 0x03 {
        0 => check_encaps!(MlKem512, ml_kem_512, 2, 3, 10, 4, ek, &m, canonical),
        1 => check_encaps!(MlKem768, ml_kem_768, 3, 2, 10, 4, ek, &m, canonical),
        _ => check_encaps!(MlKem1024, ml_kem_1024, 4, 2, 11, 5, ek, &m, canonical),
    }
});
