//! SHA-256, SHA-512 and HMAC for secret inputs.
//!
//! The chaining state, the one-block input buffer and the message schedule and
//! working variables of the compression function live in a struct that is
//! wiped after every block, after finalizing and on drop. Finalizing works on
//! the state in place, so the absorbed data is never copied out of the struct.
//! [`Sha256Accel`] instead runs the sha2 crate's block function, which keeps its
//! own unwiped scratch; see ADR 0002 for where each type is used.

use sha2::digest::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

const IV256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const IV512: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

macro_rules! define_compress {
    (
        $(#[$meta:meta])* $scratch:ident,
        $compress:ident,
        word: $word:ty,
        k: $k:expr,
        big_sigma0: ($bs0a:expr, $bs0b:expr, $bs0c:expr),
        big_sigma1: ($bs1a:expr, $bs1b:expr, $bs1c:expr),
        small_sigma0: ($ss0a:expr, $ss0b:expr, $ss0c:expr),
        small_sigma1: ($ss1a:expr, $ss1b:expr, $ss1c:expr)
    ) => {
        $(#[$meta])*
        pub(crate) struct $scratch {
            w: [$word; 16],
            v: [$word; 8],
        }

        impl $scratch {
            const fn new() -> Self {
                Self {
                    w: [0; 16],
                    v: [0; 8],
                }
            }
        }

        fn $compress(state: &mut [$word; 8], block: &[u8], scratch: &mut $scratch) {
            const WORD_BYTES: usize = core::mem::size_of::<$word>();
            for (w, bytes) in scratch.w.iter_mut().zip(block.chunks_exact(WORD_BYTES)) {
                *w = bytes.iter().fold(0, |acc, &b| (acc << 8) | <$word>::from(b));
            }
            scratch.v = *state;
            for (i, k) in $k.iter().enumerate() {
                if i >= 16 {
                    let w15 = scratch.w[(i + 1) & 15];
                    let w2 = scratch.w[(i + 14) & 15];
                    let s0 = w15.rotate_right($ss0a) ^ w15.rotate_right($ss0b) ^ (w15 >> $ss0c);
                    let s1 = w2.rotate_right($ss1a) ^ w2.rotate_right($ss1b) ^ (w2 >> $ss1c);
                    scratch.w[i & 15] = scratch.w[i & 15]
                        .wrapping_add(s0)
                        .wrapping_add(scratch.w[(i + 9) & 15])
                        .wrapping_add(s1);
                }
                let [a, b, c, d, e, f, g, h] = scratch.v;
                let t1 = h
                    .wrapping_add(e.rotate_right($bs1a) ^ e.rotate_right($bs1b) ^ e.rotate_right($bs1c))
                    .wrapping_add((e & f) ^ (!e & g))
                    .wrapping_add(*k)
                    .wrapping_add(scratch.w[i & 15]);
                let t2 = (a.rotate_right($bs0a) ^ a.rotate_right($bs0b) ^ a.rotate_right($bs0c))
                    .wrapping_add((a & b) ^ (a & c) ^ (b & c));
                scratch.v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
            }
            for (x, v) in state.iter_mut().zip(scratch.v.iter()) {
                *x = x.wrapping_add(*v);
            }
            scratch.w.zeroize();
            scratch.v.zeroize();
        }
    };
}

define_compress!(
    Sha256Scratch,
    compress256,
    word: u32,
    k: K256,
    big_sigma0: (2, 13, 22),
    big_sigma1: (6, 11, 25),
    small_sigma0: (7, 18, 3),
    small_sigma1: (17, 19, 10)
);

define_compress!(
    Sha512Scratch,
    compress512,
    word: u64,
    k: K512,
    big_sigma0: (28, 34, 39),
    big_sigma1: (14, 18, 41),
    small_sigma0: (1, 8, 7),
    small_sigma1: (19, 61, 6)
);

fn sha2_compress256(state: &mut [u32; 8], block: &[u8], _scratch: &mut ()) {
    sha2::compress256(
        state,
        core::slice::from_ref(GenericArray::from_slice(block)),
    );
}

macro_rules! define_hasher {
    (
        $(#[$meta:meta])* $name:ident,
        word: $word:ty,
        length: $length:ty,
        block: $block:expr,
        output: $out:expr,
        compress: $compress:path,
        scratch: $scratch:ty = $scratch_new:expr,
        iv: $iv:expr
    ) => {
        $(#[$meta])*
        pub(crate) struct $name {
            state: [$word; 8],
            buf: [u8; $block],
            pos: usize,
            blocks: $length,
            scratch: $scratch,
        }

        impl $name {
            pub(crate) const fn new() -> Self {
                Self {
                    state: $iv,
                    buf: [0; $block],
                    pos: 0,
                    blocks: 0,
                    scratch: $scratch_new,
                }
            }

            fn compress_buf(&mut self) {
                $compress(&mut self.state, &self.buf, &mut self.scratch);
                self.blocks = self.blocks.wrapping_add(1);
                self.pos = 0;
            }

            pub(crate) fn update(&mut self, mut data: &[u8]) {
                if self.pos > 0 {
                    let take = core::cmp::min($block - self.pos, data.len());
                    self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
                    self.pos += take;
                    data = &data[take..];
                    if self.pos < $block {
                        return;
                    }
                    self.compress_buf();
                }
                let mut blocks = data.chunks_exact($block);
                for block in &mut blocks {
                    $compress(&mut self.state, block, &mut self.scratch);
                    self.blocks = self.blocks.wrapping_add(1);
                }
                let rest = blocks.remainder();
                self.buf[..rest.len()].copy_from_slice(rest);
                self.pos = rest.len();
            }

            /// Write the first `out.len()` bytes of the digest into `out`, then
            /// wipe the state, leaving the hasher ready for a new message.
            pub(crate) fn finalize_into(&mut self, out: &mut [u8]) {
                assert!(out.len() <= $out, "output longer than the digest");
                const LENGTH_BYTES: usize = core::mem::size_of::<$length>();
                const WORD_BYTES: usize = core::mem::size_of::<$word>();
                let bit_len = self
                    .blocks
                    .wrapping_mul($block)
                    .wrapping_add(self.pos as $length)
                    .wrapping_mul(8);
                self.buf[self.pos] = 0x80;
                self.buf[self.pos + 1..].fill(0);
                if self.pos >= $block - LENGTH_BYTES {
                    self.compress_buf();
                    self.buf.fill(0);
                }
                self.buf[$block - LENGTH_BYTES..].copy_from_slice(&bit_len.to_be_bytes());
                self.compress_buf();
                // Byte-wise so that no digest word is copied into a temporary array.
                for (i, byte) in out.iter_mut().enumerate() {
                    let shift = 8 * (WORD_BYTES - 1 - i % WORD_BYTES);
                    *byte = (self.state[i / WORD_BYTES] >> shift) as u8;
                }
                self.wipe();
                self.state = $iv;
            }

            fn wipe(&mut self) {
                self.state.zeroize();
                self.buf.zeroize();
                self.pos.zeroize();
                self.blocks.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.wipe();
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

macro_rules! define_hmac {
    ($(#[$meta:meta])* $hmac:ident, $hasher:ident, block: $block:expr, output: $out:expr) => {
        $(#[$meta])*
        pub(crate) fn $hmac(out: &mut [u8], key: &[u8], parts: &[&[u8]]) {
            let mut inner = $hasher::new();
            let mut outer = $hasher::new();
            // The padded key is built in the inner hasher's buffer so that no
            // separate key block exists.
            if key.len() > $block {
                let mut key_hasher = $hasher::new();
                key_hasher.update(key);
                key_hasher.finalize_into(&mut inner.buf[..$out]);
            } else {
                inner.buf[..key.len()].copy_from_slice(key);
            }
            for (i, o) in inner.buf.iter_mut().zip(outer.buf.iter_mut()) {
                *o = *i ^ OPAD;
                *i ^= IPAD;
            }
            inner.compress_buf();
            outer.compress_buf();
            for part in parts {
                inner.update(part);
            }
            inner.finalize_into(&mut outer.buf[..$out]);
            outer.pos = $out;
            outer.finalize_into(out);
        }
    };
}

define_hasher!(
    /// SHA-256 whose state, buffer and compression scratch are wiped after use.
    Sha256,
    word: u32,
    length: u64,
    block: 64,
    output: 32,
    compress: compress256,
    scratch: Sha256Scratch = Sha256Scratch::new(),
    iv: IV256
);

define_hasher!(
    /// SHA-256 whose state and buffer are wiped after use, over the sha2
    /// crate's (possibly hardware-accelerated) block function, whose own
    /// scratch is not wiped.
    Sha256Accel,
    word: u32,
    length: u64,
    block: 64,
    output: 32,
    compress: sha2_compress256,
    scratch: () = (),
    iv: IV256
);

define_hasher!(
    /// SHA-512 whose state, buffer and compression scratch are wiped after use.
    Sha512,
    word: u64,
    length: u128,
    block: 128,
    output: 64,
    compress: compress512,
    scratch: Sha512Scratch = Sha512Scratch::new(),
    iv: IV512
);

define_hmac!(
    /// HMAC-SHA-256 of the concatenated `parts`, truncated to `out.len()` bytes.
    hmac_sha256_into,
    Sha256,
    block: 64,
    output: 32
);

define_hmac!(
    /// HMAC-SHA-512 of the concatenated `parts`, truncated to `out.len()` bytes.
    hmac_sha512_into,
    Sha512,
    block: 128,
    output: 64
);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        compress256, compress512, hmac_sha256_into, hmac_sha512_into, Sha256, Sha256Accel,
        Sha256Scratch, Sha512, Sha512Scratch, IV256, IV512,
    };
    use hmac::{Hmac, Mac};
    use sha2::Digest;

    const MAX: usize = 3 * 128 + 1;

    fn input() -> [u8; MAX] {
        let mut data = [0u8; MAX];
        let mut x: u32 = 0x9e37_79b9;
        for byte in &mut data {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *byte = x as u8;
        }
        data
    }

    macro_rules! check_hash {
        ($ours:ident, $theirs:ty, $block:expr, $out:expr) => {{
            let data = input();
            for len in 0..=3 * $block + 1 {
                let msg = &data[..len];
                let expected = <$theirs>::digest(msg);
                let mut digest = [0u8; $out];

                let mut hasher = $ours::new();
                hasher.update(msg);
                hasher.finalize_into(&mut digest);
                assert_eq!(digest[..], expected[..], "one update, len {len}");

                for split in 0..=len {
                    let mut hasher = $ours::new();
                    hasher.update(&msg[..split]);
                    hasher.update(&msg[split..]);
                    hasher.finalize_into(&mut digest);
                    assert_eq!(digest[..], expected[..], "len {len}, split {split}");
                }

                for step in [1, 7, $block - 1, $block + 3] {
                    let mut hasher = $ours::new();
                    for chunk in msg.chunks(step) {
                        hasher.update(chunk);
                    }
                    hasher.finalize_into(&mut digest);
                    assert_eq!(digest[..], expected[..], "len {len}, step {step}");
                }

                let mut short = [0u8; 16];
                let mut hasher = $ours::new();
                hasher.update(msg);
                hasher.finalize_into(&mut short);
                assert_eq!(short[..], expected[..16], "truncated, len {len}");
            }
        }};
    }

    macro_rules! check_hmac {
        ($ours:ident, $theirs:ty, $block:expr, $out:expr) => {{
            let data = input();
            for key_len in [0, 1, 16, 32, $block - 1, $block, $block + 1, 2 * $block + 3] {
                let key = &data[MAX - key_len..];
                for len in 0..=3 * $block + 1 {
                    let msg = &data[..len];
                    let mut mac = <Hmac<$theirs>>::new_from_slice(key).unwrap();
                    mac.update(msg);
                    let expected = mac.finalize().into_bytes();

                    let mut tag = [0u8; $out];
                    let split = len / 3;
                    $ours(&mut tag, key, &[&msg[..split], &msg[split..]]);
                    assert_eq!(tag[..], expected[..], "key {key_len}, len {len}");

                    let mut short = [0u8; 24];
                    $ours(&mut short, key, &[msg]);
                    assert_eq!(short[..], expected[..24], "truncated, key {key_len}");
                }
            }
        }};
    }

    #[test]
    fn sha256_matches_sha2_crate() {
        check_hash!(Sha256, sha2::Sha256, 64, 32);
    }

    #[test]
    fn sha256_accel_matches_sha2_crate() {
        check_hash!(Sha256Accel, sha2::Sha256, 64, 32);
    }

    #[test]
    fn sha512_matches_sha2_crate() {
        check_hash!(Sha512, sha2::Sha512, 128, 64);
    }

    #[test]
    fn hmac_sha256_matches_hmac_crate() {
        check_hmac!(hmac_sha256_into, sha2::Sha256, 64, 32);
    }

    #[test]
    fn hmac_sha512_matches_hmac_crate() {
        check_hmac!(hmac_sha512_into, sha2::Sha512, 128, 64);
    }

    #[test]
    fn compression_scratch_is_zero_after_every_block() {
        let data = input();

        let mut state = IV256;
        let mut scratch = Sha256Scratch::new();
        compress256(&mut state, &data[..64], &mut scratch);
        assert_ne!(state, IV256);
        assert_eq!((scratch.w, scratch.v), ([0; 16], [0; 8]));

        let mut state = IV512;
        let mut scratch = Sha512Scratch::new();
        compress512(&mut state, &data[..128], &mut scratch);
        assert_ne!(state, IV512);
        assert_eq!((scratch.w, scratch.v), ([0; 16], [0; 8]));

        let mut sha256 = Sha256::new();
        sha256.update(&data[..64 + 5]);
        sha256.update(&data[..59]);
        assert_eq!((sha256.blocks, sha256.pos), (2, 0));
        assert_eq!((sha256.scratch.w, sha256.scratch.v), ([0; 16], [0; 8]));

        let mut sha512 = Sha512::new();
        sha512.update(&data[..128 + 5]);
        sha512.update(&data[..123]);
        assert_eq!((sha512.blocks, sha512.pos), (2, 0));
        assert_eq!((sha512.scratch.w, sha512.scratch.v), ([0; 16], [0; 8]));
    }

    #[test]
    fn finalizing_wipes_state_in_place_and_resets() {
        let data = input();

        let mut sha256 = Sha256::new();
        sha256.update(&data[..100]);
        let mut digest = [0u8; 32];
        sha256.finalize_into(&mut digest);
        assert_eq!(sha256.state, Sha256::new().state);
        assert_eq!(sha256.buf, [0u8; 64]);
        assert_eq!((sha256.pos, sha256.blocks), (0, 0));
        sha256.update(b"abc");
        sha256.finalize_into(&mut digest);
        assert_eq!(digest[..], sha2::Sha256::digest(b"abc")[..]);

        let mut sha512 = Sha512::new();
        sha512.update(&data[..200]);
        let mut digest = [0u8; 64];
        sha512.finalize_into(&mut digest);
        assert_eq!(sha512.state, Sha512::new().state);
        assert_eq!(sha512.buf, [0u8; 128]);
        assert_eq!((sha512.pos, sha512.blocks), (0, 0));
        sha512.update(b"abc");
        sha512.finalize_into(&mut digest);
        assert_eq!(digest[..], sha2::Sha512::digest(b"abc")[..]);
    }
}
