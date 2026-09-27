//! SHA-256, SHA-512 and HMAC for secret inputs.
//!
//! The chaining state and the one-block input buffer live in a struct that is
//! wiped after finalizing and on drop; only the block compression function
//! comes from the sha2 crate. Finalizing works on the state in place, so the
//! absorbed data is never copied out of the struct.

use sha2::digest::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

macro_rules! define_sha2 {
    (
        $(#[$meta:meta])* $name:ident,
        $(#[$hmac_meta:meta])* $hmac:ident,
        word: $word:ty,
        length: $length:ty,
        block: $block:expr,
        output: $out:expr,
        compress: $compress:path,
        iv: $iv:expr
    ) => {
        $(#[$meta])*
        pub(crate) struct $name {
            state: [$word; 8],
            buf: [u8; $block],
            pos: usize,
            blocks: $length,
        }

        impl $name {
            pub(crate) const fn new() -> Self {
                Self {
                    state: $iv,
                    buf: [0; $block],
                    pos: 0,
                    blocks: 0,
                }
            }

            fn compress_buf(&mut self) {
                $compress(&mut self.state, core::slice::from_ref((&self.buf).into()));
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
                    $compress(
                        &mut self.state,
                        core::slice::from_ref(GenericArray::from_slice(block)),
                    );
                    self.blocks = self.blocks.wrapping_add(1);
                }
                let rest = blocks.remainder();
                self.buf[..rest.len()].copy_from_slice(rest);
                self.pos = rest.len();
            }

            /// Write the first `out.len()` bytes of the digest into `out`, then
            /// wipe the state, leaving the hasher ready for a new message.
            pub(crate) fn finalize_into(&mut self, out: &mut [u8]) {
                debug_assert!(out.len() <= $out);
                const LENGTH_BYTES: usize = core::mem::size_of::<$length>();
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
                for (chunk, word) in out
                    .chunks_mut(core::mem::size_of::<$word>())
                    .zip(self.state.iter())
                {
                    chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
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

        $(#[$hmac_meta])*
        pub(crate) fn $hmac(out: &mut [u8], key: &[u8], parts: &[&[u8]]) {
            let mut inner = $name::new();
            let mut outer = $name::new();
            // The padded key is built in the inner hasher's buffer so that no
            // separate key block exists.
            if key.len() > $block {
                let mut key_hasher = $name::new();
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

define_sha2!(
    /// SHA-256 whose state and buffer are wiped after use.
    Sha256,
    /// HMAC-SHA-256 of the concatenated `parts`, truncated to `out.len()` bytes.
    hmac_sha256_into,
    word: u32,
    length: u64,
    block: 64,
    output: 32,
    compress: sha2::compress256,
    iv: [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
);

define_sha2!(
    /// SHA-512 whose state and buffer are wiped after use.
    Sha512,
    /// HMAC-SHA-512 of the concatenated `parts`, truncated to `out.len()` bytes.
    hmac_sha512_into,
    word: u64,
    length: u128,
    block: 128,
    output: 64,
    compress: sha2::compress512,
    iv: [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ]
);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{hmac_sha256_into, hmac_sha512_into, Sha256, Sha512};
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
