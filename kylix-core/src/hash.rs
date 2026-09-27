//! SHA3 and SHAKE (FIPS 202) for secret inputs.
//!
//! The Keccak state is the only storage: input is XORed straight into the
//! lanes and output is read straight from them, so no block buffer can retain
//! secret bytes, and the state is wiped on drop.

use zeroize::{Zeroize, ZeroizeOnDrop};

const SHA3_DOMAIN: u8 = 0x06;
const SHAKE_DOMAIN: u8 = 0x1F;

struct Sponge<const RATE: usize> {
    lanes: [u64; 25],
    pos: usize,
}

impl<const RATE: usize> Sponge<RATE> {
    const fn new() -> Self {
        Self {
            lanes: [0; 25],
            pos: 0,
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let offset = self.pos % 8;
            let take = core::cmp::min(8 - offset, data.len() - done);
            let mut word = 0u64;
            for (i, &byte) in data[done..done + take].iter().enumerate() {
                word |= u64::from(byte) << (8 * (offset + i));
            }
            self.lanes[self.pos / 8] ^= word;
            self.pos += take;
            done += take;
            if self.pos == RATE {
                keccak::f1600(&mut self.lanes);
                self.pos = 0;
            }
        }
    }

    fn pad(&mut self, domain: u8) {
        self.lanes[self.pos / 8] ^= u64::from(domain) << (8 * (self.pos % 8));
        self.lanes[RATE / 8 - 1] ^= 0x80u64 << 56;
        keccak::f1600(&mut self.lanes);
        self.pos = 0;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == RATE {
                keccak::f1600(&mut self.lanes);
                self.pos = 0;
            }
            let offset = self.pos % 8;
            let take = core::cmp::min(8 - offset, out.len() - done);
            let word = self.lanes[self.pos / 8] >> (8 * offset);
            for (i, byte) in out[done..done + take].iter_mut().enumerate() {
                *byte = (word >> (8 * i)) as u8;
            }
            self.pos += take;
            done += take;
        }
    }
}

impl<const RATE: usize> Drop for Sponge<RATE> {
    fn drop(&mut self) {
        self.lanes.zeroize();
        self.pos.zeroize();
    }
}

macro_rules! define_sha3 {
    ($(#[$meta:meta])* $name:ident, rate: $rate:expr, output: $len:expr) => {
        $(#[$meta])*
        pub struct $name(Sponge<$rate>);

        impl $name {
            /// Start a new hash computation.
            pub const fn new() -> Self {
                Self(Sponge::new())
            }

            /// Absorb more input.
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Write the digest into `out`, consuming the hasher.
            pub fn finalize_into(mut self, out: &mut [u8; $len]) {
                self.0.pad(SHA3_DOMAIN);
                self.0.squeeze(out);
            }

            /// Hash `data` into `out` in one call.
            pub fn hash_into(data: &[u8], out: &mut [u8; $len]) {
                let mut hasher = Self::new();
                hasher.update(data);
                hasher.finalize_into(out);
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

macro_rules! define_shake {
    (
        $(#[$meta:meta])* $name:ident,
        $(#[$reader_meta:meta])* $reader:ident,
        rate: $rate:expr
    ) => {
        $(#[$meta])*
        pub struct $name(Sponge<$rate>);

        impl $name {
            /// Start a new XOF computation.
            pub const fn new() -> Self {
                Self(Sponge::new())
            }

            /// Absorb more input.
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Finish absorbing and return a reader for the output stream.
            pub fn finalize_xof(mut self) -> $reader {
                self.0.pad(SHAKE_DOMAIN);
                // Swapping in an all-zero sponge leaves no copy of the state in `self`.
                $reader(core::mem::replace(&mut self.0, Sponge::new()))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ZeroizeOnDrop for $name {}

        $(#[$reader_meta])*
        pub struct $reader(Sponge<$rate>);

        impl $reader {
            /// Fill `out` with the next bytes of the output stream.
            pub fn read(&mut self, out: &mut [u8]) {
                self.0.squeeze(out);
            }
        }

        impl ZeroizeOnDrop for $reader {}
    };
}

define_sha3!(
    /// SHA3-256 whose state is wiped on drop.
    Sha3_256,
    rate: 136,
    output: 32
);

define_sha3!(
    /// SHA3-512 whose state is wiped on drop.
    Sha3_512,
    rate: 72,
    output: 64
);

define_shake!(
    /// SHAKE128 absorbing phase; its state is wiped on drop.
    Shake128,
    /// SHAKE128 squeezing phase; its state is wiped on drop.
    Shake128Reader,
    rate: 168
);

define_shake!(
    /// SHAKE256 absorbing phase; its state is wiped on drop.
    Shake256,
    /// SHAKE256 squeezing phase; its state is wiped on drop.
    Shake256Reader,
    rate: 136
);

#[cfg(test)]
mod tests {
    use super::{Sha3_256, Sha3_512, Shake128, Shake256};

    const MAX: usize = 3 * 168 + 8;

    trait Case {
        const RATE: usize;
        const OUT: usize;
        fn ours(parts: &[&[u8]], chunks: &[usize], out: &mut [u8]);
        fn reference(data: &[u8], out: &mut [u8]);
    }

    macro_rules! sha3_case {
        ($case:ident, $ours:ident, $theirs:ident, rate: $rate:expr, output: $len:expr) => {
            struct $case;
            impl Case for $case {
                const RATE: usize = $rate;
                const OUT: usize = $len;
                fn ours(parts: &[&[u8]], _chunks: &[usize], out: &mut [u8]) {
                    let mut hasher = $ours::new();
                    for part in parts {
                        hasher.update(part);
                    }
                    let mut digest = [0u8; $len];
                    hasher.finalize_into(&mut digest);
                    out.copy_from_slice(&digest);
                }
                fn reference(data: &[u8], out: &mut [u8]) {
                    use sha3::Digest;
                    out.copy_from_slice(&sha3::$theirs::digest(data));
                }
            }
        };
    }

    macro_rules! shake_case {
        ($case:ident, $ours:ident, $theirs:ident, rate: $rate:expr) => {
            struct $case;
            impl Case for $case {
                const RATE: usize = $rate;
                const OUT: usize = 2 * $rate + 5;
                fn ours(parts: &[&[u8]], chunks: &[usize], out: &mut [u8]) {
                    let mut hasher = $ours::new();
                    for part in parts {
                        hasher.update(part);
                    }
                    let mut reader = hasher.finalize_xof();
                    let mut done = 0;
                    for &chunk in chunks.iter().cycle() {
                        if done == out.len() {
                            break;
                        }
                        let end = core::cmp::min(done + chunk, out.len());
                        reader.read(&mut out[done..end]);
                        done = end;
                    }
                }
                fn reference(data: &[u8], out: &mut [u8]) {
                    use sha3::digest::{ExtendableOutput, Update, XofReader};
                    let mut hasher = sha3::$theirs::default();
                    hasher.update(data);
                    hasher.finalize_xof().read(out);
                }
            }
        };
    }

    sha3_case!(Sha3_256Case, Sha3_256, Sha3_256, rate: 136, output: 32);
    sha3_case!(Sha3_512Case, Sha3_512, Sha3_512, rate: 72, output: 64);
    shake_case!(Shake128Case, Shake128, Shake128, rate: 168);
    shake_case!(Shake256Case, Shake256, Shake256, rate: 136);

    fn input() -> [u8; MAX] {
        let mut data = [0u8; MAX];
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for byte in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = (x >> 24) as u8;
        }
        data
    }

    fn check_absorb<C: Case>() {
        let data = input();
        let chunks = [C::OUT];
        for len in 0..=3 * C::RATE + 1 {
            let msg = &data[..len];
            let mut expected = [0u8; MAX];
            C::reference(msg, &mut expected[..C::OUT]);
            let mut actual = [0u8; MAX];

            C::ours(&[msg], &chunks, &mut actual[..C::OUT]);
            assert_eq!(actual[..C::OUT], expected[..C::OUT], "len {len}");

            for a in 0..=len {
                C::ours(&[&msg[..a], &msg[a..]], &chunks, &mut actual[..C::OUT]);
                assert_eq!(actual[..C::OUT], expected[..C::OUT], "len {len} split {a}");
            }

            let r = C::RATE;
            let cuts = [
                0,
                1,
                7,
                8,
                9,
                r - 1,
                r,
                r + 1,
                len / 3,
                len / 2,
                len.saturating_sub(1),
                len,
            ];
            for &a in cuts.iter().filter(|&&a| a <= len) {
                for &b in cuts.iter().filter(|&&b| a <= b && b <= len) {
                    let parts: [&[u8]; 3] = [&msg[..a], &msg[a..b], &msg[b..]];
                    C::ours(&parts, &chunks, &mut actual[..C::OUT]);
                    assert_eq!(
                        actual[..C::OUT],
                        expected[..C::OUT],
                        "len {len} splits {a},{b}"
                    );
                }
            }
        }
    }

    fn check_squeeze<C: Case>() {
        let data = input();
        let r = C::RATE;
        let total = 3 * r + 5;
        let patterns: [&[usize]; 9] = [
            &[1],
            &[7],
            &[8],
            &[13],
            &[r - 1],
            &[r],
            &[r + 1],
            &[0, 5, 1, r, 3],
            &[2 * r + 1, 1],
        ];
        for len in [0, 1, r - 1, r, 2 * r + 3] {
            let msg = &data[..len];
            let mut expected = [0u8; MAX];
            C::reference(msg, &mut expected[..total]);
            for chunks in patterns {
                let mut actual = [0u8; MAX];
                C::ours(&[msg], chunks, &mut actual[..total]);
                assert_eq!(
                    actual[..total],
                    expected[..total],
                    "len {len} chunks {chunks:?}"
                );
            }
        }
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), 2 * N);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = match u8::from_str_radix(&s[2 * i..2 * i + 2], 16) {
                Ok(v) => v,
                Err(e) => panic!("bad hex: {e}"),
            };
        }
        out
    }

    #[test]
    fn sha3_256_matches_sha3_crate() {
        check_absorb::<Sha3_256Case>();
    }

    #[test]
    fn sha3_512_matches_sha3_crate() {
        check_absorb::<Sha3_512Case>();
    }

    #[test]
    fn shake128_matches_sha3_crate() {
        check_absorb::<Shake128Case>();
        check_squeeze::<Shake128Case>();
    }

    #[test]
    fn shake256_matches_sha3_crate() {
        check_absorb::<Shake256Case>();
        check_squeeze::<Shake256Case>();
    }

    #[test]
    fn fips202_known_answers() {
        let mut d256 = [0u8; 32];
        Sha3_256::hash_into(b"", &mut d256);
        assert_eq!(
            d256,
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        Sha3_256::hash_into(b"abc", &mut d256);
        assert_eq!(
            d256,
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );

        let mut d512 = [0u8; 64];
        Sha3_512::hash_into(b"", &mut d512);
        assert_eq!(
            d512,
            hex(concat!(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
                "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            ))
        );
        Sha3_512::hash_into(b"abc", &mut d512);
        assert_eq!(
            d512,
            hex(concat!(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e",
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            ))
        );

        let mut s128 = [0u8; 32];
        Shake128::new().finalize_xof().read(&mut s128);
        assert_eq!(
            s128,
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );

        let mut s256 = [0u8; 64];
        Shake256::new().finalize_xof().read(&mut s256);
        assert_eq!(
            s256,
            hex(concat!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            ))
        );
    }
}
