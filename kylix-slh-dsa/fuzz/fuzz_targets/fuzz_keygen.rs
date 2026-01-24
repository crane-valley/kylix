#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use kylix_core::Signer;
use kylix_slh_dsa::SlhDsaShake128f;

/// A deterministic RNG seeded from fuzzer input.
struct FuzzRng {
    seed: [u8; 32],
    counter: u64,
}

impl FuzzRng {
    fn new(seed: &[u8]) -> Self {
        let mut s = [0u8; 32];
        let len = seed.len().min(32);
        s[..len].copy_from_slice(&seed[..len]);
        Self { seed: s, counter: 0 }
    }

    fn next_bytes(&mut self, dest: &mut [u8]) {
        use sha3::{Shake256, digest::{ExtendableOutput, Update, XofReader}};

        let mut hasher = Shake256::default();
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        self.counter += 1;

        let mut reader = hasher.finalize_xof();
        reader.read(dest);
    }
}

impl rand_core::RngCore for FuzzRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.next_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.next_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.next_bytes(dest);
    }
}

impl rand_core::CryptoRng for FuzzRng {}

#[derive(Debug, Arbitrary)]
struct KeygenInput {
    seed: Vec<u8>,
}

fuzz_target!(|input: KeygenInput| {
    if input.seed.is_empty() {
        return;
    }

    let mut rng = FuzzRng::new(&input.seed);

    // Key generation should never panic
    let result = SlhDsaShake128f::keygen(&mut rng);
    assert!(result.is_ok(), "keygen should always succeed");

    let (sk, pk) = result.unwrap();

    // Keys should have correct sizes
    assert_eq!(sk.to_bytes().len(), SlhDsaShake128f::SIGNING_KEY_SIZE);
    assert_eq!(pk.to_bytes().len(), SlhDsaShake128f::VERIFICATION_KEY_SIZE);
});
