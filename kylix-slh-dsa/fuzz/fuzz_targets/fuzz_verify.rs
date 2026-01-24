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
struct VerifyInput {
    key_seed: Vec<u8>,
    message: Vec<u8>,
    corruption_index: usize,
    corruption_value: u8,
}

fuzz_target!(|input: VerifyInput| {
    if input.key_seed.is_empty() {
        return;
    }

    // Generate a key pair from the seed
    let mut rng = FuzzRng::new(&input.key_seed);
    let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

    // Sign a message to get a valid signature
    let sig = SlhDsaShake128f::sign(&sk, &input.message).unwrap();

    // Verification with correct data should succeed
    let result = SlhDsaShake128f::verify(&pk, &input.message, &sig);
    assert!(result.is_ok(), "verification should succeed with correct data");

    // Test with corrupted message (if message is not empty)
    if !input.message.is_empty() {
        let mut corrupted_msg = input.message.clone();
        let idx = input.corruption_index % corrupted_msg.len();
        corrupted_msg[idx] ^= input.corruption_value | 1; // Ensure at least 1 bit changed
        let result = SlhDsaShake128f::verify(&pk, &corrupted_msg, &sig);
        assert!(result.is_err(), "verification should fail with corrupted message");
    }

    // Test with different key (generate another keypair)
    let mut rng2 = FuzzRng::new(&[input.key_seed.as_slice(), &[0xFF]].concat());
    let (_, pk2) = SlhDsaShake128f::keygen(&mut rng2).unwrap();
    if pk.to_bytes() != pk2.to_bytes() {
        let result = SlhDsaShake128f::verify(&pk2, &input.message, &sig);
        assert!(result.is_err(), "verification should fail with wrong key");
    }
});
