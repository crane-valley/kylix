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
struct RoundtripInput {
    key_seed: Vec<u8>,
    message: Vec<u8>,
}

fuzz_target!(|input: RoundtripInput| {
    if input.key_seed.is_empty() {
        return;
    }

    // Generate a key pair from the seed
    let mut rng = FuzzRng::new(&input.key_seed);
    let (sk, pk) = SlhDsaShake128f::keygen(&mut rng).unwrap();

    // Sign the message
    let sig = SlhDsaShake128f::sign(&sk, &input.message).unwrap();

    // Verification with correct key and message should always succeed
    let result = SlhDsaShake128f::verify(&pk, &input.message, &sig);
    assert!(result.is_ok(), "roundtrip verification should always succeed");

    // Signature should have correct size
    assert_eq!(sig.to_bytes().len(), SlhDsaShake128f::SIGNATURE_SIZE);

    // Verification with different message should fail
    if !input.message.is_empty() {
        let mut wrong_message = input.message.clone();
        wrong_message[0] ^= 0xFF;
        let result = SlhDsaShake128f::verify(&pk, &wrong_message, &sig);
        assert!(result.is_err(), "verification with wrong message should fail");
    }
});
