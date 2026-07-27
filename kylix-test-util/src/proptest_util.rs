//! Proptest strategies shared by the algorithm crates' property tests.

use proptest::prelude::*;

/// Generate arbitrary 32-byte seeds for testing.
pub fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate arbitrary messages of up to `max_len` bytes (exclusive).
pub fn arb_message(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..max_len)
}
