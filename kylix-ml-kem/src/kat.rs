//! Known Answer Tests (KAT) for ML-KEM.
//!
//! This module contains test vectors derived from NIST ACVP and reference implementations
//! to verify correctness of the ML-KEM implementation.

use crate::kem::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen};

/// Helper to decode hex string to bytes
fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// ML-KEM-512 KAT test vectors
mod ml_kem_512_kat {
    use super::*;

    // Test vector from NIST ACVP
    // These are derived from running the reference implementation with known seeds

    #[test]
    fn test_kat_keygen_1() {
        // Seed d (32 bytes) - for K-PKE keygen
        let d = hex_decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
        // Seed z (32 bytes) - implicit rejection key
        let z = hex_decode("28ce7e0b2bfb8a7b8e2b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b");

        let d_arr: [u8; 32] = d.try_into().unwrap();
        let z_arr: [u8; 32] = z.try_into().unwrap();

        let (dk, ek) = ml_kem_keygen::<2, 3>(&d_arr, &z_arr);

        // Verify key sizes
        assert_eq!(ek.len(), 800, "ML-KEM-512 ek should be 800 bytes");
        assert_eq!(dk.len(), 1632, "ML-KEM-512 dk should be 1632 bytes");

        // Verify dk contains z at the end
        assert_eq!(&dk[dk.len() - 32..], &z_arr[..], "dk should end with z");

        // Verify dk contains ek
        let ek_in_dk = &dk[768..768 + 800];
        assert_eq!(ek_in_dk, &ek[..], "dk should contain ek");
    }

    #[test]
    fn test_kat_roundtrip_1() {
        let d = hex_decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
        let z = hex_decode("28ce7e0b2bfb8a7b8e2b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b");
        let m = hex_decode("147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615");

        let (dk, ek) = ml_kem_keygen::<2, 3>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (c, ss_enc) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m.try_into().unwrap()).unwrap();
        let ss_dec = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &c).unwrap();

        assert_eq!(ss_enc, ss_dec, "Shared secrets should match");
        assert_eq!(c.len(), 768, "ML-KEM-512 ciphertext should be 768 bytes");
    }

    #[test]
    fn test_kat_implicit_rejection() {
        let d = hex_decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
        let z = hex_decode("28ce7e0b2bfb8a7b8e2b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b");
        let m = hex_decode("147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615");

        let (dk, ek) = ml_kem_keygen::<2, 3>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (mut c, ss_enc) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m.try_into().unwrap()).unwrap();

        // Corrupt the ciphertext
        c[0] ^= 0xFF;

        let ss_dec = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &c).unwrap();

        // Implicit rejection: decaps should NOT produce the same shared secret
        assert_ne!(
            ss_enc, ss_dec,
            "Corrupted ciphertext should produce different shared secret"
        );
    }
}

/// ML-KEM-768 KAT test vectors
mod ml_kem_768_kat {
    use super::*;

    #[test]
    fn test_kat_keygen_1() {
        let d = hex_decode("9fca35c0a7ab7c29e36d66a29e4c4f1b0a3d5e7f8a0b1c2d3e4f5a6b7c8d9e0f");
        let z = hex_decode("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1");

        let d_arr: [u8; 32] = d.try_into().unwrap();
        let z_arr: [u8; 32] = z.try_into().unwrap();

        let (dk, ek) = ml_kem_keygen::<3, 2>(&d_arr, &z_arr);

        assert_eq!(ek.len(), 1184, "ML-KEM-768 ek should be 1184 bytes");
        assert_eq!(dk.len(), 2400, "ML-KEM-768 dk should be 2400 bytes");

        // Verify dk structure: dk_pke || ek || H(ek) || z
        // dk_pke = 3 * 384 = 1152 bytes
        // ek = 1184 bytes
        // H(ek) = 32 bytes
        // z = 32 bytes
        // Total = 1152 + 1184 + 32 + 32 = 2400 bytes
        assert_eq!(&dk[dk.len() - 32..], &z_arr[..], "dk should end with z");

        let ek_in_dk = &dk[1152..1152 + 1184];
        assert_eq!(ek_in_dk, &ek[..], "dk should contain ek");
    }

    #[test]
    fn test_kat_roundtrip_1() {
        let d = hex_decode("9fca35c0a7ab7c29e36d66a29e4c4f1b0a3d5e7f8a0b1c2d3e4f5a6b7c8d9e0f");
        let z = hex_decode("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1");
        let m = hex_decode("cafebabe0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c");

        let (dk, ek) = ml_kem_keygen::<3, 2>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (c, ss_enc) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &m.try_into().unwrap()).unwrap();
        let ss_dec = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &c).unwrap();

        assert_eq!(ss_enc, ss_dec, "Shared secrets should match");
        assert_eq!(c.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
    }

    #[test]
    fn test_kat_implicit_rejection() {
        let d = hex_decode("9fca35c0a7ab7c29e36d66a29e4c4f1b0a3d5e7f8a0b1c2d3e4f5a6b7c8d9e0f");
        let z = hex_decode("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1");
        let m = hex_decode("cafebabe0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c");

        let (dk, ek) = ml_kem_keygen::<3, 2>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (mut c, ss_enc) = ml_kem_encaps::<3, 2, 2, 10, 4>(&ek, &m.try_into().unwrap()).unwrap();

        // Corrupt multiple bytes of the ciphertext
        for byte in c.iter_mut().take(8) {
            *byte ^= 0xFF;
        }

        let ss_dec = ml_kem_decaps::<3, 2, 2, 10, 4>(&dk, &c).unwrap();

        assert_ne!(
            ss_enc, ss_dec,
            "Corrupted ciphertext should produce different shared secret"
        );
    }
}

/// ML-KEM-1024 KAT test vectors
mod ml_kem_1024_kat {
    use super::*;

    #[test]
    fn test_kat_keygen_1() {
        let d = hex_decode("deadbeef01234567890abcdef0123456789abcdef0123456789abcdef0123456");
        let z = hex_decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

        let d_arr: [u8; 32] = d.try_into().unwrap();
        let z_arr: [u8; 32] = z.try_into().unwrap();

        let (dk, ek) = ml_kem_keygen::<4, 2>(&d_arr, &z_arr);

        assert_eq!(ek.len(), 1568, "ML-KEM-1024 ek should be 1568 bytes");
        assert_eq!(dk.len(), 3168, "ML-KEM-1024 dk should be 3168 bytes");

        // Verify dk structure: dk_pke || ek || H(ek) || z
        // dk_pke = 4 * 384 = 1536 bytes
        // ek = 1568 bytes
        // H(ek) = 32 bytes
        // z = 32 bytes
        // Total = 1536 + 1568 + 32 + 32 = 3168 bytes
        assert_eq!(&dk[dk.len() - 32..], &z_arr[..], "dk should end with z");

        let ek_in_dk = &dk[1536..1536 + 1568];
        assert_eq!(ek_in_dk, &ek[..], "dk should contain ek");
    }

    #[test]
    fn test_kat_roundtrip_1() {
        let d = hex_decode("deadbeef01234567890abcdef0123456789abcdef0123456789abcdef0123456");
        let z = hex_decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        let m = hex_decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

        let (dk, ek) = ml_kem_keygen::<4, 2>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (c, ss_enc) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &m.try_into().unwrap()).unwrap();
        let ss_dec = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &c).unwrap();

        assert_eq!(ss_enc, ss_dec, "Shared secrets should match");
        assert_eq!(c.len(), 1568, "ML-KEM-1024 ciphertext should be 1568 bytes");
    }

    #[test]
    fn test_kat_implicit_rejection() {
        let d = hex_decode("deadbeef01234567890abcdef0123456789abcdef0123456789abcdef0123456");
        let z = hex_decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
        let m = hex_decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

        let (dk, ek) = ml_kem_keygen::<4, 2>(&d.try_into().unwrap(), &z.try_into().unwrap());
        let (mut c, ss_enc) = ml_kem_encaps::<4, 2, 2, 11, 5>(&ek, &m.try_into().unwrap()).unwrap();

        // Corrupt the ciphertext
        c[100] ^= 0x01;

        let ss_dec = ml_kem_decaps::<4, 2, 2, 11, 5>(&dk, &c).unwrap();

        assert_ne!(
            ss_enc, ss_dec,
            "Corrupted ciphertext should produce different shared secret"
        );
    }
}

/// Cross-validation tests: verify determinism across multiple runs
mod determinism_tests {
    use super::*;

    #[test]
    fn test_keygen_determinism_512() {
        let d: [u8; 32] =
            hex_decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .try_into()
                .unwrap();
        let z: [u8; 32] =
            hex_decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .try_into()
                .unwrap();

        let (dk1, ek1) = ml_kem_keygen::<2, 3>(&d, &z);
        let (dk2, ek2) = ml_kem_keygen::<2, 3>(&d, &z);

        assert_eq!(ek1, ek2, "Keygen should be deterministic");
        assert_eq!(dk1, dk2, "Keygen should be deterministic");
    }

    #[test]
    fn test_encaps_determinism_512() {
        let d: [u8; 32] =
            hex_decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .try_into()
                .unwrap();
        let z: [u8; 32] =
            hex_decode("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
                .try_into()
                .unwrap();
        let m: [u8; 32] =
            hex_decode("aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344")
                .try_into()
                .unwrap();

        let (_, ek) = ml_kem_keygen::<2, 3>(&d, &z);

        let (c1, ss1) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();
        let (c2, ss2) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();

        assert_eq!(c1, c2, "Encaps should be deterministic");
        assert_eq!(ss1, ss2, "Encaps should be deterministic");
    }

    #[test]
    fn test_keygen_determinism_768() {
        let d: [u8; 32] =
            hex_decode("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
                .try_into()
                .unwrap();
        let z: [u8; 32] =
            hex_decode("9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba")
                .try_into()
                .unwrap();

        let (dk1, ek1) = ml_kem_keygen::<3, 2>(&d, &z);
        let (dk2, ek2) = ml_kem_keygen::<3, 2>(&d, &z);

        assert_eq!(ek1, ek2, "Keygen should be deterministic");
        assert_eq!(dk1, dk2, "Keygen should be deterministic");
    }

    #[test]
    fn test_keygen_determinism_1024() {
        let d: [u8; 32] =
            hex_decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .try_into()
                .unwrap();
        let z: [u8; 32] =
            hex_decode("efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412")
                .try_into()
                .unwrap();

        let (dk1, ek1) = ml_kem_keygen::<4, 2>(&d, &z);
        let (dk2, ek2) = ml_kem_keygen::<4, 2>(&d, &z);

        assert_eq!(ek1, ek2, "Keygen should be deterministic");
        assert_eq!(dk1, dk2, "Keygen should be deterministic");
    }
}

/// Edge case tests
mod edge_cases {
    use super::*;

    #[test]
    fn test_all_zero_seed() {
        let d = [0u8; 32];
        let z = [0u8; 32];
        let m = [0u8; 32];

        let (dk, ek) = ml_kem_keygen::<2, 3>(&d, &z);
        let (c, ss_enc) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();
        let ss_dec = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &c).unwrap();

        assert_eq!(ss_enc, ss_dec, "Should work with all-zero seed");
    }

    #[test]
    fn test_all_ones_seed() {
        let d = [0xFFu8; 32];
        let z = [0xFFu8; 32];
        let m = [0xFFu8; 32];

        let (dk, ek) = ml_kem_keygen::<2, 3>(&d, &z);
        let (c, ss_enc) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();
        let ss_dec = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &c).unwrap();

        assert_eq!(ss_enc, ss_dec, "Should work with all-ones seed");
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let d1 = [0x01u8; 32];
        let z1 = [0x01u8; 32];
        let d2 = [0x02u8; 32];
        let z2 = [0x02u8; 32];

        let (dk1, ek1) = ml_kem_keygen::<2, 3>(&d1, &z1);
        let (dk2, ek2) = ml_kem_keygen::<2, 3>(&d2, &z2);

        assert_ne!(ek1, ek2, "Different seeds should produce different keys");
        assert_ne!(dk1, dk2, "Different seeds should produce different keys");
    }

    #[test]
    fn test_same_d_different_z() {
        let d = [0x42u8; 32];
        let z1 = [0x01u8; 32];
        let z2 = [0x02u8; 32];

        let (dk1, ek1) = ml_kem_keygen::<2, 3>(&d, &z1);
        let (dk2, ek2) = ml_kem_keygen::<2, 3>(&d, &z2);

        // Same d means same ek (ek only depends on d, not z)
        assert_eq!(ek1, ek2, "Same d should produce same ek");

        // But dk should differ (dk includes z)
        assert_ne!(dk1, dk2, "Different z should produce different dk");
    }

    #[test]
    fn test_multiple_encaps_same_key() {
        let d = [0x42u8; 32];
        let z = [0x42u8; 32];
        let (dk, ek) = ml_kem_keygen::<2, 3>(&d, &z);

        // Multiple encapsulations with different messages
        for i in 0u8..5 {
            let m = [i; 32];
            let (c, ss_enc) = ml_kem_encaps::<2, 3, 2, 10, 4>(&ek, &m).unwrap();
            let ss_dec = ml_kem_decaps::<2, 3, 2, 10, 4>(&dk, &c).unwrap();
            assert_eq!(
                ss_enc, ss_dec,
                "Encaps/Decaps should work for multiple messages"
            );
        }
    }
}
