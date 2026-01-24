//! Integration tests for the Kylix CLI.
//!
//! These tests exercise the CLI binary end-to-end, verifying that:
//! - Commands execute successfully
//! - Key generation produces valid keys
//! - Encapsulation/decapsulation roundtrip works
//! - Signing/verification roundtrip works
//! - Error handling is correct

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Get a command for the kylix binary
fn kylix() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("kylix").unwrap()
}

mod info_command {
    use super::*;

    #[test]
    fn test_info_displays_algorithms() {
        kylix()
            .arg("info")
            .assert()
            .success()
            .stdout(predicate::str::contains("ML-KEM"))
            .stdout(predicate::str::contains("ML-DSA"))
            .stdout(predicate::str::contains("ml-kem-512"))
            .stdout(predicate::str::contains("ml-kem-768"))
            .stdout(predicate::str::contains("ml-kem-1024"))
            .stdout(predicate::str::contains("ml-dsa-44"))
            .stdout(predicate::str::contains("ml-dsa-65"))
            .stdout(predicate::str::contains("ml-dsa-87"));
    }
}

mod keygen_command {
    use super::*;

    #[test]
    fn test_keygen_ml_kem_768_hex() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("test_key");

        kylix()
            .args(["keygen", "-a", "ml-kem-768", "-o"])
            .arg(output.to_str().unwrap())
            .arg("-f")
            .arg("hex")
            .assert()
            .success()
            .stdout(predicate::str::contains("Public key written to"))
            .stdout(predicate::str::contains("Secret key written to"));

        // Verify files were created
        let pub_path = tmp.path().join("test_key.pub");
        let sec_path = tmp.path().join("test_key.sec");
        assert!(pub_path.exists(), "Public key file should exist");
        assert!(sec_path.exists(), "Secret key file should exist");

        // Verify hex format (all characters are hex digits)
        let pub_content = fs::read_to_string(&pub_path).unwrap();
        assert!(
            pub_content.trim().chars().all(|c| c.is_ascii_hexdigit()),
            "Public key should be hex encoded"
        );
    }

    #[test]
    fn test_keygen_ml_kem_512_base64() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("test_key");

        kylix()
            .args(["keygen", "-a", "ml-kem-512", "-o"])
            .arg(output.to_str().unwrap())
            .arg("-f")
            .arg("base64")
            .assert()
            .success();

        let pub_path = tmp.path().join("test_key.pub");
        let pub_content = fs::read_to_string(&pub_path).unwrap();

        // Base64 characters
        assert!(
            pub_content
                .trim()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "Public key should be base64 encoded"
        );
    }

    #[test]
    fn test_keygen_ml_kem_1024_pem() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("test_key");

        kylix()
            .args(["keygen", "-a", "ml-kem-1024", "-o"])
            .arg(output.to_str().unwrap())
            .arg("-f")
            .arg("pem")
            .assert()
            .success();

        let pub_path = tmp.path().join("test_key.pub");
        let pub_content = fs::read_to_string(&pub_path).unwrap();

        assert!(
            pub_content.starts_with("-----BEGIN ML-KEM PUBLIC KEY-----"),
            "PEM should have correct header"
        );
        assert!(
            pub_content.contains("-----END ML-KEM PUBLIC KEY-----"),
            "PEM should have correct footer"
        );
    }

    #[test]
    fn test_keygen_ml_dsa_65() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("dsa_key");

        kylix()
            .args(["keygen", "-a", "ml-dsa-65", "-o"])
            .arg(output.to_str().unwrap())
            .assert()
            .success();

        let pub_path = tmp.path().join("dsa_key.pub");
        let sec_path = tmp.path().join("dsa_key.sec");
        assert!(pub_path.exists());
        assert!(sec_path.exists());
    }

    #[test]
    fn test_keygen_all_algorithms() {
        let algorithms = [
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
        ];

        for algo in algorithms {
            let tmp = TempDir::new().unwrap();
            let output = tmp.path().join("key");

            kylix()
                .args(["keygen", "-a", algo, "-o"])
                .arg(output.to_str().unwrap())
                .assert()
                .success();
        }
    }
}

mod encaps_decaps_roundtrip {
    use super::*;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ciphertext");

        // Generate keys
        kylix()
            .args(["keygen", "-a", "ml-kem-768", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        // Encapsulate
        let encaps_output = kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        // Extract shared secret from encaps output
        let encaps_stdout = String::from_utf8_lossy(&encaps_output.get_output().stdout);
        let ss_encaps = encaps_stdout
            .lines()
            .find(|l| l.starts_with("Shared secret:"))
            .map(|l| l.trim_start_matches("Shared secret:").trim())
            .expect("Should have shared secret in output");

        // Decapsulate
        let decaps_output = kylix()
            .args(["decaps", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        let ss_decaps = String::from_utf8_lossy(&decaps_output.get_output().stdout);

        // Both shared secrets should match
        assert_eq!(
            ss_encaps.trim(),
            ss_decaps.trim(),
            "Encapsulated and decapsulated shared secrets should match"
        );
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ciphertext");

        kylix()
            .args(["keygen", "-a", "ml-kem-512", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        let encaps_output = kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        let encaps_stdout = String::from_utf8_lossy(&encaps_output.get_output().stdout);
        let ss_encaps = encaps_stdout
            .lines()
            .find(|l| l.starts_with("Shared secret:"))
            .map(|l| l.trim_start_matches("Shared secret:").trim())
            .unwrap();

        let decaps_output = kylix()
            .args(["decaps", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        let ss_decaps = String::from_utf8_lossy(&decaps_output.get_output().stdout);
        assert_eq!(ss_encaps.trim(), ss_decaps.trim());
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ciphertext");

        kylix()
            .args(["keygen", "-a", "ml-kem-1024", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        let encaps_output = kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        let encaps_stdout = String::from_utf8_lossy(&encaps_output.get_output().stdout);
        let ss_encaps = encaps_stdout
            .lines()
            .find(|l| l.starts_with("Shared secret:"))
            .map(|l| l.trim_start_matches("Shared secret:").trim())
            .unwrap();

        let decaps_output = kylix()
            .args(["decaps", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();

        let ss_decaps = String::from_utf8_lossy(&decaps_output.get_output().stdout);
        assert_eq!(ss_encaps.trim(), ss_decaps.trim());
    }
}

mod sign_verify_roundtrip {
    use super::*;

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let msg_path = tmp.path().join("message.txt");
        let sig_path = tmp.path().join("signature");

        // Create test message
        fs::write(&msg_path, b"Hello, post-quantum world!").unwrap();

        // Generate keys
        kylix()
            .args(["keygen", "-a", "ml-dsa-65", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        // Sign
        kylix()
            .args(["sign", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-o")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains("Signature written to"));

        // Verify
        kylix()
            .args(["verify", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-s")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains("Signature is valid"));
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let msg_path = tmp.path().join("message.txt");
        let sig_path = tmp.path().join("signature");

        fs::write(&msg_path, b"Test message for ML-DSA-44").unwrap();

        kylix()
            .args(["keygen", "-a", "ml-dsa-44", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        kylix()
            .args(["sign", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-o")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success();

        kylix()
            .args(["verify", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-s")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains("Signature is valid"));
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let msg_path = tmp.path().join("message.txt");
        let sig_path = tmp.path().join("signature");

        fs::write(&msg_path, b"Test message for ML-DSA-87").unwrap();

        kylix()
            .args(["keygen", "-a", "ml-dsa-87", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        kylix()
            .args(["sign", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-o")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success();

        kylix()
            .args(["verify", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-s")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains("Signature is valid"));
    }

    #[test]
    fn test_verification_fails_with_wrong_message() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let msg_path = tmp.path().join("message.txt");
        let wrong_msg_path = tmp.path().join("wrong_message.txt");
        let sig_path = tmp.path().join("signature");

        fs::write(&msg_path, b"Original message").unwrap();
        fs::write(&wrong_msg_path, b"Tampered message").unwrap();

        kylix()
            .args(["keygen", "-a", "ml-dsa-65", "-o"])
            .arg(key_path.to_str().unwrap())
            .assert()
            .success();

        kylix()
            .args(["sign", "--key"])
            .arg(tmp.path().join("key.sec").to_str().unwrap())
            .arg("-i")
            .arg(msg_path.to_str().unwrap())
            .arg("-o")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .success();

        // Verification should fail with wrong message
        kylix()
            .args(["verify", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-i")
            .arg(wrong_msg_path.to_str().unwrap())
            .arg("-s")
            .arg(sig_path.to_str().unwrap())
            .assert()
            .failure()
            .stderr(predicate::str::contains("verification failed"));
    }
}

mod error_handling {
    use super::*;

    #[test]
    fn test_missing_required_args() {
        // keygen without output
        kylix()
            .arg("keygen")
            .assert()
            .failure()
            .stderr(predicate::str::contains("required"));
    }

    #[test]
    fn test_invalid_algorithm() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("key");

        kylix()
            .args(["keygen", "-a", "invalid-algo", "-o"])
            .arg(output.to_str().unwrap())
            .assert()
            .failure();
    }

    #[test]
    fn test_nonexistent_key_file() {
        kylix()
            .args(["encaps", "--pub", "/nonexistent/path/key.pub"])
            .assert()
            .failure();
    }

    #[test]
    fn test_bench_zero_iterations() {
        kylix()
            .args(["bench", "--iterations", "0"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("at least 1"));
    }
}

mod bench_command {
    use super::*;

    #[test]
    fn test_bench_single_algorithm() {
        kylix()
            .args(["bench", "-a", "ml-kem-768", "-i", "10"])
            .assert()
            .success()
            .stdout(predicate::str::contains("ML-KEM-768"))
            .stdout(predicate::str::contains("keygen"))
            .stdout(predicate::str::contains("encaps"))
            .stdout(predicate::str::contains("decaps"));
    }

    #[test]
    fn test_bench_json_output() {
        let output = kylix()
            .args(["bench", "-a", "ml-dsa-44", "-i", "5", "--report", "json"])
            .assert()
            .success();

        let stdout = String::from_utf8_lossy(&output.get_output().stdout);
        // Should be valid JSON
        assert!(
            serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
            "Output should be valid JSON"
        );
    }

    #[test]
    fn test_bench_markdown_output() {
        kylix()
            .args([
                "bench",
                "-a",
                "ml-kem-512",
                "-i",
                "5",
                "--report",
                "markdown",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("| Algorithm |"))
            .stdout(predicate::str::contains("| ML-KEM-512 |"));
    }
}

mod format_auto_detection {
    use super::*;

    #[test]
    fn test_hex_format_auto_detection() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ct");

        // Generate in hex
        kylix()
            .args(["keygen", "-a", "ml-kem-768", "-o"])
            .arg(key_path.to_str().unwrap())
            .arg("-f")
            .arg("hex")
            .assert()
            .success();

        // Encaps should auto-detect hex format
        kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();
    }

    #[test]
    fn test_base64_format_auto_detection() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ct");

        // Generate in base64
        kylix()
            .args(["keygen", "-a", "ml-kem-768", "-o"])
            .arg(key_path.to_str().unwrap())
            .arg("-f")
            .arg("base64")
            .assert()
            .success();

        // Encaps should auto-detect base64 format
        kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();
    }

    #[test]
    fn test_pem_format_auto_detection() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("key");
        let ct_path = tmp.path().join("ct");

        // Generate in PEM
        kylix()
            .args(["keygen", "-a", "ml-kem-768", "-o"])
            .arg(key_path.to_str().unwrap())
            .arg("-f")
            .arg("pem")
            .assert()
            .success();

        // Encaps should auto-detect PEM format
        kylix()
            .args(["encaps", "--pub"])
            .arg(tmp.path().join("key.pub").to_str().unwrap())
            .arg("-o")
            .arg(ct_path.to_str().unwrap())
            .assert()
            .success();
    }
}
