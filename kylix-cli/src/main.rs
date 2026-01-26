//! Kylix CLI - Post-quantum cryptography command-line tool.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use kylix_pqc::ml_dsa::{self, MlDsa44, MlDsa65, MlDsa87, Signer};
use kylix_pqc::ml_kem::{self, Kem, MlKem1024, MlKem512, MlKem768};
use kylix_pqc::slh_dsa::{
    self, SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
    SlhDsaShake256s,
};
use rand::rng;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroize;

#[cfg(feature = "bench")]
mod bench;

/// Post-quantum cryptography CLI tool
#[derive(Parser)]
#[command(name = "kylix")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Algorithm to use
        #[arg(short, long, value_enum, default_value = "ml-kem-768")]
        algo: Algorithm,

        /// Output file prefix (creates `<prefix>.pub` and `<prefix>.sec`)
        #[arg(short, long)]
        output: String,

        /// Output format
        #[arg(short, long, value_enum, default_value = "hex")]
        format: OutputFormat,
    },

    /// Encapsulate a shared secret using a public key
    Encaps {
        /// Path to the public key file
        #[arg(long = "pub")]
        pubkey: PathBuf,

        /// Output file for ciphertext (writes to stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "hex")]
        format: OutputFormat,
    },

    /// Decapsulate a shared secret using a secret key
    Decaps {
        /// Path to the secret key file
        #[arg(long = "key")]
        key: PathBuf,

        /// Path to the ciphertext file (reads from stdin if not specified)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output format for shared secret
        #[arg(short, long, value_enum, default_value = "hex")]
        format: OutputFormat,
    },

    /// Sign a file using ML-DSA or SLH-DSA
    Sign {
        /// Path to the signing key file
        #[arg(long = "key")]
        key: PathBuf,

        /// Input file to sign
        #[arg(short, long)]
        input: PathBuf,

        /// Output file for signature
        #[arg(short, long)]
        output: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "hex")]
        format: OutputFormat,

        /// Algorithm (required for SLH-DSA to distinguish -s/-f variants)
        #[arg(long, value_enum)]
        algo: Option<Algorithm>,
    },

    /// Verify a signature using ML-DSA or SLH-DSA
    Verify {
        /// Path to the verification (public) key file
        #[arg(long = "pub")]
        pubkey: PathBuf,

        /// Input file that was signed
        #[arg(short, long)]
        input: PathBuf,

        /// Signature file
        #[arg(short, long)]
        signature: PathBuf,

        /// Input format for key and signature files
        #[arg(short, long, value_enum, default_value = "hex")]
        format: OutputFormat,

        /// Algorithm (required for SLH-DSA to distinguish -s/-f variants)
        #[arg(long, value_enum)]
        algo: Option<Algorithm>,
    },

    /// Display information about supported algorithms
    Info,

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Run performance benchmarks
    #[cfg(feature = "bench")]
    Bench {
        /// Algorithm to benchmark (defaults to all if not specified)
        #[arg(short, long, value_enum)]
        algo: Option<Algorithm>,

        /// Number of iterations
        #[arg(short, long, default_value = "1000")]
        iterations: u64,

        /// Output file for results (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        report: bench::ReportFormat,

        /// Compare with external PQC implementations (OpenSSL, liboqs)
        #[arg(long)]
        compare: bool,

        /// Specific tools to compare with (comma-separated: openssl,liboqs)
        #[arg(long, value_delimiter = ',')]
        with: Option<Vec<String>>,
    },
}

/// Supported post-quantum cryptographic algorithms for CLI operations.
///
/// This enum is used across all CLI subcommands (keygen, encaps, decaps, sign, verify, bench)
/// to specify which algorithm variant to use.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum Algorithm {
    /// ML-KEM-512 (NIST Security Level 1, 128-bit)
    #[value(name = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768 (NIST Security Level 3, 192-bit)
    #[value(name = "ml-kem-768")]
    MlKem768,
    /// ML-KEM-1024 (NIST Security Level 5, 256-bit)
    #[value(name = "ml-kem-1024")]
    MlKem1024,
    /// ML-DSA-44 (NIST Security Level 2, 128-bit)
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65 (NIST Security Level 3, 192-bit)
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA-87 (NIST Security Level 5, 256-bit)
    #[value(name = "ml-dsa-87")]
    MlDsa87,
    /// SLH-DSA-SHAKE-128s (NIST Security Level 1, small signatures)
    #[value(name = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f (NIST Security Level 1, fast signing)
    #[value(name = "slh-dsa-shake-128f")]
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s (NIST Security Level 3, small signatures)
    #[value(name = "slh-dsa-shake-192s")]
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f (NIST Security Level 3, fast signing)
    #[value(name = "slh-dsa-shake-192f")]
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s (NIST Security Level 5, small signatures)
    #[value(name = "slh-dsa-shake-256s")]
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f (NIST Security Level 5, fast signing)
    #[value(name = "slh-dsa-shake-256f")]
    SlhDsaShake256f,
}

impl Algorithm {
    /// Returns true if this is a KEM algorithm
    fn is_kem(&self) -> bool {
        matches!(
            self,
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
        )
    }

    /// Returns true if this is a signature algorithm
    #[allow(dead_code)]
    fn is_dsa(&self) -> bool {
        matches!(
            self,
            Algorithm::MlDsa44
                | Algorithm::MlDsa65
                | Algorithm::MlDsa87
                | Algorithm::SlhDsaShake128s
                | Algorithm::SlhDsaShake128f
                | Algorithm::SlhDsaShake192s
                | Algorithm::SlhDsaShake192f
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
        )
    }

    /// Returns true if this is an SLH-DSA algorithm
    fn is_slh_dsa(&self) -> bool {
        matches!(
            self,
            Algorithm::SlhDsaShake128s
                | Algorithm::SlhDsaShake128f
                | Algorithm::SlhDsaShake192s
                | Algorithm::SlhDsaShake192f
                | Algorithm::SlhDsaShake256s
                | Algorithm::SlhDsaShake256f
        )
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::MlKem512 => write!(f, "ML-KEM-512"),
            Algorithm::MlKem768 => write!(f, "ML-KEM-768"),
            Algorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            Algorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            Algorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            Algorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            Algorithm::SlhDsaShake128s => write!(f, "SLH-DSA-SHAKE-128s"),
            Algorithm::SlhDsaShake128f => write!(f, "SLH-DSA-SHAKE-128f"),
            Algorithm::SlhDsaShake192s => write!(f, "SLH-DSA-SHAKE-192s"),
            Algorithm::SlhDsaShake192f => write!(f, "SLH-DSA-SHAKE-192f"),
            Algorithm::SlhDsaShake256s => write!(f, "SLH-DSA-SHAKE-256s"),
            Algorithm::SlhDsaShake256f => write!(f, "SLH-DSA-SHAKE-256f"),
        }
    }
}

/// Algorithm metadata for size detection and display.
pub struct AlgorithmInfo {
    pub pub_key_size: usize,
    pub sec_key_size: usize,
    pub output_size: usize, // ciphertext for KEM, signature for DSA
    pub pub_label: &'static str,
    pub sec_label: &'static str,
}

impl Algorithm {
    /// Get algorithm metadata.
    pub const fn info(&self) -> AlgorithmInfo {
        match self {
            Algorithm::MlKem512 => AlgorithmInfo {
                pub_key_size: MlKem512::ENCAPSULATION_KEY_SIZE,
                sec_key_size: MlKem512::DECAPSULATION_KEY_SIZE,
                output_size: MlKem512::CIPHERTEXT_SIZE,
                pub_label: "ML-KEM PUBLIC KEY",
                sec_label: "ML-KEM SECRET KEY",
            },
            Algorithm::MlKem768 => AlgorithmInfo {
                pub_key_size: MlKem768::ENCAPSULATION_KEY_SIZE,
                sec_key_size: MlKem768::DECAPSULATION_KEY_SIZE,
                output_size: MlKem768::CIPHERTEXT_SIZE,
                pub_label: "ML-KEM PUBLIC KEY",
                sec_label: "ML-KEM SECRET KEY",
            },
            Algorithm::MlKem1024 => AlgorithmInfo {
                pub_key_size: MlKem1024::ENCAPSULATION_KEY_SIZE,
                sec_key_size: MlKem1024::DECAPSULATION_KEY_SIZE,
                output_size: MlKem1024::CIPHERTEXT_SIZE,
                pub_label: "ML-KEM PUBLIC KEY",
                sec_label: "ML-KEM SECRET KEY",
            },
            Algorithm::MlDsa44 => AlgorithmInfo {
                pub_key_size: MlDsa44::VERIFICATION_KEY_SIZE,
                sec_key_size: MlDsa44::SIGNING_KEY_SIZE,
                output_size: MlDsa44::SIGNATURE_SIZE,
                pub_label: "ML-DSA PUBLIC KEY",
                sec_label: "ML-DSA SECRET KEY",
            },
            Algorithm::MlDsa65 => AlgorithmInfo {
                pub_key_size: MlDsa65::VERIFICATION_KEY_SIZE,
                sec_key_size: MlDsa65::SIGNING_KEY_SIZE,
                output_size: MlDsa65::SIGNATURE_SIZE,
                pub_label: "ML-DSA PUBLIC KEY",
                sec_label: "ML-DSA SECRET KEY",
            },
            Algorithm::MlDsa87 => AlgorithmInfo {
                pub_key_size: MlDsa87::VERIFICATION_KEY_SIZE,
                sec_key_size: MlDsa87::SIGNING_KEY_SIZE,
                output_size: MlDsa87::SIGNATURE_SIZE,
                pub_label: "ML-DSA PUBLIC KEY",
                sec_label: "ML-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake128s => AlgorithmInfo {
                pub_key_size: SlhDsaShake128s::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake128s::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake128s::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake128f => AlgorithmInfo {
                pub_key_size: SlhDsaShake128f::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake128f::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake128f::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake192s => AlgorithmInfo {
                pub_key_size: SlhDsaShake192s::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake192s::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake192s::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake192f => AlgorithmInfo {
                pub_key_size: SlhDsaShake192f::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake192f::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake192f::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake256s => AlgorithmInfo {
                pub_key_size: SlhDsaShake256s::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake256s::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake256s::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
            Algorithm::SlhDsaShake256f => AlgorithmInfo {
                pub_key_size: SlhDsaShake256f::VERIFICATION_KEY_SIZE,
                sec_key_size: SlhDsaShake256f::SIGNING_KEY_SIZE,
                output_size: SlhDsaShake256f::SIGNATURE_SIZE,
                pub_label: "SLH-DSA PUBLIC KEY",
                sec_label: "SLH-DSA SECRET KEY",
            },
        }
    }

    /// Detect KEM algorithm from public key size.
    fn detect_kem_from_pub_key(size: usize) -> Result<Self> {
        match size {
            MlKem512::ENCAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem512),
            MlKem768::ENCAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem768),
            MlKem1024::ENCAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown public key size: {} bytes. Expected {}, {}, or {}.",
                size,
                MlKem512::ENCAPSULATION_KEY_SIZE,
                MlKem768::ENCAPSULATION_KEY_SIZE,
                MlKem1024::ENCAPSULATION_KEY_SIZE
            ),
        }
    }

    /// Detect KEM algorithm from secret key size.
    fn detect_kem_from_sec_key(size: usize) -> Result<Self> {
        match size {
            MlKem512::DECAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem512),
            MlKem768::DECAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem768),
            MlKem1024::DECAPSULATION_KEY_SIZE => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown secret key size: {} bytes. Expected {}, {}, or {}.",
                size,
                MlKem512::DECAPSULATION_KEY_SIZE,
                MlKem768::DECAPSULATION_KEY_SIZE,
                MlKem1024::DECAPSULATION_KEY_SIZE
            ),
        }
    }

    /// Detect DSA algorithm from signing key size.
    /// Note: SLH-DSA 128s/128f have same key sizes; defaults to 128f.
    fn detect_dsa_from_signing_key(size: usize) -> Result<Self> {
        match size {
            MlDsa44::SIGNING_KEY_SIZE => Ok(Algorithm::MlDsa44),
            MlDsa65::SIGNING_KEY_SIZE => Ok(Algorithm::MlDsa65),
            MlDsa87::SIGNING_KEY_SIZE => Ok(Algorithm::MlDsa87),
            SlhDsaShake128f::SIGNING_KEY_SIZE => Ok(Algorithm::SlhDsaShake128f),
            SlhDsaShake192f::SIGNING_KEY_SIZE => Ok(Algorithm::SlhDsaShake192f),
            SlhDsaShake256f::SIGNING_KEY_SIZE => Ok(Algorithm::SlhDsaShake256f),
            _ => bail!(
                "Unknown signing key size: {} bytes. Expected ML-DSA (2560/4032/4896) or SLH-DSA (64/96/128).",
                size
            ),
        }
    }

    /// Detect DSA algorithm from verification key size.
    /// Note: SLH-DSA 128s/128f have same key sizes; defaults to 128f.
    fn detect_dsa_from_verification_key(size: usize) -> Result<Self> {
        match size {
            MlDsa44::VERIFICATION_KEY_SIZE => Ok(Algorithm::MlDsa44),
            MlDsa65::VERIFICATION_KEY_SIZE => Ok(Algorithm::MlDsa65),
            MlDsa87::VERIFICATION_KEY_SIZE => Ok(Algorithm::MlDsa87),
            SlhDsaShake128f::VERIFICATION_KEY_SIZE => Ok(Algorithm::SlhDsaShake128f),
            SlhDsaShake192f::VERIFICATION_KEY_SIZE => Ok(Algorithm::SlhDsaShake192f),
            SlhDsaShake256f::VERIFICATION_KEY_SIZE => Ok(Algorithm::SlhDsaShake256f),
            _ => bail!(
                "Unknown verification key size: {} bytes. Expected ML-DSA (1312/1952/2592) or SLH-DSA (32/48/64).",
                size
            ),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Hexadecimal encoding
    Hex,
    /// Base64 encoding
    Base64,
    /// PEM format
    Pem,
}

/// Encode bytes to the specified format
fn encode_output(data: &[u8], format: OutputFormat, label: &str) -> String {
    match format {
        OutputFormat::Hex => hex::encode(data),
        OutputFormat::Base64 => BASE64.encode(data),
        OutputFormat::Pem => {
            let b64 = BASE64.encode(data);
            let wrapped: String = b64
                .as_bytes()
                .chunks(64)
                .map(|chunk| std::str::from_utf8(chunk).expect("BASE64 output is valid ASCII"))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "-----BEGIN {}-----\n{}\n-----END {}-----",
                label, wrapped, label
            )
        }
    }
}

/// Check if a string is valid hexadecimal
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decode bytes with auto-detection of format.
/// Detection order: PEM (by header) -> Hex (if all hex chars) -> Base64.
/// The format parameter is ignored for input; it only affects output encoding.
fn decode_input(data: &str, _format: OutputFormat) -> Result<Vec<u8>> {
    let data = data.trim();

    // Auto-detect PEM format
    if data.starts_with("-----BEGIN") {
        let lines: Vec<&str> = data.lines().collect();
        if lines.len() < 3 {
            bail!("Invalid PEM format");
        }
        let b64: String = lines[1..lines.len() - 1].join("");
        return BASE64
            .decode(&b64)
            .context("Failed to decode PEM base64 content");
    }

    // Auto-detect hex vs base64
    // Hex: only 0-9, a-f, A-F (and must have even length for valid bytes)
    // Base64: may contain +, /, = which are not valid hex
    if is_hex(data) && data.len() % 2 == 0 {
        return hex::decode(data).context("Failed to decode hex");
    }

    // Try base64
    BASE64.decode(data).context("Failed to decode base64")
}

/// Write a file with restricted permissions (0o600) on Unix systems.
/// On non-Unix systems, falls back to standard [`fs::write`].
///
/// # Parameters
///
/// - `path`: Filesystem path where the secret data will be written.
/// - `content`: UTF-8 string contents to write to the secret file.
///
/// # Errors
///
/// Returns an error if the file cannot be created or written. On Unix systems,
/// this includes failures when setting file permissions; on non-Unix systems,
/// this includes any error returned by [`fs::write`].
fn write_secret_file(path: &str, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::path::Path;

        let target = Path::new(path);
        let parent = target.parent().ok_or_else(|| {
            anyhow!(
                "Invalid path for secret file (no parent directory): {}",
                path
            )
        })?;

        let filename = target
            .file_name()
            .ok_or_else(|| anyhow!("Invalid path for secret file (no filename): {}", path))?;

        // Use random suffix to prevent attackers from pre-creating predictable temp files
        let random_suffix: u64 = rand::random();
        let mut temp_path = parent.to_path_buf();
        temp_path.push(format!(
            ".{}.{:016x}.tmp",
            filename.to_string_lossy(),
            random_suffix
        ));

        // Create temp file with restrictive permissions (0o600) BEFORE writing secret data
        // Use create_new to prevent race conditions with attacker-created files
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .with_context(|| {
                format!(
                    "Failed to create temp file for secret key: {}",
                    temp_path.display()
                )
            })?;
        file.write_all(content.as_bytes()).with_context(|| {
            format!(
                "Failed to write temp file for secret key: {}",
                temp_path.display()
            )
        })?;

        // Atomic rename to target path (works because same filesystem)
        fs::rename(&temp_path, path)
            .with_context(|| format!("Failed to rename temp file to secret key file: {}", path))?;

        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content)
            .with_context(|| format!("Failed to write secret key file: {}", path))?;
        Ok(())
    }
}

/// Generate a key pair for the specified algorithm
fn cmd_keygen(algo: Algorithm, output: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Generating {} key pair...", algo);
    }

    let info = algo.info();
    let (pk_label, sk_label) = (info.pub_label, info.sec_label);

    let (pk_bytes, mut sk_bytes): (Vec<u8>, Vec<u8>) = match algo {
        Algorithm::MlKem512 => {
            let (dk, ek) = ml_kem::MlKem512::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
        }
        Algorithm::MlKem768 => {
            let (dk, ek) = ml_kem::MlKem768::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
        }
        Algorithm::MlKem1024 => {
            let (dk, ek) = ml_kem::MlKem1024::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
        }
        Algorithm::MlDsa44 => {
            let (sk, pk) = ml_dsa::MlDsa44::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        Algorithm::MlDsa65 => {
            let (sk, pk) = ml_dsa::MlDsa65::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        Algorithm::MlDsa87 => {
            let (sk, pk) = ml_dsa::MlDsa87::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        }
        Algorithm::SlhDsaShake128s => {
            let (sk, pk) = slh_dsa::SlhDsaShake128s::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
        Algorithm::SlhDsaShake128f => {
            let (sk, pk) = slh_dsa::SlhDsaShake128f::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
        Algorithm::SlhDsaShake192s => {
            let (sk, pk) = slh_dsa::SlhDsaShake192s::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
        Algorithm::SlhDsaShake192f => {
            let (sk, pk) = slh_dsa::SlhDsaShake192f::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
        Algorithm::SlhDsaShake256s => {
            let (sk, pk) = slh_dsa::SlhDsaShake256s::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
        Algorithm::SlhDsaShake256f => {
            let (sk, pk) = slh_dsa::SlhDsaShake256f::keygen(&mut rng())
                .map_err(|e| anyhow!("Key generation failed: {:?}", e))?;
            (pk.to_bytes(), sk.to_bytes())
        }
    };

    // Store sizes before zeroization for verbose output
    let pk_size = pk_bytes.len();
    let sk_size = sk_bytes.len();

    let pk_encoded = encode_output(&pk_bytes, format, pk_label);
    let sk_encoded = encode_output(&sk_bytes, format, sk_label);

    // Zeroize secret key bytes after encoding
    sk_bytes.zeroize();

    let pub_path = format!("{}.pub", output);
    let sec_path = format!("{}.sec", output);

    fs::write(&pub_path, &pk_encoded).context("Failed to write public key")?;
    // Use restrictive permissions (0o600) for secret key on Unix
    write_secret_file(&sec_path, &sk_encoded)?;

    if verbose {
        eprintln!("Public key size: {} bytes", pk_size);
        eprintln!("Secret key size: {} bytes", sk_size);
    }

    println!("Public key written to: {}", pub_path);
    println!("Secret key written to: {}", sec_path);

    Ok(())
}

/// Encapsulate a shared secret
fn cmd_encaps(
    pubkey: &PathBuf,
    output: Option<&PathBuf>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let pk_data = fs::read_to_string(pubkey).context("Failed to read public key file")?;
    let pk_bytes = decode_input(&pk_data, format)?;

    let algo = Algorithm::detect_kem_from_pub_key(pk_bytes.len())?;

    if verbose {
        eprintln!("Detected algorithm: {}", algo);
        eprintln!("Public key size: {} bytes", pk_bytes.len());
    }

    let (ct_bytes, mut ss_bytes): (Vec<u8>, Vec<u8>) = match algo {
        Algorithm::MlKem512 => {
            let ek = ml_kem::ml_kem_512::EncapsulationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid public key: {:?}", e))?;
            let (ct, ss) = ml_kem::MlKem512::encaps(&ek, &mut rng())
                .map_err(|e| anyhow!("Encapsulation failed: {:?}", e))?;
            (ct.as_bytes().to_vec(), ss.as_ref().to_vec())
        }
        Algorithm::MlKem768 => {
            let ek = ml_kem::ml_kem_768::EncapsulationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid public key: {:?}", e))?;
            let (ct, ss) = ml_kem::MlKem768::encaps(&ek, &mut rng())
                .map_err(|e| anyhow!("Encapsulation failed: {:?}", e))?;
            (ct.as_bytes().to_vec(), ss.as_ref().to_vec())
        }
        Algorithm::MlKem1024 => {
            let ek = ml_kem::ml_kem_1024::EncapsulationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid public key: {:?}", e))?;
            let (ct, ss) = ml_kem::MlKem1024::encaps(&ek, &mut rng())
                .map_err(|e| anyhow!("Encapsulation failed: {:?}", e))?;
            (ct.as_bytes().to_vec(), ss.as_ref().to_vec())
        }
        // detect_kem_algorithm only returns ML-KEM variants, so DSA variants are unreachable
        _ => unreachable!(),
    };

    let ct_encoded = encode_output(&ct_bytes, format, "ML-KEM CIPHERTEXT");

    if let Some(out_path) = output {
        fs::write(out_path, &ct_encoded).context("Failed to write ciphertext")?;
        if verbose {
            eprintln!("Ciphertext written to: {}", out_path.display());
            eprintln!("Ciphertext size: {} bytes", ct_bytes.len());
        }
    } else {
        println!("{}", ct_encoded);
    }

    // Always output shared secret to stdout (or stderr if ciphertext goes to stdout)
    let ss_encoded = encode_output(&ss_bytes, format, "SHARED SECRET");
    if output.is_some() {
        println!("Shared secret: {}", ss_encoded);
    } else {
        eprintln!("Shared secret: {}", ss_encoded);
    }

    if verbose {
        eprintln!("Shared secret size: {} bytes", ss_bytes.len());
    }

    // Zeroize shared secret after output
    ss_bytes.zeroize();

    Ok(())
}

/// Decapsulate a shared secret
fn cmd_decaps(
    key: &PathBuf,
    input: Option<&PathBuf>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let mut sk_data = fs::read_to_string(key).context("Failed to read secret key file")?;
    let mut sk_bytes = decode_input(&sk_data, format)?;

    // Zeroize raw string data immediately after decoding
    sk_data.zeroize();

    let algo = Algorithm::detect_kem_from_sec_key(sk_bytes.len())?;

    if verbose {
        eprintln!("Detected algorithm: {}", algo);
        eprintln!("Secret key size: {} bytes", sk_bytes.len());
    }

    let ct_data = if let Some(ct_path) = input {
        fs::read_to_string(ct_path).context("Failed to read ciphertext file")?
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read ciphertext from stdin")?;
        buf
    };
    let ct_bytes = decode_input(&ct_data, format)?;

    if verbose {
        eprintln!("Ciphertext size: {} bytes", ct_bytes.len());
    }

    let mut ss_bytes: Vec<u8> = match algo {
        Algorithm::MlKem512 => {
            let dk = ml_kem::ml_kem_512::DecapsulationKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid secret key: {:?}", e))?;
            let ct = ml_kem::ml_kem_512::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|e| anyhow!("Invalid ciphertext: {:?}", e))?;
            let ss = ml_kem::MlKem512::decaps(&dk, &ct)
                .map_err(|e| anyhow!("Decapsulation failed: {:?}", e))?;
            ss.as_ref().to_vec()
        }
        Algorithm::MlKem768 => {
            let dk = ml_kem::ml_kem_768::DecapsulationKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid secret key: {:?}", e))?;
            let ct = ml_kem::ml_kem_768::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|e| anyhow!("Invalid ciphertext: {:?}", e))?;
            let ss = ml_kem::MlKem768::decaps(&dk, &ct)
                .map_err(|e| anyhow!("Decapsulation failed: {:?}", e))?;
            ss.as_ref().to_vec()
        }
        Algorithm::MlKem1024 => {
            let dk = ml_kem::ml_kem_1024::DecapsulationKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid secret key: {:?}", e))?;
            let ct = ml_kem::ml_kem_1024::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|e| anyhow!("Invalid ciphertext: {:?}", e))?;
            let ss = ml_kem::MlKem1024::decaps(&dk, &ct)
                .map_err(|e| anyhow!("Decapsulation failed: {:?}", e))?;
            ss.as_ref().to_vec()
        }
        // detect_kem_algorithm only returns ML-KEM variants, so this is unreachable
        _ => unreachable!(),
    };

    // Zeroize secret key bytes after decapsulation
    sk_bytes.zeroize();

    let ss_encoded = encode_output(&ss_bytes, format, "SHARED SECRET");
    println!("{}", ss_encoded);

    if verbose {
        eprintln!("Shared secret size: {} bytes", ss_bytes.len());
    }

    // Zeroize shared secret after output
    ss_bytes.zeroize();

    Ok(())
}

/// Sign a file with ML-DSA or SLH-DSA
fn cmd_sign(
    key: &PathBuf,
    input: &PathBuf,
    output: &PathBuf,
    format: OutputFormat,
    explicit_algo: Option<Algorithm>,
    verbose: bool,
) -> Result<()> {
    let mut sk_data = fs::read_to_string(key).context("Failed to read signing key file")?;
    let mut sk_bytes = decode_input(&sk_data, format)?;

    // Zeroize the raw string data immediately after decoding
    sk_data.zeroize();

    // Use explicit algorithm if provided, otherwise detect from key size
    let algo = if let Some(a) = explicit_algo {
        // Validate key size matches the explicit algorithm
        if a.is_kem() {
            bail!("Algorithm {} is not a signature algorithm", a);
        }
        let expected_size = a.info().sec_key_size;
        if sk_bytes.len() != expected_size {
            bail!(
                "Key size {} bytes does not match algorithm {} (expected {} bytes)",
                sk_bytes.len(),
                a,
                expected_size
            );
        }
        a
    } else {
        Algorithm::detect_dsa_from_signing_key(sk_bytes.len())?
    };

    if verbose {
        eprintln!("Detected algorithm: {}", algo);
        eprintln!("Signing key size: {} bytes", sk_bytes.len());
    }

    let message = fs::read(input).context("Failed to read input file")?;

    if verbose {
        eprintln!("Message size: {} bytes", message.len());
    }

    let sig_bytes: Vec<u8> = match algo {
        Algorithm::MlDsa44 => {
            let sk = ml_dsa::dsa44::SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid signing key: {:?}", e))?;
            let sig = ml_dsa::MlDsa44::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_bytes().to_vec()
        }
        Algorithm::MlDsa65 => {
            let sk = ml_dsa::dsa65::SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid signing key: {:?}", e))?;
            let sig = ml_dsa::MlDsa65::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_bytes().to_vec()
        }
        Algorithm::MlDsa87 => {
            let sk = ml_dsa::dsa87::SigningKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("Invalid signing key: {:?}", e))?;
            let sig = ml_dsa::MlDsa87::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_bytes().to_vec()
        }
        Algorithm::SlhDsaShake128s => {
            let sk = slh_dsa::slh_dsa_shake_128s::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake128s::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake128f => {
            let sk = slh_dsa::slh_dsa_shake_128f::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake128f::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake192s => {
            let sk = slh_dsa::slh_dsa_shake_192s::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake192s::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake192f => {
            let sk = slh_dsa::slh_dsa_shake_192f::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake192f::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake256s => {
            let sk = slh_dsa::slh_dsa_shake_256s::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake256s::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake256f => {
            let sk = slh_dsa::slh_dsa_shake_256f::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake256f::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        _ => bail!("Algorithm {} does not support signing", algo),
    };

    // Zeroize the decoded secret key bytes after signing
    sk_bytes.zeroize();

    let sig_label = if algo.is_slh_dsa() {
        "SLH-DSA SIGNATURE"
    } else {
        "ML-DSA SIGNATURE"
    };
    let sig_encoded = encode_output(&sig_bytes, format, sig_label);
    fs::write(output, &sig_encoded).context("Failed to write signature")?;

    if verbose {
        eprintln!("Signature size: {} bytes", sig_bytes.len());
    }

    println!("Signature written to: {}", output.display());

    Ok(())
}

/// Verify a signature with ML-DSA or SLH-DSA
fn cmd_verify(
    pubkey: &PathBuf,
    input: &PathBuf,
    signature: &PathBuf,
    format: OutputFormat,
    explicit_algo: Option<Algorithm>,
    verbose: bool,
) -> Result<()> {
    let pk_data = fs::read_to_string(pubkey).context("Failed to read public key file")?;
    let pk_bytes = decode_input(&pk_data, format)?;

    // Use explicit algorithm if provided, otherwise detect from key size
    let algo = if let Some(a) = explicit_algo {
        // Validate key size matches the explicit algorithm
        if a.is_kem() {
            bail!("Algorithm {} is not a signature algorithm", a);
        }
        let expected_size = a.info().pub_key_size;
        if pk_bytes.len() != expected_size {
            bail!(
                "Key size {} bytes does not match algorithm {} (expected {} bytes)",
                pk_bytes.len(),
                a,
                expected_size
            );
        }
        a
    } else {
        Algorithm::detect_dsa_from_verification_key(pk_bytes.len())?
    };

    if verbose {
        eprintln!("Detected algorithm: {}", algo);
        eprintln!("Verification key size: {} bytes", pk_bytes.len());
    }

    let message = fs::read(input).context("Failed to read input file")?;
    let sig_data = fs::read_to_string(signature).context("Failed to read signature file")?;
    let sig_bytes = decode_input(&sig_data, format)?;

    if verbose {
        eprintln!("Message size: {} bytes", message.len());
        eprintln!("Signature size: {} bytes", sig_bytes.len());
    }

    let result = match algo {
        Algorithm::MlDsa44 => {
            let pk = ml_dsa::dsa44::VerificationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid verification key: {:?}", e))?;
            let sig = ml_dsa::dsa44::Signature::from_bytes(&sig_bytes)
                .map_err(|e| anyhow!("Invalid signature: {:?}", e))?;
            ml_dsa::MlDsa44::verify(&pk, &message, &sig)
        }
        Algorithm::MlDsa65 => {
            let pk = ml_dsa::dsa65::VerificationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid verification key: {:?}", e))?;
            let sig = ml_dsa::dsa65::Signature::from_bytes(&sig_bytes)
                .map_err(|e| anyhow!("Invalid signature: {:?}", e))?;
            ml_dsa::MlDsa65::verify(&pk, &message, &sig)
        }
        Algorithm::MlDsa87 => {
            let pk = ml_dsa::dsa87::VerificationKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("Invalid verification key: {:?}", e))?;
            let sig = ml_dsa::dsa87::Signature::from_bytes(&sig_bytes)
                .map_err(|e| anyhow!("Invalid signature: {:?}", e))?;
            ml_dsa::MlDsa87::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake128s => {
            let pk = slh_dsa::slh_dsa_shake_128s::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_128s::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake128s::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake128f => {
            let pk = slh_dsa::slh_dsa_shake_128f::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_128f::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake128f::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake192s => {
            let pk = slh_dsa::slh_dsa_shake_192s::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_192s::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake192s::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake192f => {
            let pk = slh_dsa::slh_dsa_shake_192f::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_192f::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake192f::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake256s => {
            let pk = slh_dsa::slh_dsa_shake_256s::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_256s::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake256s::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake256f => {
            let pk = slh_dsa::slh_dsa_shake_256f::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_256f::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake256f::verify(&pk, &message, &sig)
        }
        _ => bail!("Algorithm {} does not support verification", algo),
    };

    match result {
        Ok(()) => {
            println!("Signature is valid.");
            Ok(())
        }
        Err(_) => {
            bail!("Signature verification failed.")
        }
    }
}

/// Display information about supported algorithms
fn cmd_info() {
    println!("Kylix - Post-Quantum Cryptography Library");
    println!();
    println!("Supported algorithms:");
    println!();

    // ML-KEM algorithms
    println!("  ML-KEM (FIPS 203) - Key Encapsulation Mechanism");
    for (algo, level) in [
        (Algorithm::MlKem512, "Security Level 1 (128-bit)"),
        (Algorithm::MlKem768, "Security Level 3 (192-bit)"),
        (Algorithm::MlKem1024, "Security Level 5 (256-bit)"),
    ] {
        let info = algo.info();
        println!(
            "    {:<12} {}  PK: {}B  SK: {}B  CT: {}B",
            format!("{}", algo).to_lowercase(),
            level,
            info.pub_key_size,
            info.sec_key_size,
            info.output_size
        );
    }
    println!();

    // ML-DSA algorithms
    println!("  ML-DSA (FIPS 204) - Digital Signature Algorithm");
    for (algo, level) in [
        (Algorithm::MlDsa44, "Security Level 2 (128-bit)"),
        (Algorithm::MlDsa65, "Security Level 3 (192-bit)"),
        (Algorithm::MlDsa87, "Security Level 5 (256-bit)"),
    ] {
        let info = algo.info();
        println!(
            "    {:<12} {}  PK: {}B  SK: {}B  SIG: {}B",
            format!("{}", algo).to_lowercase(),
            level,
            info.pub_key_size,
            info.sec_key_size,
            info.output_size
        );
    }
    println!();

    // SLH-DSA algorithms
    println!("  SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm");
    for (algo, level) in [
        (Algorithm::SlhDsaShake128s, "Security Level 1 (small)"),
        (Algorithm::SlhDsaShake128f, "Security Level 1 (fast)"),
        (Algorithm::SlhDsaShake192s, "Security Level 3 (small)"),
        (Algorithm::SlhDsaShake192f, "Security Level 3 (fast)"),
        (Algorithm::SlhDsaShake256s, "Security Level 5 (small)"),
        (Algorithm::SlhDsaShake256f, "Security Level 5 (fast)"),
    ] {
        let info = algo.info();
        println!(
            "    {:<20} {}  PK: {}B  SK: {}B  SIG: {}B",
            format!("{}", algo).to_lowercase(),
            level,
            info.pub_key_size,
            info.sec_key_size,
            info.output_size
        );
    }
    println!();

    println!("Output formats:");
    println!("    hex    - Hexadecimal encoding (default)");
    println!("    base64 - Base64 encoding");
    println!("    pem    - PEM format with headers");
}

/// Generate shell completions
fn cmd_completions(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "kylix", &mut io::stdout());
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen {
            algo,
            output,
            format,
        } => cmd_keygen(algo, &output, format, cli.verbose),

        Commands::Encaps {
            pubkey,
            output,
            format,
        } => cmd_encaps(&pubkey, output.as_ref(), format, cli.verbose),

        Commands::Decaps { key, input, format } => {
            cmd_decaps(&key, input.as_ref(), format, cli.verbose)
        }

        Commands::Sign {
            key,
            input,
            output,
            format,
            algo,
        } => cmd_sign(&key, &input, &output, format, algo, cli.verbose),

        Commands::Verify {
            pubkey,
            input,
            signature,
            format,
            algo,
        } => cmd_verify(&pubkey, &input, &signature, format, algo, cli.verbose),

        Commands::Info => {
            cmd_info();
            Ok(())
        }

        Commands::Completions { shell } => {
            cmd_completions(shell);
            Ok(())
        }

        #[cfg(feature = "bench")]
        Commands::Bench {
            algo,
            iterations,
            output,
            report,
            compare,
            with,
        } => bench::cmd_bench(
            algo,
            iterations,
            output.as_ref(),
            report,
            compare,
            with.as_ref(),
            cli.verbose,
        ),
    }
}
