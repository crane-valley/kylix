//! Kylix CLI - Post-quantum cryptography command-line tool.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use kylix_bench::{BenchmarkReport, BenchmarkResult};
use kylix_pqc::ml_dsa::{self, MlDsa44, MlDsa65, MlDsa87, Signer};
use kylix_pqc::ml_kem::{self, Kem, MlKem1024, MlKem512, MlKem768};
use kylix_pqc::slh_dsa::{
    self, SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
    SlhDsaShake256s,
};
use rand::rng;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ML-KEM key size constants
const ML_KEM_512_EK_SIZE: usize = MlKem512::ENCAPSULATION_KEY_SIZE;
const ML_KEM_512_DK_SIZE: usize = MlKem512::DECAPSULATION_KEY_SIZE;
const ML_KEM_512_CT_SIZE: usize = MlKem512::CIPHERTEXT_SIZE;
const ML_KEM_768_EK_SIZE: usize = MlKem768::ENCAPSULATION_KEY_SIZE;
const ML_KEM_768_DK_SIZE: usize = MlKem768::DECAPSULATION_KEY_SIZE;
const ML_KEM_768_CT_SIZE: usize = MlKem768::CIPHERTEXT_SIZE;
const ML_KEM_1024_EK_SIZE: usize = MlKem1024::ENCAPSULATION_KEY_SIZE;
const ML_KEM_1024_DK_SIZE: usize = MlKem1024::DECAPSULATION_KEY_SIZE;
const ML_KEM_1024_CT_SIZE: usize = MlKem1024::CIPHERTEXT_SIZE;

// ML-DSA key size constants
const ML_DSA_44_VK_SIZE: usize = MlDsa44::VERIFICATION_KEY_SIZE;
const ML_DSA_44_SK_SIZE: usize = MlDsa44::SIGNING_KEY_SIZE;
const ML_DSA_44_SIG_SIZE: usize = MlDsa44::SIGNATURE_SIZE;
const ML_DSA_65_VK_SIZE: usize = MlDsa65::VERIFICATION_KEY_SIZE;
const ML_DSA_65_SK_SIZE: usize = MlDsa65::SIGNING_KEY_SIZE;
const ML_DSA_65_SIG_SIZE: usize = MlDsa65::SIGNATURE_SIZE;
const ML_DSA_87_VK_SIZE: usize = MlDsa87::VERIFICATION_KEY_SIZE;
const ML_DSA_87_SK_SIZE: usize = MlDsa87::SIGNING_KEY_SIZE;
const ML_DSA_87_SIG_SIZE: usize = MlDsa87::SIGNATURE_SIZE;

// SLH-DSA key size constants
const SLH_DSA_128S_VK_SIZE: usize = SlhDsaShake128s::VERIFICATION_KEY_SIZE;
const SLH_DSA_128S_SK_SIZE: usize = SlhDsaShake128s::SIGNING_KEY_SIZE;
const SLH_DSA_128S_SIG_SIZE: usize = SlhDsaShake128s::SIGNATURE_SIZE;
const SLH_DSA_128F_VK_SIZE: usize = SlhDsaShake128f::VERIFICATION_KEY_SIZE;
const SLH_DSA_128F_SK_SIZE: usize = SlhDsaShake128f::SIGNING_KEY_SIZE;
const SLH_DSA_128F_SIG_SIZE: usize = SlhDsaShake128f::SIGNATURE_SIZE;
const SLH_DSA_192S_VK_SIZE: usize = SlhDsaShake192s::VERIFICATION_KEY_SIZE;
const SLH_DSA_192S_SK_SIZE: usize = SlhDsaShake192s::SIGNING_KEY_SIZE;
const SLH_DSA_192S_SIG_SIZE: usize = SlhDsaShake192s::SIGNATURE_SIZE;
const SLH_DSA_192F_VK_SIZE: usize = SlhDsaShake192f::VERIFICATION_KEY_SIZE;
const SLH_DSA_192F_SK_SIZE: usize = SlhDsaShake192f::SIGNING_KEY_SIZE;
const SLH_DSA_192F_SIG_SIZE: usize = SlhDsaShake192f::SIGNATURE_SIZE;
const SLH_DSA_256S_VK_SIZE: usize = SlhDsaShake256s::VERIFICATION_KEY_SIZE;
const SLH_DSA_256S_SK_SIZE: usize = SlhDsaShake256s::SIGNING_KEY_SIZE;
const SLH_DSA_256S_SIG_SIZE: usize = SlhDsaShake256s::SIGNATURE_SIZE;
const SLH_DSA_256F_VK_SIZE: usize = SlhDsaShake256f::VERIFICATION_KEY_SIZE;
const SLH_DSA_256F_SK_SIZE: usize = SlhDsaShake256f::SIGNING_KEY_SIZE;
const SLH_DSA_256F_SIG_SIZE: usize = SlhDsaShake256f::SIGNATURE_SIZE;

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
        report: ReportFormat,

        /// Compare with external PQC implementations (OpenSSL, liboqs, wolfSSL)
        #[arg(long)]
        compare: bool,

        /// Specific tools to compare with (comma-separated: openssl,liboqs,wolfssl)
        #[arg(long, value_delimiter = ',')]
        with: Option<Vec<String>>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ReportFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Markdown table
    Markdown,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Algorithm {
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

/// Generate a key pair for the specified algorithm
fn cmd_keygen(algo: Algorithm, output: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Generating {} key pair...", algo);
    }

    let (pk_label, sk_label) = if algo.is_kem() {
        ("ML-KEM PUBLIC KEY", "ML-KEM SECRET KEY")
    } else if algo.is_slh_dsa() {
        ("SLH-DSA PUBLIC KEY", "SLH-DSA SECRET KEY")
    } else {
        ("ML-DSA PUBLIC KEY", "ML-DSA SECRET KEY")
    };

    let (pk_bytes, sk_bytes): (Vec<u8>, Vec<u8>) = match algo {
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

    let pk_encoded = encode_output(&pk_bytes, format, pk_label);
    let sk_encoded = encode_output(&sk_bytes, format, sk_label);

    let pub_path = format!("{}.pub", output);
    let sec_path = format!("{}.sec", output);

    fs::write(&pub_path, &pk_encoded).context("Failed to write public key")?;
    fs::write(&sec_path, &sk_encoded).context("Failed to write secret key")?;

    if verbose {
        eprintln!("Public key size: {} bytes", pk_bytes.len());
        eprintln!("Secret key size: {} bytes", sk_bytes.len());
    }

    println!("Public key written to: {}", pub_path);
    println!("Secret key written to: {}", sec_path);

    Ok(())
}

/// Detect algorithm from key size
fn detect_kem_algorithm(key_size: usize, is_public: bool) -> Result<Algorithm> {
    if is_public {
        match key_size {
            ML_KEM_512_EK_SIZE => Ok(Algorithm::MlKem512),
            ML_KEM_768_EK_SIZE => Ok(Algorithm::MlKem768),
            ML_KEM_1024_EK_SIZE => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown public key size: {} bytes. Expected {}, {}, or {}.",
                key_size,
                ML_KEM_512_EK_SIZE,
                ML_KEM_768_EK_SIZE,
                ML_KEM_1024_EK_SIZE
            ),
        }
    } else {
        match key_size {
            ML_KEM_512_DK_SIZE => Ok(Algorithm::MlKem512),
            ML_KEM_768_DK_SIZE => Ok(Algorithm::MlKem768),
            ML_KEM_1024_DK_SIZE => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown secret key size: {} bytes. Expected {}, {}, or {}.",
                key_size,
                ML_KEM_512_DK_SIZE,
                ML_KEM_768_DK_SIZE,
                ML_KEM_1024_DK_SIZE
            ),
        }
    }
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

    let algo = detect_kem_algorithm(pk_bytes.len(), true)?;

    if verbose {
        eprintln!("Detected algorithm: {}", algo);
        eprintln!("Public key size: {} bytes", pk_bytes.len());
    }

    let (ct_bytes, ss_bytes): (Vec<u8>, Vec<u8>) = match algo {
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

    Ok(())
}

/// Decapsulate a shared secret
fn cmd_decaps(
    key: &PathBuf,
    input: Option<&PathBuf>,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let sk_data = fs::read_to_string(key).context("Failed to read secret key file")?;
    let sk_bytes = decode_input(&sk_data, format)?;

    let algo = detect_kem_algorithm(sk_bytes.len(), false)?;

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

    let ss_bytes: Vec<u8> = match algo {
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

    let ss_encoded = encode_output(&ss_bytes, format, "SHARED SECRET");
    println!("{}", ss_encoded);

    if verbose {
        eprintln!("Shared secret size: {} bytes", ss_bytes.len());
    }

    Ok(())
}

/// Detect DSA algorithm from signing key size
fn detect_dsa_algorithm_from_sk(key_size: usize) -> Result<Algorithm> {
    match key_size {
        // ML-DSA variants
        ML_DSA_44_SK_SIZE => Ok(Algorithm::MlDsa44),
        ML_DSA_65_SK_SIZE => Ok(Algorithm::MlDsa65),
        ML_DSA_87_SK_SIZE => Ok(Algorithm::MlDsa87),
        // SLH-DSA variants (note: 128s and 128f have same SK size, prefer 128f as default)
        SLH_DSA_128S_SK_SIZE => Ok(Algorithm::SlhDsaShake128f), // 64 bytes
        SLH_DSA_192S_SK_SIZE => Ok(Algorithm::SlhDsaShake192f), // 96 bytes
        SLH_DSA_256S_SK_SIZE => Ok(Algorithm::SlhDsaShake256f), // 128 bytes
        _ => bail!(
            "Unknown signing key size: {} bytes. Expected ML-DSA (2560/4032/4896) or SLH-DSA (64/96/128).",
            key_size
        ),
    }
}

/// Detect DSA algorithm from verification key size
fn detect_dsa_algorithm_from_vk(key_size: usize) -> Result<Algorithm> {
    match key_size {
        // ML-DSA variants
        ML_DSA_44_VK_SIZE => Ok(Algorithm::MlDsa44),
        ML_DSA_65_VK_SIZE => Ok(Algorithm::MlDsa65),
        ML_DSA_87_VK_SIZE => Ok(Algorithm::MlDsa87),
        // SLH-DSA variants (note: 128s and 128f have same VK size, prefer 128f as default)
        SLH_DSA_128S_VK_SIZE => Ok(Algorithm::SlhDsaShake128f), // 32 bytes
        SLH_DSA_192S_VK_SIZE => Ok(Algorithm::SlhDsaShake192f), // 48 bytes
        SLH_DSA_256S_VK_SIZE => Ok(Algorithm::SlhDsaShake256f), // 64 bytes
        _ => bail!(
            "Unknown verification key size: {} bytes. Expected ML-DSA (1312/1952/2592) or SLH-DSA (32/48/64).",
            key_size
        ),
    }
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
        let expected_size = match a {
            Algorithm::MlDsa44 => ML_DSA_44_SK_SIZE,
            Algorithm::MlDsa65 => ML_DSA_65_SK_SIZE,
            Algorithm::MlDsa87 => ML_DSA_87_SK_SIZE,
            Algorithm::SlhDsaShake128s | Algorithm::SlhDsaShake128f => SLH_DSA_128S_SK_SIZE,
            Algorithm::SlhDsaShake192s | Algorithm::SlhDsaShake192f => SLH_DSA_192S_SK_SIZE,
            Algorithm::SlhDsaShake256s | Algorithm::SlhDsaShake256f => SLH_DSA_256S_SK_SIZE,
            _ => bail!("Algorithm {} is not a signature algorithm", a),
        };
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
        detect_dsa_algorithm_from_sk(sk_bytes.len())?
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
        let expected_size = match a {
            Algorithm::MlDsa44 => ML_DSA_44_VK_SIZE,
            Algorithm::MlDsa65 => ML_DSA_65_VK_SIZE,
            Algorithm::MlDsa87 => ML_DSA_87_VK_SIZE,
            Algorithm::SlhDsaShake128s | Algorithm::SlhDsaShake128f => SLH_DSA_128S_VK_SIZE,
            Algorithm::SlhDsaShake192s | Algorithm::SlhDsaShake192f => SLH_DSA_192S_VK_SIZE,
            Algorithm::SlhDsaShake256s | Algorithm::SlhDsaShake256f => SLH_DSA_256S_VK_SIZE,
            _ => bail!("Algorithm {} is not a signature algorithm", a),
        };
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
        detect_dsa_algorithm_from_vk(pk_bytes.len())?
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
    println!("  ML-KEM (FIPS 203) - Key Encapsulation Mechanism");
    println!(
        "    ml-kem-512   Security Level 1 (128-bit)  PK: {}B   SK: {}B  CT: {}B",
        ML_KEM_512_EK_SIZE, ML_KEM_512_DK_SIZE, ML_KEM_512_CT_SIZE
    );
    println!(
        "    ml-kem-768   Security Level 3 (192-bit)  PK: {}B  SK: {}B  CT: {}B",
        ML_KEM_768_EK_SIZE, ML_KEM_768_DK_SIZE, ML_KEM_768_CT_SIZE
    );
    println!(
        "    ml-kem-1024  Security Level 5 (256-bit)  PK: {}B  SK: {}B  CT: {}B",
        ML_KEM_1024_EK_SIZE, ML_KEM_1024_DK_SIZE, ML_KEM_1024_CT_SIZE
    );
    println!();
    println!("  ML-DSA (FIPS 204) - Digital Signature Algorithm");
    println!(
        "    ml-dsa-44    Security Level 2 (128-bit)  PK: {}B  SK: {}B  SIG: {}B",
        ML_DSA_44_VK_SIZE, ML_DSA_44_SK_SIZE, ML_DSA_44_SIG_SIZE
    );
    println!(
        "    ml-dsa-65    Security Level 3 (192-bit)  PK: {}B  SK: {}B  SIG: {}B",
        ML_DSA_65_VK_SIZE, ML_DSA_65_SK_SIZE, ML_DSA_65_SIG_SIZE
    );
    println!(
        "    ml-dsa-87    Security Level 5 (256-bit)  PK: {}B  SK: {}B  SIG: {}B",
        ML_DSA_87_VK_SIZE, ML_DSA_87_SK_SIZE, ML_DSA_87_SIG_SIZE
    );
    println!();
    println!("  SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm");
    println!(
        "    slh-dsa-shake-128s  Security Level 1 (small)  PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_128S_VK_SIZE, SLH_DSA_128S_SK_SIZE, SLH_DSA_128S_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-128f  Security Level 1 (fast)   PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_128F_VK_SIZE, SLH_DSA_128F_SK_SIZE, SLH_DSA_128F_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-192s  Security Level 3 (small)  PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_192S_VK_SIZE, SLH_DSA_192S_SK_SIZE, SLH_DSA_192S_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-192f  Security Level 3 (fast)   PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_192F_VK_SIZE, SLH_DSA_192F_SK_SIZE, SLH_DSA_192F_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-256s  Security Level 5 (small)  PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_256S_VK_SIZE, SLH_DSA_256S_SK_SIZE, SLH_DSA_256S_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-256f  Security Level 5 (fast)   PK: {}B   SK: {}B   SIG: {}B",
        SLH_DSA_256F_VK_SIZE, SLH_DSA_256F_SK_SIZE, SLH_DSA_256F_SIG_SIZE
    );
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

// ============================================================================
// External Tool Comparison
// ============================================================================

/// Detected external PQC tool
#[derive(Debug, Clone)]
struct ExternalTool {
    name: String,
    path: PathBuf,
    version: String,
}

/// Benchmark results from an external tool
#[derive(Debug, Clone)]
struct ExternalBenchResult {
    tool_name: String,
    algorithm: String,
    operation: String,
    mean_us: f64,
}

/// Detect available external PQC tools
fn detect_external_tools(filter: Option<&Vec<String>>) -> Vec<ExternalTool> {
    let mut tools = Vec::new();

    // Check if tool should be included based on filter
    let should_include = |name: &str| -> bool {
        filter.as_ref().map_or(true, |f| {
            f.iter().any(|s| s.eq_ignore_ascii_case(name))
        })
    };

    // Detect liboqs speed_kem tool
    if should_include("liboqs") {
        if let Some(tool) = detect_liboqs() {
            tools.push(tool);
        }
    }

    // Detect OpenSSL 3.5+ with PQC support
    if should_include("openssl") {
        if let Some(tool) = detect_openssl() {
            tools.push(tool);
        }
    }

    tools
}

/// Detect liboqs speed_kem/speed_sig tools
fn detect_liboqs() -> Option<ExternalTool> {
    // Try to find speed_kem in PATH
    let path = which::which("speed_kem").ok()?;

    // Get version by running with --help or checking liboqs version
    let output = Command::new(&path).arg("--help").output().ok()?;
    let help_text = String::from_utf8_lossy(&output.stdout);

    // Extract version info if available
    let version = if help_text.contains("liboqs") {
        // Try to extract version
        "liboqs".to_string()
    } else {
        "unknown".to_string()
    };

    Some(ExternalTool {
        name: "liboqs".to_string(),
        path,
        version,
    })
}

/// Detect OpenSSL 3.5+ with PQC support
fn detect_openssl() -> Option<ExternalTool> {
    // Try PATH first, then common installation locations
    let candidates: Vec<std::path::PathBuf> = {
        let mut paths = vec![];

        // Check PATH
        if let Ok(p) = which::which("openssl") {
            paths.push(p);
        }

        // Windows: FireDaemon OpenSSL
        #[cfg(target_os = "windows")]
        {
            paths.push(std::path::PathBuf::from(
                r"C:\Program Files\FireDaemon OpenSSL 3\bin\openssl.exe",
            ));
        }

        // macOS/Linux: Homebrew, common locations
        #[cfg(not(target_os = "windows"))]
        {
            paths.push(std::path::PathBuf::from("/opt/homebrew/bin/openssl"));
            paths.push(std::path::PathBuf::from("/usr/local/bin/openssl"));
        }

        paths
    };

    for path in candidates {
        if !path.exists() {
            continue;
        }

        let output = match Command::new(&path).arg("version").output() {
            Ok(o) => o,
            Err(_) => continue,
        };
        let version_str = String::from_utf8_lossy(&output.stdout);

        // Check for OpenSSL 3.5+ (which has native PQC support)
        if version_str.contains("OpenSSL 3.5")
            || version_str.contains("OpenSSL 3.6")
            || version_str.contains("OpenSSL 3.7")
        {
            // Verify PQC algorithms are available
            let list_output = match Command::new(&path)
                .args(["list", "-kem-algorithms"])
                .output()
            {
                Ok(o) => o,
                Err(_) => continue,
            };
            let kem_list = String::from_utf8_lossy(&list_output.stdout);

            if kem_list.contains("ML-KEM") {
                return Some(ExternalTool {
                    name: "OpenSSL".to_string(),
                    path,
                    version: version_str.trim().to_string(),
                });
            }
        }
    }

    None
}

/// Run liboqs KEM benchmark
fn run_liboqs_kem_benchmark(
    tool: &ExternalTool,
    algo: &str,
    iterations: u64,
) -> Result<Vec<ExternalBenchResult>> {
    // Map Kylix algorithm names to liboqs names
    let liboqs_algo = match algo {
        "ML-KEM-512" => "ML-KEM-512",
        "ML-KEM-768" => "ML-KEM-768",
        "ML-KEM-1024" => "ML-KEM-1024",
        _ => return Ok(vec![]),
    };

    // Run speed_kem with the algorithm
    let output = Command::new(&tool.path)
        .args(["--alg", liboqs_algo, &iterations.to_string()])
        .output()
        .context("Failed to run liboqs speed_kem")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_liboqs_output(&stdout, &tool.name, algo)
}

/// Run liboqs signature benchmark
fn run_liboqs_sig_benchmark(
    tool: &ExternalTool,
    algo: &str,
    iterations: u64,
) -> Result<Vec<ExternalBenchResult>> {
    // Map Kylix algorithm names to liboqs names
    let liboqs_algo = match algo {
        "ML-DSA-44" => "ML-DSA-44",
        "ML-DSA-65" => "ML-DSA-65",
        "ML-DSA-87" => "ML-DSA-87",
        _ => return Ok(vec![]),
    };

    // Find speed_sig (should be in same directory as speed_kem)
    let speed_sig_path = tool.path.parent().map(|p| p.join("speed_sig"));
    let speed_sig = speed_sig_path
        .filter(|p| p.exists())
        .or_else(|| which::which("speed_sig").ok());

    let Some(sig_path) = speed_sig else {
        return Ok(vec![]);
    };

    let output = Command::new(&sig_path)
        .args(["--alg", liboqs_algo, &iterations.to_string()])
        .output()
        .context("Failed to run liboqs speed_sig")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_liboqs_output(&stdout, &tool.name, algo)
}

/// Parse liboqs speed_kem/speed_sig output
fn parse_liboqs_output(
    output: &str,
    tool_name: &str,
    algo: &str,
) -> Result<Vec<ExternalBenchResult>> {
    let mut results = Vec::new();

    // liboqs output format:
    // Operation              Iterations  Total time (s)  Time (us): mean
    // keygen:                     10000          0.142           14.200
    // encaps:                     10000          0.185           18.500
    // decaps:                     10000          0.201           20.100

    for line in output.lines() {
        let line = line.trim();

        // Parse keygen/encaps/decaps/sign/verify lines
        for op in ["keygen", "encaps", "decaps", "sign", "verify"] {
            if line.starts_with(&format!("{}:", op)) {
                // Extract mean time from the line
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(mean_us) = parts.last().unwrap_or(&"0").parse::<f64>() {
                        results.push(ExternalBenchResult {
                            tool_name: tool_name.to_string(),
                            algorithm: algo.to_string(),
                            operation: op.to_string(),
                            mean_us,
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Run OpenSSL KEM benchmark (time individual operations)
fn run_openssl_kem_benchmark(
    tool: &ExternalTool,
    algo: &str,
    iterations: u64,
) -> Result<Vec<ExternalBenchResult>> {
    let openssl_algo = match algo {
        "ML-KEM-512" => "ML-KEM-512",
        "ML-KEM-768" => "ML-KEM-768",
        "ML-KEM-1024" => "ML-KEM-1024",
        _ => return Ok(vec![]),
    };

    let mut results = Vec::new();
    let temp_dir = std::env::temp_dir();
    let key_file = temp_dir.join("kylix_bench_key.pem");
    let ct_file = temp_dir.join("kylix_bench_ct.bin");
    let ss_file = temp_dir.join("kylix_bench_ss.bin");

    // Benchmark keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["genpkey", "-algorithm", openssl_algo, "-out"])
            .arg(&key_file)
            .output();
    }
    let keygen_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "keygen".to_string(),
        mean_us: keygen_total.as_micros() as f64 / iterations as f64,
    });

    // Generate a key for encaps/decaps benchmarks
    let _ = Command::new(&tool.path)
        .args(["genpkey", "-algorithm", openssl_algo, "-out"])
        .arg(&key_file)
        .output();

    // Extract public key
    let pub_file = temp_dir.join("kylix_bench_pub.pem");
    let _ = Command::new(&tool.path)
        .args(["pkey", "-in"])
        .arg(&key_file)
        .args(["-pubout", "-out"])
        .arg(&pub_file)
        .output();

    // Benchmark encaps
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["pkeyutl", "-encap", "-inkey"])
            .arg(&pub_file)
            .args(["-pubin", "-out"])
            .arg(&ct_file)
            .args(["-secret"])
            .arg(&ss_file)
            .output();
    }
    let encaps_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "encaps".to_string(),
        mean_us: encaps_total.as_micros() as f64 / iterations as f64,
    });

    // Benchmark decaps
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["pkeyutl", "-decap", "-inkey"])
            .arg(&key_file)
            .args(["-in"])
            .arg(&ct_file)
            .args(["-secret"])
            .arg(&ss_file)
            .output();
    }
    let decaps_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "decaps".to_string(),
        mean_us: decaps_total.as_micros() as f64 / iterations as f64,
    });

    // Cleanup
    let _ = fs::remove_file(&key_file);
    let _ = fs::remove_file(&pub_file);
    let _ = fs::remove_file(&ct_file);
    let _ = fs::remove_file(&ss_file);

    Ok(results)
}

/// Run OpenSSL signature benchmark
fn run_openssl_sig_benchmark(
    tool: &ExternalTool,
    algo: &str,
    iterations: u64,
) -> Result<Vec<ExternalBenchResult>> {
    let openssl_algo = match algo {
        "ML-DSA-44" => "ML-DSA-44",
        "ML-DSA-65" => "ML-DSA-65",
        "ML-DSA-87" => "ML-DSA-87",
        _ => return Ok(vec![]),
    };

    let mut results = Vec::new();
    let temp_dir = std::env::temp_dir();
    let key_file = temp_dir.join("kylix_bench_sig_key.pem");
    let msg_file = temp_dir.join("kylix_bench_msg.txt");
    let sig_file = temp_dir.join("kylix_bench_sig.bin");

    // Create test message
    fs::write(&msg_file, b"The quick brown fox jumps over the lazy dog")?;

    // Benchmark keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["genpkey", "-algorithm", openssl_algo, "-out"])
            .arg(&key_file)
            .output();
    }
    let keygen_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "keygen".to_string(),
        mean_us: keygen_total.as_micros() as f64 / iterations as f64,
    });

    // Generate a key for sign/verify benchmarks
    let _ = Command::new(&tool.path)
        .args(["genpkey", "-algorithm", openssl_algo, "-out"])
        .arg(&key_file)
        .output();

    // Benchmark sign
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["pkeyutl", "-sign", "-inkey"])
            .arg(&key_file)
            .args(["-in"])
            .arg(&msg_file)
            .args(["-out"])
            .arg(&sig_file)
            .output();
    }
    let sign_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "sign".to_string(),
        mean_us: sign_total.as_micros() as f64 / iterations as f64,
    });

    // Extract public key
    let pub_file = temp_dir.join("kylix_bench_sig_pub.pem");
    let _ = Command::new(&tool.path)
        .args(["pkey", "-in"])
        .arg(&key_file)
        .args(["-pubout", "-out"])
        .arg(&pub_file)
        .output();

    // Benchmark verify
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Command::new(&tool.path)
            .args(["pkeyutl", "-verify", "-inkey"])
            .arg(&pub_file)
            .args(["-pubin", "-in"])
            .arg(&msg_file)
            .args(["-sigfile"])
            .arg(&sig_file)
            .output();
    }
    let verify_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "verify".to_string(),
        mean_us: verify_total.as_micros() as f64 / iterations as f64,
    });

    // Cleanup
    let _ = fs::remove_file(&key_file);
    let _ = fs::remove_file(&pub_file);
    let _ = fs::remove_file(&msg_file);
    let _ = fs::remove_file(&sig_file);

    Ok(results)
}

/// Run benchmarks on external tools
fn run_external_benchmarks(
    tools: &[ExternalTool],
    algo: &str,
    is_kem: bool,
    iterations: u64,
) -> Vec<ExternalBenchResult> {
    let mut results = Vec::new();

    for tool in tools {
        let tool_results = if tool.name == "liboqs" {
            if is_kem {
                run_liboqs_kem_benchmark(tool, algo, iterations)
            } else {
                run_liboqs_sig_benchmark(tool, algo, iterations)
            }
        } else if tool.name == "OpenSSL" {
            if is_kem {
                run_openssl_kem_benchmark(tool, algo, iterations)
            } else {
                run_openssl_sig_benchmark(tool, algo, iterations)
            }
        } else {
            Ok(vec![])
        };

        if let Ok(r) = tool_results {
            results.extend(r);
        }
    }

    results
}

/// Format comparison table
fn format_comparison_table(
    kylix_results: &[BenchmarkResult],
    external_results: &[ExternalBenchResult],
    report_format: ReportFormat,
) -> String {
    // Group results by algorithm
    let mut by_algo: std::collections::HashMap<String, Vec<(&str, &str, f64)>> =
        std::collections::HashMap::new();

    // Add Kylix results
    for r in kylix_results {
        let algo = r.algorithm.clone();
        by_algo
            .entry(algo)
            .or_default()
            .push(("Kylix", &r.operation, r.mean.as_micros() as f64));
    }

    // Add external results
    for r in external_results {
        by_algo
            .entry(r.algorithm.clone())
            .or_default()
            .push((&r.tool_name, &r.operation, r.mean_us));
    }

    match report_format {
        ReportFormat::Markdown => format_comparison_markdown(&by_algo),
        ReportFormat::Json => format_comparison_json(kylix_results, external_results),
        ReportFormat::Text => format_comparison_text(&by_algo),
    }
}

fn format_comparison_text(
    by_algo: &std::collections::HashMap<String, Vec<(&str, &str, f64)>>,
) -> String {
    let mut output = String::new();
    output.push_str("Kylix Benchmark Comparison\n");
    output.push_str("==========================\n\n");

    for (algo, results) in by_algo {
        output.push_str(&format!("{}\n", algo));
        output.push_str(&"-".repeat(algo.len()));
        output.push('\n');

        // Group by tool
        let mut by_tool: std::collections::HashMap<&str, Vec<(&str, f64)>> =
            std::collections::HashMap::new();
        for (tool, op, time) in results {
            by_tool.entry(*tool).or_default().push((*op, *time));
        }

        // Find Kylix times for comparison
        let kylix_times: std::collections::HashMap<&str, f64> = by_tool
            .get("Kylix")
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        for (tool, ops) in &by_tool {
            output.push_str(&format!("  {}:\n", tool));
            for (op, time) in ops {
                let speedup = if *tool != "Kylix" {
                    kylix_times
                        .get(op)
                        .map(|kt| format!(" ({:.1}x faster)", time / kt))
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                output.push_str(&format!("    {}: {:.1} µs{}\n", op, time, speedup));
            }
        }
        output.push('\n');
    }

    output
}

fn format_comparison_markdown(
    by_algo: &std::collections::HashMap<String, Vec<(&str, &str, f64)>>,
) -> String {
    let mut output = String::new();
    output.push_str("# Kylix Benchmark Comparison\n\n");

    for (algo, results) in by_algo {
        output.push_str(&format!("## {}\n\n", algo));

        // Collect unique tools and operations
        let mut tools: Vec<&str> = results.iter().map(|(t, _, _)| *t).collect();
        tools.sort();
        tools.dedup();

        let mut ops: Vec<&str> = results.iter().map(|(_, o, _)| *o).collect();
        ops.sort();
        ops.dedup();

        // Build table header
        output.push_str("| Library |");
        for op in &ops {
            output.push_str(&format!(" {} |", op));
        }
        output.push('\n');

        output.push_str("|---------|");
        for _ in &ops {
            output.push_str("-------:|");
        }
        output.push('\n');

        // Build table rows
        for tool in &tools {
            output.push_str(&format!("| {} |", tool));
            for op in &ops {
                let time = results
                    .iter()
                    .find(|(t, o, _)| t == tool && o == op)
                    .map(|(_, _, time)| *time);
                if let Some(t) = time {
                    output.push_str(&format!(" {:.1} µs |", t));
                } else {
                    output.push_str(" - |");
                }
            }
            output.push('\n');
        }
        output.push('\n');
    }

    output
}

fn format_comparison_json(
    kylix_results: &[BenchmarkResult],
    external_results: &[ExternalBenchResult],
) -> String {
    use serde_json::json;

    let kylix: Vec<_> = kylix_results
        .iter()
        .map(|r| {
            json!({
                "tool": "Kylix",
                "algorithm": r.algorithm,
                "operation": r.operation,
                "mean_us": r.mean.as_micros()
            })
        })
        .collect();

    let external: Vec<_> = external_results
        .iter()
        .map(|r| {
            json!({
                "tool": r.tool_name,
                "algorithm": r.algorithm,
                "operation": r.operation,
                "mean_us": r.mean_us
            })
        })
        .collect();

    let combined: Vec<_> = kylix.into_iter().chain(external).collect();
    serde_json::to_string_pretty(&combined).unwrap_or_default()
}

// ============================================================================
// Benchmark Functions
// ============================================================================

/// Run a single benchmark and return timing data
fn run_benchmark<F>(iterations: u64, mut f: F) -> Vec<Duration>
where
    F: FnMut(),
{
    // Warmup
    for _ in 0..10 {
        f();
    }

    // Actual benchmark
    let mut times = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        times.push(start.elapsed());
    }
    times
}

/// Generic benchmark for KEM algorithms
fn bench_kem_variant<K: Kem>(algo_name: &str, iterations: u64) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    // KeyGen - RNG initialized outside the loop
    {
        let mut bench_rng = rng();
        let times = run_benchmark(iterations, || {
            let _ = K::keygen(&mut bench_rng);
        });
        results.push(BenchmarkResult::new(
            algo_name, "keygen", iterations, &times,
        ));
    }

    // Encaps - RNG initialized outside the loop
    {
        let mut setup_rng = rng();
        let (_dk, ek) = K::keygen(&mut setup_rng).unwrap();
        let mut bench_rng = rng();
        let times = run_benchmark(iterations, || {
            let _ = K::encaps(&ek, &mut bench_rng);
        });
        results.push(BenchmarkResult::new(
            algo_name, "encaps", iterations, &times,
        ));
    }

    // Decaps
    {
        let mut setup_rng = rng();
        let (dk, ek) = K::keygen(&mut setup_rng).unwrap();
        let (ct, _) = K::encaps(&ek, &mut setup_rng).unwrap();
        let times = run_benchmark(iterations, || {
            let _ = K::decaps(&dk, &ct);
        });
        results.push(BenchmarkResult::new(
            algo_name, "decaps", iterations, &times,
        ));
    }

    results
}

/// Run benchmarks for ML-KEM algorithms
fn bench_ml_kem(algo: Algorithm, iterations: u64) -> Vec<BenchmarkResult> {
    let algo_name = algo.to_string();
    match algo {
        Algorithm::MlKem512 => bench_kem_variant::<MlKem512>(&algo_name, iterations),
        Algorithm::MlKem768 => bench_kem_variant::<MlKem768>(&algo_name, iterations),
        Algorithm::MlKem1024 => bench_kem_variant::<MlKem1024>(&algo_name, iterations),
        _ => Vec::new(),
    }
}

/// Generic benchmark for DSA algorithms
fn bench_dsa_variant<S: Signer>(
    algo_name: &str,
    iterations: u64,
    message: &[u8],
) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    // KeyGen - RNG initialized outside the loop
    {
        let mut bench_rng = rng();
        let times = run_benchmark(iterations, || {
            let _ = S::keygen(&mut bench_rng);
        });
        results.push(BenchmarkResult::new(
            algo_name, "keygen", iterations, &times,
        ));
    }

    // Sign
    {
        let mut setup_rng = rng();
        let (sk, _vk) = S::keygen(&mut setup_rng).unwrap();
        let times = run_benchmark(iterations, || {
            let _ = S::sign(&sk, message);
        });
        results.push(BenchmarkResult::new(algo_name, "sign", iterations, &times));
    }

    // Verify
    {
        let mut setup_rng = rng();
        let (sk, vk) = S::keygen(&mut setup_rng).unwrap();
        let sig = S::sign(&sk, message).unwrap();
        let times = run_benchmark(iterations, || {
            let _ = S::verify(&vk, message, &sig);
        });
        results.push(BenchmarkResult::new(
            algo_name, "verify", iterations, &times,
        ));
    }

    results
}

/// Run benchmarks for ML-DSA algorithms
fn bench_ml_dsa(algo: Algorithm, iterations: u64) -> Vec<BenchmarkResult> {
    let algo_name = algo.to_string();
    let message = b"The quick brown fox jumps over the lazy dog";

    match algo {
        Algorithm::MlDsa44 => bench_dsa_variant::<MlDsa44>(&algo_name, iterations, message),
        Algorithm::MlDsa65 => bench_dsa_variant::<MlDsa65>(&algo_name, iterations, message),
        Algorithm::MlDsa87 => bench_dsa_variant::<MlDsa87>(&algo_name, iterations, message),
        _ => Vec::new(),
    }
}

/// Run benchmarks for SLH-DSA algorithms
fn bench_slh_dsa(algo: Algorithm, iterations: u64) -> Vec<BenchmarkResult> {
    let algo_name = algo.to_string();
    let message = b"The quick brown fox jumps over the lazy dog";

    match algo {
        Algorithm::SlhDsaShake128s => {
            bench_dsa_variant::<SlhDsaShake128s>(&algo_name, iterations, message)
        }
        Algorithm::SlhDsaShake128f => {
            bench_dsa_variant::<SlhDsaShake128f>(&algo_name, iterations, message)
        }
        Algorithm::SlhDsaShake192s => {
            bench_dsa_variant::<SlhDsaShake192s>(&algo_name, iterations, message)
        }
        Algorithm::SlhDsaShake192f => {
            bench_dsa_variant::<SlhDsaShake192f>(&algo_name, iterations, message)
        }
        Algorithm::SlhDsaShake256s => {
            bench_dsa_variant::<SlhDsaShake256s>(&algo_name, iterations, message)
        }
        Algorithm::SlhDsaShake256f => {
            bench_dsa_variant::<SlhDsaShake256f>(&algo_name, iterations, message)
        }
        _ => Vec::new(),
    }
}

/// Run performance benchmarks
fn cmd_bench(
    algo: Option<Algorithm>,
    iterations: u64,
    output: Option<&PathBuf>,
    report_format: ReportFormat,
    compare: bool,
    with: Option<&Vec<String>>,
    verbose: bool,
) -> Result<()> {
    if iterations == 0 {
        bail!("Iterations must be at least 1");
    }

    if verbose {
        eprintln!("Running benchmarks with {} iterations...", iterations);
    }

    // Detect external tools if comparison is requested
    let external_tools = if compare {
        let tools = detect_external_tools(with);
        if tools.is_empty() {
            eprintln!("Warning: No external PQC tools detected. Comparison will show Kylix results only.");
            eprintln!("Supported tools: liboqs (speed_kem/speed_sig), OpenSSL 3.5+");
        } else if verbose {
            eprintln!("Detected external tools:");
            for tool in &tools {
                eprintln!("  - {} ({})", tool.name, tool.version);
            }
        }
        tools
    } else {
        vec![]
    };

    let mut report = BenchmarkReport::new("kylix");
    let mut external_results: Vec<ExternalBenchResult> = Vec::new();

    let algorithms = if let Some(a) = algo {
        vec![a]
    } else {
        // Note: SLH-DSA not included by default as it's slow (use --algo to specify)
        vec![
            Algorithm::MlKem512,
            Algorithm::MlKem768,
            Algorithm::MlKem1024,
            Algorithm::MlDsa44,
            Algorithm::MlDsa65,
            Algorithm::MlDsa87,
        ]
    };

    for algo in &algorithms {
        if verbose {
            eprintln!("Benchmarking {}...", algo);
        }

        let results = if algo.is_kem() {
            bench_ml_kem(*algo, iterations)
        } else if algo.is_slh_dsa() {
            bench_slh_dsa(*algo, iterations)
        } else {
            bench_ml_dsa(*algo, iterations)
        };

        for result in results {
            report.add_result(result);
        }

        // Run external benchmarks if comparison is requested
        if compare && !external_tools.is_empty() {
            let algo_name = format!("{}", algo);
            let is_kem = algo.is_kem();

            if verbose {
                eprintln!("  Running external tool benchmarks...");
            }

            let ext_results = run_external_benchmarks(&external_tools, &algo_name, is_kem, iterations);
            external_results.extend(ext_results);
        }
    }

    let output_content = if compare {
        format_comparison_table(&report.results, &external_results, report_format)
    } else {
        match report_format {
            ReportFormat::Text => {
                let mut text = String::new();
                text.push_str("Kylix Benchmark Results\n");
                text.push_str("=======================\n\n");
                for result in &report.results {
                    text.push_str(&result.format());
                    text.push('\n');
                }
                text
            }
            ReportFormat::Json => {
                serde_json::to_string_pretty(&report).context("Failed to serialize report to JSON")?
            }
            ReportFormat::Markdown => report.to_markdown(),
        }
    };

    if let Some(out_path) = output {
        fs::write(out_path, &output_content).context("Failed to write benchmark report")?;
        println!("Benchmark report written to: {}", out_path.display());
    } else {
        println!("{}", output_content);
    }

    Ok(())
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

        Commands::Bench {
            algo,
            iterations,
            output,
            report,
            compare,
            with,
        } => cmd_bench(
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
