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

    /// Sign a file using ML-DSA
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
    },

    /// Verify a signature using ML-DSA
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

/// Sign a file with ML-DSA
fn cmd_sign(
    key: &PathBuf,
    input: &PathBuf,
    output: &PathBuf,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let mut sk_data = fs::read_to_string(key).context("Failed to read signing key file")?;
    let mut sk_bytes = decode_input(&sk_data, format)?;

    // Zeroize the raw string data immediately after decoding
    sk_data.zeroize();

    let algo = detect_dsa_algorithm_from_sk(sk_bytes.len())?;

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
        Algorithm::SlhDsaShake128s | Algorithm::SlhDsaShake128f => {
            let sk = slh_dsa::slh_dsa_shake_128f::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake128f::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake192s | Algorithm::SlhDsaShake192f => {
            let sk = slh_dsa::slh_dsa_shake_192f::SigningKey::from_bytes(&sk_bytes)
                .ok_or_else(|| anyhow!("Invalid signing key"))?;
            let sig = slh_dsa::SlhDsaShake192f::sign(&sk, &message)
                .map_err(|e| anyhow!("Signing failed: {:?}", e))?;
            sig.as_ref().to_vec()
        }
        Algorithm::SlhDsaShake256s | Algorithm::SlhDsaShake256f => {
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

/// Verify a signature with ML-DSA
fn cmd_verify(
    pubkey: &PathBuf,
    input: &PathBuf,
    signature: &PathBuf,
    format: OutputFormat,
    verbose: bool,
) -> Result<()> {
    let pk_data = fs::read_to_string(pubkey).context("Failed to read public key file")?;
    let pk_bytes = decode_input(&pk_data, format)?;

    let algo = detect_dsa_algorithm_from_vk(pk_bytes.len())?;

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
        Algorithm::SlhDsaShake128s | Algorithm::SlhDsaShake128f => {
            let pk = slh_dsa::slh_dsa_shake_128f::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_128f::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake128f::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake192s | Algorithm::SlhDsaShake192f => {
            let pk = slh_dsa::slh_dsa_shake_192f::VerificationKey::from_bytes(&pk_bytes)
                .ok_or_else(|| anyhow!("Invalid verification key"))?;
            let sig = slh_dsa::slh_dsa_shake_192f::Signature::from_bytes(&sig_bytes)
                .ok_or_else(|| anyhow!("Invalid signature"))?;
            slh_dsa::SlhDsaShake192f::verify(&pk, &message, &sig)
        }
        Algorithm::SlhDsaShake256s | Algorithm::SlhDsaShake256f => {
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
        "    slh-dsa-shake-256s  Security Level 5 (small)  PK: {}B   SK: {}B  SIG: {}B",
        SLH_DSA_256S_VK_SIZE, SLH_DSA_256S_SK_SIZE, SLH_DSA_256S_SIG_SIZE
    );
    println!(
        "    slh-dsa-shake-256f  Security Level 5 (fast)   PK: {}B   SK: {}B  SIG: {}B",
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
    verbose: bool,
) -> Result<()> {
    if iterations == 0 {
        bail!("Iterations must be at least 1");
    }

    if verbose {
        eprintln!("Running benchmarks with {} iterations...", iterations);
    }

    let mut report = BenchmarkReport::new("kylix");

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

    for algo in algorithms {
        if verbose {
            eprintln!("Benchmarking {}...", algo);
        }

        let results = if algo.is_kem() {
            bench_ml_kem(algo, iterations)
        } else if algo.is_slh_dsa() {
            bench_slh_dsa(algo, iterations)
        } else {
            bench_ml_dsa(algo, iterations)
        };

        for result in results {
            report.add_result(result);
        }
    }

    let output_content = match report_format {
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
        } => cmd_sign(&key, &input, &output, format, cli.verbose),

        Commands::Verify {
            pubkey,
            input,
            signature,
            format,
        } => cmd_verify(&pubkey, &input, &signature, format, cli.verbose),

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
        } => cmd_bench(algo, iterations, output.as_ref(), report, cli.verbose),
    }
}
