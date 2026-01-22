//! Kylix CLI - Post-quantum cryptography command-line tool.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use kylix_pqc::ml_kem::{self, Kem};
use rand::rng;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

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

    /// Sign a file (requires ML-DSA - not yet implemented)
    Sign {
        /// Path to the secret key file
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

    /// Verify a signature (requires ML-DSA - not yet implemented)
    Verify {
        /// Path to the public key file
        #[arg(long = "pub")]
        pubkey: PathBuf,

        /// Input file that was signed
        #[arg(short, long)]
        input: PathBuf,

        /// Signature file
        #[arg(short, long)]
        signature: PathBuf,
    },

    /// Display information about supported algorithms
    Info,

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
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
    // Future: ML-DSA variants
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::MlKem512 => write!(f, "ML-KEM-512"),
            Algorithm::MlKem768 => write!(f, "ML-KEM-768"),
            Algorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
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
                .chars()
                .collect::<Vec<_>>()
                .chunks(64)
                .map(|c| c.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "-----BEGIN {}-----\n{}\n-----END {}-----",
                label, wrapped, label
            )
        }
    }
}

/// Decode bytes from the specified format
fn decode_input(data: &str, format: OutputFormat) -> Result<Vec<u8>> {
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

    match format {
        OutputFormat::Hex => hex::decode(data).context("Failed to decode hex"),
        OutputFormat::Base64 => BASE64.decode(data).context("Failed to decode base64"),
        OutputFormat::Pem => bail!("Expected PEM format but not found"),
    }
}

/// Generate a key pair for the specified algorithm
fn cmd_keygen(algo: Algorithm, output: &str, format: OutputFormat, verbose: bool) -> Result<()> {
    if verbose {
        eprintln!("Generating {} key pair...", algo);
    }

    let (pk_label, sk_label) = match algo {
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
            ("ML-KEM PUBLIC KEY", "ML-KEM SECRET KEY")
        }
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
            800 => Ok(Algorithm::MlKem512),
            1184 => Ok(Algorithm::MlKem768),
            1568 => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown public key size: {} bytes. Expected 800, 1184, or 1568.",
                key_size
            ),
        }
    } else {
        match key_size {
            1632 => Ok(Algorithm::MlKem512),
            2400 => Ok(Algorithm::MlKem768),
            3168 => Ok(Algorithm::MlKem1024),
            _ => bail!(
                "Unknown secret key size: {} bytes. Expected 1632, 2400, or 3168.",
                key_size
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
    };

    let ss_encoded = encode_output(&ss_bytes, format, "SHARED SECRET");
    println!("{}", ss_encoded);

    if verbose {
        eprintln!("Shared secret size: {} bytes", ss_bytes.len());
    }

    Ok(())
}

/// Sign a file (not yet implemented)
fn cmd_sign(
    _key: &PathBuf,
    _input: &PathBuf,
    _output: &PathBuf,
    _format: OutputFormat,
    _verbose: bool,
) -> Result<()> {
    bail!("Signing is not yet implemented. ML-DSA support coming soon.")
}

/// Verify a signature (not yet implemented)
fn cmd_verify(
    _pubkey: &PathBuf,
    _input: &PathBuf,
    _signature: &PathBuf,
    _verbose: bool,
) -> Result<()> {
    bail!("Verification is not yet implemented. ML-DSA support coming soon.")
}

/// Display information about supported algorithms
fn cmd_info() {
    println!("Kylix - Post-Quantum Cryptography Library");
    println!();
    println!("Supported algorithms:");
    println!();
    println!("  ML-KEM (FIPS 203) - Key Encapsulation Mechanism");
    println!("    ml-kem-512   Security Level 1 (128-bit)  PK: 800B   SK: 1632B  CT: 768B");
    println!("    ml-kem-768   Security Level 3 (192-bit)  PK: 1184B  SK: 2400B  CT: 1088B");
    println!("    ml-kem-1024  Security Level 5 (256-bit)  PK: 1568B  SK: 3168B  CT: 1568B");
    println!();
    println!("Planned support:");
    println!("    ML-DSA (FIPS 204)  - Digital Signature Algorithm");
    println!("    SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures");
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
        } => cmd_sign(&key, &input, &output, format, cli.verbose),

        Commands::Verify {
            pubkey,
            input,
            signature,
        } => cmd_verify(&pubkey, &input, &signature, cli.verbose),

        Commands::Info => {
            cmd_info();
            Ok(())
        }

        Commands::Completions { shell } => {
            cmd_completions(shell);
            Ok(())
        }
    }
}
