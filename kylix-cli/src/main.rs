//! Kylix CLI - Post-quantum cryptography command-line tool.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kylix")]
#[command(author, version, about = "Post-quantum cryptography CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Algorithm to use (ml-kem-512, ml-kem-768, ml-kem-1024)
        #[arg(short, long, default_value = "ml-kem-768")]
        algorithm: String,

        /// Output file prefix for keys
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Encapsulate a shared secret
    Encaps {
        /// Path to the encapsulation (public) key file
        #[arg(short = 'k', long)]
        key: String,

        /// Output file for ciphertext
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Decapsulate a shared secret
    Decaps {
        /// Path to the decapsulation (private) key file
        #[arg(short = 'k', long)]
        key: String,

        /// Path to the ciphertext file
        #[arg(short, long)]
        ciphertext: String,
    },

    /// Display information about supported algorithms
    Info,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { algorithm, output } => {
            println!("Generating {} key pair...", algorithm);
            if let Some(prefix) = output {
                println!("Output prefix: {}", prefix);
            }
            // TODO: Implement key generation
            eprintln!("Error: Key generation not yet implemented");
            std::process::exit(1);
        }

        Commands::Encaps { key, output } => {
            println!("Encapsulating with key: {}", key);
            if let Some(out) = output {
                println!("Output: {}", out);
            }
            // TODO: Implement encapsulation
            eprintln!("Error: Encapsulation not yet implemented");
            std::process::exit(1);
        }

        Commands::Decaps { key, ciphertext } => {
            println!("Decapsulating with key: {}", key);
            println!("Ciphertext: {}", ciphertext);
            // TODO: Implement decapsulation
            eprintln!("Error: Decapsulation not yet implemented");
            std::process::exit(1);
        }

        Commands::Info => {
            println!("Kylix - Post-Quantum Cryptography Library");
            println!();
            println!("Supported algorithms:");
            println!();
            println!("  ML-KEM (FIPS 203) - Key Encapsulation Mechanism");
            println!("    - ml-kem-512   Security Level 1 (128-bit)");
            println!("    - ml-kem-768   Security Level 3 (192-bit)");
            println!("    - ml-kem-1024  Security Level 5 (256-bit)");
            println!();
            println!("Future support planned:");
            println!("    - ML-DSA (FIPS 204) - Digital Signature Algorithm");
            println!("    - SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures");
        }
    }
}
