//! Benchmark functionality for Kylix CLI.
//!
//! This module is conditionally compiled with the `bench` feature.

use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use kylix_bench::{BenchmarkReport, BenchmarkResult};
use kylix_pqc::ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signer};
use kylix_pqc::ml_kem::{Kem, MlKem1024, MlKem512, MlKem768};
use kylix_pqc::slh_dsa::{
    SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
    SlhDsaShake256s,
};
use rand::rng;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::Algorithm;

// liboqs benchmark duration estimation constants
//
// These are assumed operations-per-second figures used only to convert a chosen
// iteration count into an *approximate* benchmark duration for liboqs KEM/SIG
// operations. They are intentionally coarse, order-of-magnitude estimates.
//
// Basis for the values:
// - On typical commodity x86_64 CPUs (e.g., recent laptop/desktop cores) with
//   reasonably optimized builds, liboqs KEM operations often reach on the order
//   of 10^4 operations per second.
// - Signature operations are generally more expensive than KEMs and, in practice,
//   often fall closer to the 10^3 operations-per-second range.
//
// The 10x difference between KEM and SIG here reflects this typical throughput
// gap observed in liboqs micro-benchmarks across a variety of algorithms. It is
// *not* a strict bound: depending on the specific scheme, CPU, and compiler
// flags, the actual ratio can be smaller or larger.
//
// Expected variance:
// - Real performance can vary by at least a small constant factor (e.g., 2–10x)
//   in either direction due to hardware differences, turbo behavior, thermal
//   limits, choice of algorithm/parameter set, and build configuration.
// - These constants should therefore be treated as rough defaults for user-facing
//   time estimation, not as precise measurements and not for security decisions.
const LIBOQS_KEM_OPS_PER_SEC: u64 = 10000;
const LIBOQS_SIG_OPS_PER_SEC: u64 = 1000;

/// Report output format for benchmarks.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Markdown table
    Markdown,
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
        filter
            .as_ref()
            .map_or(true, |f| f.iter().any(|s| s.eq_ignore_ascii_case(name)))
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
    // Try to find speed_kem in PATH first, then common locations
    let candidates: Vec<std::path::PathBuf> = {
        let mut paths = vec![];

        // Check LIBOQS_SPEED_KEM environment variable first
        if let Ok(p) = std::env::var("LIBOQS_SPEED_KEM") {
            paths.push(std::path::PathBuf::from(p));
        }

        // Check PATH
        if let Ok(p) = which::which("speed_kem") {
            paths.push(p);
        }

        // Windows: check common vcpkg build locations
        #[cfg(target_os = "windows")]
        {
            // Check VCPKG_ROOT environment variable first, then common paths
            let mut vcpkg_roots_to_check: Vec<std::path::PathBuf> = Vec::new();
            if let Ok(vcpkg_root) = std::env::var("VCPKG_ROOT") {
                vcpkg_roots_to_check.push(std::path::PathBuf::from(vcpkg_root));
            }
            vcpkg_roots_to_check.extend(
                ["C:\\vcpkg", "D:\\vcpkg", "E:\\vcpkg"]
                    .iter()
                    .map(std::path::PathBuf::from),
            );

            for root in vcpkg_roots_to_check {
                let base = root.join("buildtrees\\liboqs\\src");
                if let Ok(entries) = std::fs::read_dir(&base) {
                    for entry in entries.flatten() {
                        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            for build_type in ["x64-Release", "x64-Debug"] {
                                let speed_kem = entry
                                    .path()
                                    .join("out\\build")
                                    .join(build_type)
                                    .join("tests\\speed_kem.exe");
                                if speed_kem.exists() {
                                    paths.push(speed_kem);
                                }
                            }
                        }
                    }
                }
            }
        }

        paths
    };

    for path in candidates {
        if !path.exists() {
            continue;
        }

        // Get version by running with --help
        // Note: liboqs speed_kem outputs help to stderr
        let output = match Command::new(&path).arg("--help").output() {
            Ok(o) => o,
            Err(_) => continue,
        };
        // Check both stdout and stderr since liboqs outputs to stderr
        let stdout_text = String::from_utf8_lossy(&output.stdout);
        let stderr_text = String::from_utf8_lossy(&output.stderr);
        let help_text = format!("{}{}", stdout_text, stderr_text);

        // Extract version info if available
        // Note: liboqs speed_kem doesn't output version in --help, so we just mark as "detected"
        if help_text.contains("speed_kem") || help_text.contains("Usage") {
            return Some(ExternalTool {
                name: "liboqs".to_string(),
                path,
                version: "detected".to_string(),
            });
        }
    }

    None
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
        // Parse version to support future releases (3.8, 4.0, etc.)
        // Handles versions like "3.5.0", "3.6.0-alpha", etc.
        let is_supported_version = {
            /// Parses the leading numeric portion of a version component string.
            ///
            /// This handles version strings with suffixes like "5-alpha" or "0-beta1",
            /// extracting only the numeric prefix (e.g., "5-alpha" -> Some(5)).
            /// Returns None if the string doesn't start with a digit.
            fn parse_version_number(s: &str) -> Option<u64> {
                let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
                s[..end].parse::<u64>().ok()
            }

            let mut supported = false;
            let mut tokens = version_str.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == "OpenSSL" {
                    if let Some(ver_token) = tokens.next() {
                        let mut parts = ver_token.split('.');
                        let major = parts.next().and_then(parse_version_number);
                        let minor = parts.next().and_then(parse_version_number);
                        if let (Some(maj), Some(min)) = (major, minor) {
                            supported = maj > 3 || (maj == 3 && min >= 5);
                        }
                    }
                    break;
                }
            }
            supported
        };

        if is_supported_version {
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
///
/// Note: liboqs speed_kem uses `-d` flag for duration in seconds (default 3s).
/// The iterations parameter is converted to approximate duration.
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

    // Convert iterations to approximate duration (min 1s)
    let duration = std::cmp::max(1, iterations / LIBOQS_KEM_OPS_PER_SEC);

    // Run speed_kem with the algorithm (liboqs syntax: speed_kem [-d duration] <algorithm>)
    let output = Command::new(&tool.path)
        .args(["-d", &duration.to_string(), liboqs_algo])
        .output()
        .context("Failed to run liboqs speed_kem")?;

    // Check if the command succeeded; report failure if not
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "liboqs speed_kem failed for {}: {}",
            algo,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_liboqs_output(&stdout, &tool.name, algo)
}

/// Run liboqs signature benchmark
///
/// Note: liboqs speed_sig uses `-d` flag for duration in seconds (default 3s).
/// The iterations parameter is converted to approximate duration.
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
    // Use platform-appropriate executable name
    let speed_sig_name = if cfg!(windows) {
        "speed_sig.exe"
    } else {
        "speed_sig"
    };
    let speed_sig_path = tool.path.parent().map(|p| p.join(speed_sig_name));
    let speed_sig = speed_sig_path
        .filter(|p| p.exists())
        .or_else(|| which::which("speed_sig").ok());

    let Some(sig_path) = speed_sig else {
        return Ok(vec![]);
    };

    // Convert iterations to approximate duration (min 1s)
    let duration = std::cmp::max(1, iterations / LIBOQS_SIG_OPS_PER_SEC);

    // Run speed_sig with the algorithm (liboqs syntax: speed_sig [-d duration] <algorithm>)
    let output = Command::new(&sig_path)
        .args(["-d", &duration.to_string(), liboqs_algo])
        .output()
        .context("Failed to run liboqs speed_sig")?;

    // Check if the command succeeded; report failure if not
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "liboqs speed_sig failed for {}: {}",
            algo,
            stderr.trim()
        ));
    }

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

    // liboqs output format (pipe-delimited):
    // Operation                            | Iterations | Total time (s) | Time (us): mean | pop. stdev | ...
    // keygen                               |      21326 |          3.000 |         140.673 |    349.433 | ...
    // encaps                               |      18791 |          3.000 |         159.651 |    367.587 | ...
    // decaps                               |      15217 |          3.000 |         197.148 |    400.151 | ...

    for line in output.lines() {
        let line = line.trim();

        // Parse keygen/encaps/decaps/sign/verify lines
        for op in ["keygen", "encaps", "decaps", "sign", "verify"] {
            // Check if line starts with the operation name (no colon in new format)
            if line.starts_with(op) && line.contains('|') {
                // Split by pipe and extract mean time (4th column, index 3)
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 4 {
                    // Mean time is in the 4th column (index 3)
                    if let Ok(mean_us) = parts[3].trim().parse::<f64>() {
                        results.push(ExternalBenchResult {
                            tool_name: tool_name.to_string(),
                            algorithm: algo.to_string(),
                            operation: op.to_string(),
                            mean_us,
                        });
                        break; // Found this operation, move to next line
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Run an OpenSSL command and check its exit status
fn run_openssl_command(tool_path: &std::path::Path, args: &[&str]) -> Result<()> {
    let output = Command::new(tool_path)
        .args(args)
        .output()
        .context("Failed to execute OpenSSL command")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "OpenSSL command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
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

    // Use secure temporary directory to avoid symlink attacks
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let key_file = temp_dir.path().join("key.pem");
    let pub_file = temp_dir.path().join("pub.pem");
    let ct_file = temp_dir.path().join("ct.bin");
    let ss_file = temp_dir.path().join("ss.bin");

    let key_str = key_file.to_string_lossy();
    let pub_str = pub_file.to_string_lossy();
    let ct_str = ct_file.to_string_lossy();
    let ss_str = ss_file.to_string_lossy();

    // Benchmark keygen
    let start = Instant::now();
    for _ in 0..iterations {
        run_openssl_command(
            &tool.path,
            &["genpkey", "-algorithm", openssl_algo, "-out", &key_str],
        )?;
    }
    let keygen_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "keygen".to_string(),
        mean_us: keygen_total.as_micros() as f64 / iterations as f64,
    });

    // Generate a key for encaps/decaps benchmarks
    run_openssl_command(
        &tool.path,
        &["genpkey", "-algorithm", openssl_algo, "-out", &key_str],
    )?;

    // Extract public key
    run_openssl_command(
        &tool.path,
        &["pkey", "-in", &key_str, "-pubout", "-out", &pub_str],
    )?;

    // Benchmark encaps
    let start = Instant::now();
    for _ in 0..iterations {
        run_openssl_command(
            &tool.path,
            &[
                "pkeyutl", "-encap", "-inkey", &pub_str, "-pubin", "-out", &ct_str, "-secret",
                &ss_str,
            ],
        )?;
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
        run_openssl_command(
            &tool.path,
            &[
                "pkeyutl", "-decap", "-inkey", &key_str, "-in", &ct_str, "-secret", &ss_str,
            ],
        )?;
    }
    let decaps_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "decaps".to_string(),
        mean_us: decaps_total.as_micros() as f64 / iterations as f64,
    });

    // temp_dir is automatically cleaned up when dropped
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

    // Use secure temporary directory to avoid symlink attacks
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let key_file = temp_dir.path().join("key.pem");
    let pub_file = temp_dir.path().join("pub.pem");
    let msg_file = temp_dir.path().join("msg.txt");
    let sig_file = temp_dir.path().join("sig.bin");

    // Create test message
    fs::write(&msg_file, b"The quick brown fox jumps over the lazy dog")?;

    let key_str = key_file.to_string_lossy();
    let pub_str = pub_file.to_string_lossy();
    let msg_str = msg_file.to_string_lossy();
    let sig_str = sig_file.to_string_lossy();

    // Benchmark keygen
    let start = Instant::now();
    for _ in 0..iterations {
        run_openssl_command(
            &tool.path,
            &["genpkey", "-algorithm", openssl_algo, "-out", &key_str],
        )?;
    }
    let keygen_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "keygen".to_string(),
        mean_us: keygen_total.as_micros() as f64 / iterations as f64,
    });

    // Generate a key for sign/verify benchmarks
    run_openssl_command(
        &tool.path,
        &["genpkey", "-algorithm", openssl_algo, "-out", &key_str],
    )?;

    // Benchmark sign
    let start = Instant::now();
    for _ in 0..iterations {
        run_openssl_command(
            &tool.path,
            &[
                "pkeyutl", "-sign", "-inkey", &key_str, "-in", &msg_str, "-out", &sig_str,
            ],
        )?;
    }
    let sign_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "sign".to_string(),
        mean_us: sign_total.as_micros() as f64 / iterations as f64,
    });

    // Extract public key
    run_openssl_command(
        &tool.path,
        &["pkey", "-in", &key_str, "-pubout", "-out", &pub_str],
    )?;

    // Benchmark verify
    let start = Instant::now();
    for _ in 0..iterations {
        run_openssl_command(
            &tool.path,
            &[
                "pkeyutl", "-verify", "-inkey", &pub_str, "-pubin", "-in", &msg_str, "-sigfile",
                &sig_str,
            ],
        )?;
    }
    let verify_total = start.elapsed();
    results.push(ExternalBenchResult {
        tool_name: tool.name.clone(),
        algorithm: algo.to_string(),
        operation: "verify".to_string(),
        mean_us: verify_total.as_micros() as f64 / iterations as f64,
    });

    // temp_dir is automatically cleaned up when dropped
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

        match tool_results {
            Ok(r) => results.extend(r),
            Err(e) => eprintln!(
                "Warning: benchmark for tool '{}' on algorithm '{}' failed: {}",
                tool.name, algo, e
            ),
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
        by_algo.entry(r.algorithm.clone()).or_default().push((
            &r.tool_name,
            &r.operation,
            r.mean_us,
        ));
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

    // Add fairness note
    output.push_str("Note: OpenSSL benchmarks include process startup and file I/O overhead\n");
    output.push_str("      (each operation spawns a new process). liboqs uses its native\n");
    output.push_str("      speed_kem/speed_sig tools for fair in-process comparison.\n");
    output.push_str("      Kylix benchmarks run in-process with no I/O overhead.\n\n");

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
                        .filter(|kt| **kt > 0.0 && *time > 0.0)
                        .map(|kt| {
                            if *kt < *time {
                                // Kylix is faster (kt < time means Kylix took less time)
                                format!(" (Kylix {:.1}x faster)", time / kt)
                            } else if *kt > *time {
                                // Kylix is slower (kt > time means Kylix took more time)
                                format!(" (Kylix {:.1}x slower)", kt / time)
                            } else {
                                " (same speed as Kylix)".to_string()
                            }
                        })
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

    // Add fairness note
    output
        .push_str("> **Note:** OpenSSL benchmarks include process startup and file I/O overhead\n");
    output.push_str("> (each operation spawns a new process). liboqs uses its native\n");
    output.push_str("> `speed_kem`/`speed_sig` tools for fair in-process comparison.\n");
    output.push_str("> Kylix benchmarks run in-process with no I/O overhead.\n\n");

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
                "mean_us": r.mean.as_micros(),
                "notes": "in-process benchmark"
            })
        })
        .collect();

    let external: Vec<_> = external_results
        .iter()
        .map(|r| {
            let notes = if r.tool_name == "OpenSSL" {
                "includes process startup and file I/O overhead"
            } else {
                "in-process benchmark via native speed tool"
            };
            json!({
                "tool": r.tool_name,
                "algorithm": r.algorithm,
                "operation": r.operation,
                "mean_us": r.mean_us,
                "notes": notes
            })
        })
        .collect();

    let result = json!({
        "disclaimer": "OpenSSL benchmarks include process startup and file I/O overhead (each operation spawns a new process). liboqs uses its native speed_kem/speed_sig tools for fair in-process comparison. Kylix benchmarks run in-process with no I/O overhead.",
        "results": kylix.into_iter().chain(external).collect::<Vec<_>>()
    });
    serde_json::to_string_pretty(&result).expect(
        "Failed to serialize benchmark comparison JSON; data structure should be serializable",
    )
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
pub fn cmd_bench(
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
            eprintln!(
                "Warning: No external PQC tools detected. Comparison will show Kylix results only."
            );
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

            let ext_results =
                run_external_benchmarks(&external_tools, &algo_name, is_kem, iterations);
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
            ReportFormat::Json => serde_json::to_string_pretty(&report)
                .context("Failed to serialize report to JSON")?,
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
