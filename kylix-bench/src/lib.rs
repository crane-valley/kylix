//! Kylix Benchmark Infrastructure
//!
//! This crate provides benchmarking utilities for measuring and comparing
//! the performance of Kylix's post-quantum cryptography implementations.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Benchmark result for a single operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Name of the algorithm (e.g., "ML-KEM-768")
    pub algorithm: String,
    /// Name of the operation (e.g., "keygen", "encaps", "decaps")
    pub operation: String,
    /// Number of iterations performed
    pub iterations: u64,
    /// Total time for all iterations
    pub total_time: Duration,
    /// Mean time per operation
    pub mean: Duration,
    /// Standard deviation
    pub std_dev: Duration,
    /// Throughput (operations per second)
    pub throughput: f64,
}

impl BenchmarkResult {
    /// Create a new benchmark result from raw timing data.
    pub fn new(
        algorithm: &str,
        operation: &str,
        iterations: u64,
        times: &[Duration],
    ) -> Self {
        let total_time: Duration = times.iter().sum();
        let mean_nanos = total_time.as_nanos() as f64 / iterations as f64;
        let mean = Duration::from_nanos(mean_nanos as u64);

        // Calculate standard deviation
        let variance = times
            .iter()
            .map(|t| {
                let diff = t.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / times.len() as f64;
        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        let throughput = iterations as f64 / total_time.as_secs_f64();

        Self {
            algorithm: algorithm.to_string(),
            operation: operation.to_string(),
            iterations,
            total_time,
            mean,
            std_dev,
            throughput,
        }
    }

    /// Format the result as a human-readable string.
    pub fn format(&self) -> String {
        format!(
            "{} {}: {:.2} µs/op ({:.0} ops/sec)",
            self.algorithm,
            self.operation,
            self.mean.as_nanos() as f64 / 1000.0,
            self.throughput
        )
    }
}

/// Collection of benchmark results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Library name and version
    pub library: String,
    /// Timestamp of the benchmark run
    pub timestamp: String,
    /// System information
    pub system: SystemInfo,
    /// Individual benchmark results
    pub results: Vec<BenchmarkResult>,
}

/// System information for benchmark context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system
    pub os: String,
    /// CPU architecture
    pub arch: String,
    /// Number of CPUs
    pub num_cpus: usize,
}

impl SystemInfo {
    /// Gather current system information.
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            num_cpus: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1),
        }
    }
}

impl BenchmarkReport {
    /// Create a new benchmark report.
    pub fn new(library: &str) -> Self {
        Self {
            library: library.to_string(),
            timestamp: chrono_lite_timestamp(),
            system: SystemInfo::current(),
            results: Vec::new(),
        }
    }

    /// Add a benchmark result.
    pub fn add_result(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    /// Save the report to a JSON file.
    pub fn save_json(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Generate a markdown report.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {} Benchmark Results\n\n", self.library));
        md.push_str(&format!("**Date:** {}\n\n", self.timestamp));
        md.push_str(&format!(
            "**System:** {} ({}, {} CPUs)\n\n",
            self.system.os, self.system.arch, self.system.num_cpus
        ));
        md.push_str("## Results\n\n");
        md.push_str("| Algorithm | Operation | Mean (µs) | Std Dev (µs) | Throughput (ops/sec) |\n");
        md.push_str("|-----------|-----------|-----------|--------------|----------------------|\n");

        for result in &self.results {
            md.push_str(&format!(
                "| {} | {} | {:.2} | {:.2} | {:.0} |\n",
                result.algorithm,
                result.operation,
                result.mean.as_nanos() as f64 / 1000.0,
                result.std_dev.as_nanos() as f64 / 1000.0,
                result.throughput
            ));
        }

        md
    }
}

/// Simple timestamp without external dependencies.
fn chrono_lite_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_creation() {
        let times: Vec<Duration> = (0..100)
            .map(|_| Duration::from_micros(50))
            .collect();
        let result = BenchmarkResult::new("ML-KEM-768", "keygen", 100, &times);

        assert_eq!(result.algorithm, "ML-KEM-768");
        assert_eq!(result.operation, "keygen");
        assert_eq!(result.iterations, 100);
        assert!(result.throughput > 0.0);
    }

    #[test]
    fn test_system_info() {
        let info = SystemInfo::current();
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
        assert!(info.num_cpus > 0);
    }

    #[test]
    fn test_report_markdown() {
        let mut report = BenchmarkReport::new("kylix-ml-kem");
        let times: Vec<Duration> = (0..10)
            .map(|_| Duration::from_micros(50))
            .collect();
        report.add_result(BenchmarkResult::new("ML-KEM-768", "keygen", 10, &times));

        let md = report.to_markdown();
        assert!(md.contains("ML-KEM-768"));
        assert!(md.contains("keygen"));
    }
}
