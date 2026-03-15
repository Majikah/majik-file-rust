//! majik_compressor.rs
//!
//! Zstd compression provider for MajikFile.
//! Uses the `zstd` crate — a safe Rust wrapper around the reference C library.
//!
//! Crate mapping: @bokuweb/zstd-wasm → zstd

use crate::core::constants::ZSTD_MAX_LEVEL;
use crate::core::error::MajikFileError;

// ─── Adaptive Level Thresholds ────────────────────────────────────────────────

struct AdaptiveThreshold {
    min_bytes: usize,
    max_level: i32,
}

/// Memory-safe level caps per input size — mirrors ADAPTIVE_THRESHOLDS in TypeScript.
const ADAPTIVE_THRESHOLDS: &[AdaptiveThreshold] = &[
    AdaptiveThreshold {
        min_bytes: 500 * 1024 * 1024,
        max_level: 6,
    },
    AdaptiveThreshold {
        min_bytes: 100 * 1024 * 1024,
        max_level: 12,
    },
    AdaptiveThreshold {
        min_bytes: 50 * 1024 * 1024,
        max_level: 16,
    },
    AdaptiveThreshold {
        min_bytes: 10 * 1024 * 1024,
        max_level: 19,
    },
];

// ─── Named presets ────────────────────────────────────────────────────────────

/// Named compression presets — mirrors `CompressionPreset` in TypeScript.
pub struct CompressionPreset;

impl CompressionPreset {
    pub const FASTEST: i32 = 2;
    pub const FAST: i32 = 3;
    pub const BALANCED: i32 = 6;
    pub const GOOD: i32 = 9;
    pub const BETTER: i32 = 15;
    pub const BEST: i32 = 19;
    pub const ULTRA: i32 = 22;
}

// ─── MajikCompressor ──────────────────────────────────────────────────────────

/// Zstd compression provider — mirrors `MajikCompressor` in TypeScript.
pub struct MajikCompressor;

impl MajikCompressor {
    // ── Level helpers ─────────────────────────────────────────────────────

    /// Clamp any integer to the valid Zstd level range [1, 22].
    pub fn clamp_level(level: i32) -> i32 {
        level.clamp(1, ZSTD_MAX_LEVEL)
    }

    /// Derive a safe Zstd compression level for the given input size.
    /// The requested `desired_level` is honoured unless it would exceed the
    /// memory-safe ceiling for the input size.
    ///
    /// Mirrors `adaptiveLevel()` in TypeScript.
    pub fn adaptive_level(data_len: usize, desired_level: i32) -> i32 {
        let clamped = Self::clamp_level(desired_level);
        for threshold in ADAPTIVE_THRESHOLDS {
            if data_len > threshold.min_bytes {
                return clamped.min(threshold.max_level);
            }
        }
        clamped // ≤ 10 MB — all levels are safe
    }

    // ── Compress / Decompress ─────────────────────────────────────────────

    /// Compress raw bytes using Zstd at the specified level.
    /// The level is always safety-clamped via `adaptive_level()`.
    ///
    /// Mirrors `compress()` in TypeScript.
    pub fn compress(data: &[u8], level: Option<i32>) -> Result<Vec<u8>, MajikFileError> {
        if data.is_empty() {
            return Err(MajikFileError::invalid_input(
                "MajikCompressor::compress: data must be non-empty",
            ));
        }
        let desired = level.unwrap_or(ZSTD_MAX_LEVEL);
        let safe_level = Self::adaptive_level(data.len(), desired);

        zstd::bulk::compress(data, safe_level)
            .map_err(|e| MajikFileError::compression_failed(Some(Box::new(e))))
    }

    /// Decompress Zstd-compressed bytes.
    ///
    /// Mirrors `decompress()` in TypeScript.
    pub fn decompress(data: &[u8]) -> Result<Vec<u8>, MajikFileError> {
        if data.is_empty() {
            return Err(MajikFileError::invalid_input(
                "MajikCompressor::decompress: data must be non-empty",
            ));
        }

        const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024 * 1024; // 50 GB

        // Use a generous upper-bound multiplier; zstd will error if exceeded.
        zstd::bulk::decompress(data, MAX_DECOMPRESSED_SIZE)
            .map_err(|e| MajikFileError::decompression_failed(Some(Box::new(e))))
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    /// Returns the compression ratio as a percentage size reduction.
    /// e.g. 100 bytes → 30 bytes = 70.0% reduction.
    ///
    /// Mirrors `compressionRatioPct()` in TypeScript.
    pub fn compression_ratio_pct(original_size: u64, compressed_size: u64) -> f64 {
        if original_size == 0 {
            return 0.0;
        }
        let reduction =
            (original_size as f64 - compressed_size as f64) / original_size as f64 * 100.0;
        let rounded = (reduction * 10.0).round() / 10.0;
        rounded.max(0.0)
    }
}
