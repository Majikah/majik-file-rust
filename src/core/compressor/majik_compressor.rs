//! majik_compressor.rs
//!
//! Pure-Rust Zstd provider (`structured-zstd`, levels 1–22, no FFI / WASM).
//! Replaces `@bokuweb/zstd-wasm`; no async init step is needed.

use std::io::Read;

use structured_zstd::decoding::StreamingDecoder;
use structured_zstd::encoding::{compress_slice_to_vec, CompressionLevel as ZLevel};

use crate::core::crypto::constants::COMPRESSION_SUITE;
use crate::core::error::{MajikFileError, Result};
use crate::core::types::CompressionCodec;

/// Maximum Zstd compression level (highest ratio, slowest).
pub const ZSTD_MAX_LEVEL: i32 = 22;

/// Explicit integer Zstd level, 1–22 (clamped by [`MajikCompressor::clamp_level`]).
pub type CompressionLevel = i32;

/// Named presets → concrete Zstd levels.
pub struct CompressionPreset;
impl CompressionPreset {
    pub const FASTEST: CompressionLevel = 2;
    pub const FAST: CompressionLevel = 3;
    pub const BALANCED: CompressionLevel = 6;
    pub const GOOD: CompressionLevel = 9;
    pub const BETTER: CompressionLevel = 15;
    pub const BEST: CompressionLevel = 19;
    pub const ULTRA: CompressionLevel = 22;
}

/// Memory-safe level caps by input size, largest first (identical to TS).
const ADAPTIVE_THRESHOLDS: [(usize, CompressionLevel); 4] = [
    (500 * 1024 * 1024, 6),
    (100 * 1024 * 1024, 12),
    (50 * 1024 * 1024, 16),
    (10 * 1024 * 1024, 19),
];

pub struct MajikCompressor;

impl MajikCompressor {
    pub fn clamp_level(level: i32) -> CompressionLevel {
        level.clamp(1, ZSTD_MAX_LEVEL)
    }

    pub fn raw_byte_size(data: &[u8]) -> usize {
        data.len()
    }

    /// Requested level is honoured unless it exceeds the safe ceiling for
    /// the input size; it is never raised.
    pub fn adaptive_level(data: &[u8], desired_level: i32) -> CompressionLevel {
        let size = Self::raw_byte_size(data);
        let clamped = Self::clamp_level(desired_level);
        for (min_bytes, max_level) in ADAPTIVE_THRESHOLDS {
            if size > min_bytes {
                return clamped.min(max_level);
            }
        }
        clamped
    }

    pub fn compress(data: &[u8], level: Option<i32>) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(MajikFileError::invalid_input(
                "MajikCompressor.compress: data must be a non-empty byte slice",
            ));
        }
        let safe = Self::adaptive_level(data, level.unwrap_or(ZSTD_MAX_LEVEL));
        Ok(compress_slice_to_vec(data, ZLevel::from_level(safe)))
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(MajikFileError::invalid_input(
                "MajikCompressor.decompress: data must be a non-empty byte slice",
            ));
        }
        let mut decoder = StreamingDecoder::new(data);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .map_err(|e| MajikFileError::decompression_failed(Some(Box::new(e))))?;
        Ok(out)
    }

    /// Percentage size reduction, one decimal, clamped at 0.
    pub fn compression_ratio_pct(original_size: f64, compressed_size: f64) -> f64 {
        if original_size <= 0.0 {
            return 0.0;
        }
        let reduction = (original_size - compressed_size) / original_size * 100.0;
        ((reduction * 10.0).round() / 10.0).max(0.0)
    }
}

/// Built-in zstd codec — the implicit default for encrypt/decrypt.
pub struct ZstdCodec;

pub const ZSTD_CODEC: ZstdCodec = ZstdCodec;

impl CompressionCodec for ZstdCodec {
    fn alg(&self) -> &str {
        COMPRESSION_SUITE.alg
    }
    fn compress(&self, bytes: &[u8], level: Option<i32>) -> Result<Vec<u8>> {
        MajikCompressor::compress(bytes, level)
    }
    fn decompress(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        MajikCompressor::decompress(bytes)
    }
}
