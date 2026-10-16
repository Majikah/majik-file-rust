//! constants.rs — shared constants for the MajikFile crypto/binary format layer.
//! (R2 prefixes intentionally live in the MajikMessageFile layer, not here.)

// ─── AES-256-GCM ────────────────────────────────────────────────────────────
pub const AES_KEY_LEN: usize = 32;
pub const IV_LENGTH: usize = 12;

// ─── ML-KEM-768 (FIPS-203) ──────────────────────────────────────────────────
pub const ML_KEM_PK_LEN: usize = 1184;
/// 2400-byte *expanded* secret key — the `@noble/post-quantum` format.
pub const ML_KEM_SK_LEN: usize = 2400;
pub const ML_KEM_CT_LEN: usize = 1088;

// ─── File size limits ───────────────────────────────────────────────────────
pub const MAX_FILE_SIZE_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_GROUP_RECIPIENTS: usize = 32;

// ─── .mjkb binary format ────────────────────────────────────────────────────
/// v2 (current): explicit `z` compression flag, no embedded FileContext.
pub const MJKB_VERSION: u8 = 0x02;
/// v1 (legacy, read-only).
pub const MJKB_VERSION_LEGACY: u8 = 0x01;
pub const MJKB_SUPPORTED_VERSIONS: [u8; 2] = [MJKB_VERSION_LEGACY, MJKB_VERSION];

// ─── MJKS signed trailer: [.mjkb][sig JSON][u32 BE len]["MJKS"] ─────────────
pub const MJKS_MAGIC: [u8; 4] = [0x4d, 0x4a, 0x4b, 0x53];
pub const MJKS_MAGIC_LEN: usize = 4;
pub const MJKS_OVERHEAD: usize = 8;

// ─── JSON record schema version ─────────────────────────────────────────────
pub const FILE_SCHEMA_VERSION: u32 = 1;
pub const LEGACY_SCHEMA_VERSION: u32 = 0;

// ─── Crypto / compression suite metadata ────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct CryptoSuite {
    pub kem_alg: &'static str,
    pub cipher_alg: &'static str,
}
pub const CRYPTO_SUITE: CryptoSuite = CryptoSuite {
    kem_alg: "ML-KEM-768",
    cipher_alg: "AES-256-GCM",
};

#[derive(Debug, Clone, Copy)]
pub struct CompressionSuite {
    pub alg: &'static str,
}
/// Absent `ca` / `compression_alg` always means this.
pub const COMPRESSION_SUITE: CompressionSuite = CompressionSuite { alg: "zstd" };
