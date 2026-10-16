//! types.rs — TS interfaces/types become structs/enums/traits.
//! Nothing here knows about chat, threads, R2 or other Majikah-specific
//! concepts (that belongs to MajikMessageFile).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::core::compressor::majik_compressor::CompressionLevel;
use crate::core::crypto::constants::{COMPRESSION_SUITE, CRYPTO_SUITE};
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::error::Result;

/// Base64 address of a Majik public key (`MajikKeyAddress`).
pub type MajikKeyAddress = String;
/// Base64 SHA-256 of the ML-KEM public key (`MajikKeyFingerprint`).
pub type MajikKeyFingerprint = String;

// ─── Compression codec (pluggable) ──────────────────────────────────────────

/// Pluggable compression. `alg` is stamped into payload `ca` / JSON
/// `compression_alg` and is the key used to find the codec again on decrypt.
pub trait CompressionCodec: Send + Sync {
    fn alg(&self) -> &str;
    fn compress(&self, bytes: &[u8], level: Option<i32>) -> Result<Vec<u8>>;
    fn decompress(&self, bytes: &[u8]) -> Result<Vec<u8>>;
}

/// Accepted by every decrypt-family method. Built-in zstd is always tried
/// first and needs no entry; `compressors` is only consulted for other `ca`s.
#[derive(Default, Clone)]
pub struct DecryptCompressionOptions {
    pub compressors: Vec<Arc<dyn CompressionCodec>>,
}

impl std::fmt::Debug for DecryptCompressionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptCompressionOptions")
            .field("compressor_count", &self.compressors.len())
            .finish()
    }
}

// ─── Signature provider (replaces @majikah/majik-signature) ─────────────────

#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<String>,
}

/// Envelope metadata of a signature (no cryptographic verification).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileSignature {
    pub signer_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub content_hash: String,
}

/// Abstraction over the signing library. MajikFile only stores the
/// *serialized* signature string (base64) and delegates everything
/// signature-specific to the provider.
pub trait SignatureProvider {
    /// Signing key (e.g. an unlocked MajikKey).
    type SigningKey;
    /// What verification needs (a key, or the signer's public keys).
    type Verifier;
    /// Verification outcome (e.g. `VerificationResult`).
    type Verification;

    /// Sign `data`, returning the serialized signature.
    fn sign(&self, data: &[u8], key: &Self::SigningKey, options: &SignOptions) -> Result<String>;
    fn verify(
        &self,
        data: &[u8],
        serialized: &str,
        verifier: &Self::Verifier,
    ) -> Result<Self::Verification>;
    /// Err if `serialized` is not a valid serialized signature.
    fn validate(&self, serialized: &str) -> Result<()>;
    fn info(&self, serialized: &str) -> Result<FileSignature>;
    /// Signature → JSON value (embedded in the MJKS trailer).
    fn to_json(&self, serialized: &str) -> Result<serde_json::Value>;
    /// JSON value (from the MJKS trailer) → serialized signature.
    #[allow(clippy::wrong_self_convention)]
    fn from_json(&self, json: &serde_json::Value) -> Result<String>;
}

// ─── Identities & recipients ────────────────────────────────────────────────

/// File owner's full identity. The secret key is wiped on drop.
#[derive(Clone)]
pub struct MajikFileIdentity {
    pub public_key: MajikKeyAddress,
    pub fingerprint: MajikKeyFingerprint,
    /// ML-KEM-768 public key (1184 bytes).
    pub ml_kem_public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub ml_kem_secret_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MajikFileIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MajikFileIdentity")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .field("ml_kem_secret_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct MajikFileRecipient {
    pub fingerprint: MajikKeyFingerprint,
    pub public_key: MajikKeyAddress,
    pub ml_kem_public_key: Vec<u8>,
}

/// Borrowed decrypt identity (`MajikFileDecryptIdentity`): no secret copy is
/// made and the caller keeps ownership of — and responsibility for wiping —
/// the secret key.
#[derive(Clone, Copy)]
pub struct MajikFileDecryptIdentity<'a> {
    pub fingerprint: &'a str,
    pub ml_kem_secret_key: &'a [u8],
    /// Optional; used by `can_decrypt()` participant checks.
    pub public_key: Option<&'a str>,
}

impl<'a> MajikFileDecryptIdentity<'a> {
    pub fn new(fingerprint: &'a str, ml_kem_secret_key: &'a [u8]) -> Self {
        Self {
            fingerprint,
            ml_kem_secret_key,
            public_key: None,
        }
    }
    pub fn with_public_key(mut self, public_key: &'a str) -> Self {
        self.public_key = Some(public_key);
        self
    }
}

impl<'a> From<&'a MajikFileIdentity> for MajikFileDecryptIdentity<'a> {
    fn from(i: &'a MajikFileIdentity) -> Self {
        Self {
            fingerprint: &i.fingerprint,
            ml_kem_secret_key: &i.ml_kem_secret_key,
            public_key: Some(&i.public_key),
        }
    }
}

// ─── Per-recipient key entry (group .mjkb) ──────────────────────────────────

/// `encrypted_aes_key = group_aes_key XOR ml_kem_shared_secret` (32 bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MajikFileGroupKey {
    pub fingerprint: MajikKeyFingerprint,
    /// Base64 ML-KEM-768 ciphertext (1088 bytes).
    pub ml_kem_cipher_text: String,
    /// Base64 32-byte wrapped AES key.
    pub encrypted_aes_key: String,
}

// ─── .mjkb payloads ─────────────────────────────────────────────────────────

/// v1 (legacy, read-only): `c` embedded a FileContext; decompression was inferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MjkbSinglePayloadV1 {
    pub ml_kem_cipher_text: String,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub m: Option<String>,
    #[serde(default)]
    pub c: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MjkbGroupPayloadV1 {
    pub keys: Vec<MajikFileGroupKey>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub m: Option<String>,
    #[serde(default)]
    pub c: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MjkbPayloadV1 {
    Group(MjkbGroupPayloadV1),
    Single(MjkbSinglePayloadV1),
}

/// v2 (current). Field order matters: it matches TS `JSON.stringify` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MjkbSinglePayloadV2 {
    pub ml_kem_cipher_text: String,
    pub n: Option<String>,
    pub m: Option<String>,
    /// True if the plaintext was compressed before encryption.
    pub z: bool,
    /// Compression algorithm; absent means "zstd". Only meaningful when `z`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MjkbGroupPayloadV2 {
    pub keys: Vec<MajikFileGroupKey>,
    pub n: Option<String>,
    pub m: Option<String>,
    pub z: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MjkbPayloadV2 {
    Group(MjkbGroupPayloadV2),
    Single(MjkbSinglePayloadV2),
}

/// "Current" payload — what `encode_mjkb()` always writes.
pub type MjkbPayload = MjkbPayloadV2;

/// Any payload `decode_mjkb()` may return (V2 is tried first: it requires `z`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnyMjkbPayload {
    V2(MjkbPayloadV2),
    V1(MjkbPayloadV1),
}

impl AnyMjkbPayload {
    pub fn is_group(&self) -> bool {
        matches!(
            self,
            Self::V2(MjkbPayloadV2::Group(_)) | Self::V1(MjkbPayloadV1::Group(_))
        )
    }
    pub fn is_single(&self) -> bool {
        !self.is_group()
    }
    /// Original filename (`n`).
    pub fn n(&self) -> Option<&str> {
        match self {
            Self::V2(MjkbPayloadV2::Group(p)) => p.n.as_deref(),
            Self::V2(MjkbPayloadV2::Single(p)) => p.n.as_deref(),
            Self::V1(MjkbPayloadV1::Group(p)) => p.n.as_deref(),
            Self::V1(MjkbPayloadV1::Single(p)) => p.n.as_deref(),
        }
    }
    /// MIME type (`m`).
    pub fn m(&self) -> Option<&str> {
        match self {
            Self::V2(MjkbPayloadV2::Group(p)) => p.m.as_deref(),
            Self::V2(MjkbPayloadV2::Single(p)) => p.m.as_deref(),
            Self::V1(MjkbPayloadV1::Group(p)) => p.m.as_deref(),
            Self::V1(MjkbPayloadV1::Single(p)) => p.m.as_deref(),
        }
    }
    /// Explicit compression flag; `None` for v1 payloads.
    pub fn z(&self) -> Option<bool> {
        match self {
            Self::V2(MjkbPayloadV2::Group(p)) => Some(p.z),
            Self::V2(MjkbPayloadV2::Single(p)) => Some(p.z),
            Self::V1(_) => None,
        }
    }
    /// Compression algorithm tag; `None` means zstd.
    pub fn ca(&self) -> Option<&str> {
        match self {
            Self::V2(MjkbPayloadV2::Group(p)) => p.ca.as_deref(),
            Self::V2(MjkbPayloadV2::Single(p)) => p.ca.as_deref(),
            Self::V1(_) => None,
        }
    }
}

/// Fully parsed .mjkb binary.
#[derive(Debug, Clone)]
pub struct DecodedMjkb {
    pub version: u8,
    /// Authoritative IV from the binary header.
    pub iv: Vec<u8>,
    /// AES-GCM ciphertext (+16-byte tag).
    pub ciphertext: Vec<u8>,
    pub payload: AnyMjkbPayload,
}

// ─── Record schema ──────────────────────────────────────────────────────────

/// `kind` stamped on base records (subclasses use their own literal).
pub const FILE_KIND: &str = "file";

/// Serialised MajikFile. The encrypted binary is intentionally excluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MajikFileJson {
    pub id: String,
    /// Absent on legacy rows → deserializes to 0 (`LEGACY_SCHEMA_VERSION`).
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub kind: String,
    pub user_id: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_original: u64,
    pub size_stored: u64,
    /// SHA-256 hex of the original bytes (dedup key).
    pub file_hash: String,
    /// Hex 12-byte IV (audit only; the binary header is authoritative).
    pub encryption_iv: String,
    pub participants: Vec<MajikKeyAddress>,
    pub kem_alg: String,
    pub cipher_alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_level: Option<CompressionLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_alg: Option<String>,
    pub timestamp: Option<String>,
    pub last_update: Option<String>,
    /// base64 serialized signature.
    #[serde(default)]
    pub signature: Option<String>,
}

pub const DEFAULT_KEM_ALG: &str = CRYPTO_SUITE.kem_alg;
pub const DEFAULT_CIPHER_ALG: &str = CRYPTO_SUITE.cipher_alg;
pub const DEFAULT_COMPRESSION_ALG: &str = COMPRESSION_SUITE.alg;

/// `toDangerousJSON()` shape — includes plaintext. Never persist.
#[derive(Debug, Clone, Serialize)]
pub struct MajikFileDangerousJson {
    #[serde(flatten)]
    pub json: MajikFileJson,
    pub decrypted_base64: Option<String>,
}

// ─── CreateOptions ──────────────────────────────────────────────────────────

pub struct MajikFileCreateOptions {
    pub data: Vec<u8>,
    pub user_id: String,
    pub identity: MajikFileIdentity,
    /// Additional recipients; non-empty → group .mjkb.
    pub recipients: Vec<MajikFileRecipient>,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub id: Option<String>,
    pub bypass_size_limit: bool,
    pub compression_level: Option<CompressionLevel>,
    /// Custom codec replacing built-in zstd for this encryption.
    pub compressor: Option<Arc<dyn CompressionCodec>>,
}

impl MajikFileCreateOptions {
    pub fn new(data: Vec<u8>, user_id: impl Into<String>, identity: MajikFileIdentity) -> Self {
        Self {
            data,
            user_id: user_id.into(),
            identity,
            recipients: Vec::new(),
            original_name: None,
            mime_type: None,
            id: None,
            bypass_size_limit: false,
            compression_level: None,
            compressor: None,
        }
    }
}

// ─── Stats ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikFileStats {
    pub id: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_original_human: String,
    pub size_stored_human: String,
    pub compression_ratio_pct: f64,
    pub file_hash: String,
    pub is_group: bool,
    pub is_signed: bool,
}
