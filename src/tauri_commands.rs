//! tauri_commands.rs
//!
//! Tauri command bindings for MajikFile.
//!
//! Drop these commands into your Tauri `src-tauri/src/main.rs`:
//!
//! ```ignore
//! use majik_file::tauri_commands::*;
//!
//! fn main() {
//!     tauri::Builder::default()
//!         .invoke_handler(tauri::generate_handler![
//!             cmd_generate_ml_kem_keypair,
//!             cmd_encrypt_file,
//!             cmd_decrypt_file,
//!             cmd_decrypt_file_with_metadata,
//!             cmd_is_valid_mjkb,
//!             cmd_sha256_hex,
//!             cmd_sha256_base64,
//!             cmd_format_bytes,
//!             cmd_infer_mime_type,
//!         ])
//!         .run(tauri::generate_context!())
//!         .unwrap();
//! }
//! ```
//!
//! TypeScript frontend usage:
//! ```typescript
//! import { invoke } from '@tauri-apps/api/core';
//!
//! const { publicKey, secretKey } = await invoke('cmd_generate_ml_kem_keypair');
//!
//! const { mjkbBytes, metadata } = await invoke('cmd_encrypt_file', {
//!   req: {
//!     data: Array.from(fileBytes),
//!     userId: 'user-uuid',
//!     identity: {
//!       publicKey: publicKeyString,
//!       fingerprint,
//!       mlKemPublicKey: Array.from(mlKemPubKeyBytes),
//!       mlKemSecretKey: Array.from(mlKemSecKeyBytes),
//!     },
//!   },
//! });
//! ```

use serde::{Deserialize, Serialize};

use crate::core::crypto::crypto_provider::generate_ml_kem_keypair;
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::types::{
    MajikFileCreateOptions, MajikFileDecryptIdentity, MajikFileIdentity, MajikFileRecipient,
};
use crate::core::utils::{format_bytes, infer_mime_type_from_filename, sha256_base64, sha256_hex};
use crate::majik_file::MajikFile;

// ─── Serialisable DTOs ────────────────────────────────────────────────────────

/// Passed from TypeScript → Rust for identity fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPayload {
    pub public_key: String,
    pub fingerprint: String,
    /// ML-KEM-768 public key as a byte array.
    pub ml_kem_public_key: Vec<u8>,
    /// ML-KEM-768 secret key as a byte array.
    /// Only required for decryption commands.
    #[serde(default)]
    pub ml_kem_secret_key: Vec<u8>,
}

impl From<IdentityPayload> for MajikFileIdentity {
    fn from(p: IdentityPayload) -> Self {
        MajikFileIdentity {
            public_key: p.public_key,
            fingerprint: p.fingerprint,
            ml_kem_public_key: p.ml_kem_public_key,
            ml_kem_secret_key: Zeroizing::new(p.ml_kem_secret_key),
        }
    }
}

/// Passed from TypeScript → Rust for a single recipient.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientPayload {
    pub fingerprint: String,
    pub public_key: String,
    pub ml_kem_public_key: Vec<u8>,
}

impl From<RecipientPayload> for MajikFileRecipient {
    fn from(p: RecipientPayload) -> Self {
        MajikFileRecipient {
            fingerprint: p.fingerprint,
            public_key: p.public_key,
            ml_kem_public_key: p.ml_kem_public_key,
        }
    }
}

/// Result returned to TypeScript after a successful `cmd_generate_ml_kem_keypair`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeypairResult {
    /// ML-KEM-768 public key (1184 bytes).
    pub public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub secret_key: Vec<u8>,
}

/// Compact file metadata returned to TypeScript after encryption.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptResult {
    /// Encrypted .mjkb binary bytes — upload this to R2.
    pub mjkb_bytes: Vec<u8>,
    /// Supabase row metadata — insert this into the majik_files table.
    pub metadata: serde_json::Value,
}

/// DTO used by the Tauri invoke call for encryption to avoid many positional parameters.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptRequest {
    pub data: Vec<u8>,
    pub user_id: String,
    pub identity: IdentityPayload,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub recipients: Vec<RecipientPayload>,
    #[serde(default)]
    pub compression_level: Option<i32>,
    #[serde(default)]
    pub bypass_size_limit: bool,
}

/// Result returned to TypeScript after a successful `cmd_decrypt_file_with_metadata`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecryptWithMetadataResult {
    pub bytes: Vec<u8>,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair.
/// Intended for testing — production identities derive from a BIP-39 seed.
#[tauri::command]
pub fn cmd_generate_ml_kem_keypair() -> KeypairResult {
    let keypair = generate_ml_kem_keypair();
    KeypairResult {
        public_key: keypair.public_key,
        secret_key: keypair.secret_key.to_vec(),
    }
}

/// Encrypt a file and return the .mjkb bytes + Supabase metadata.
#[tauri::command]
pub fn cmd_encrypt_file(req: EncryptRequest) -> Result<EncryptResult, String> {
    let options = MajikFileCreateOptions {
        data: req.data,
        user_id: req.user_id,
        identity: req.identity.into(),
        recipients: req.recipients.into_iter().map(Into::into).collect(),
        original_name: req.original_name,
        mime_type: req.mime_type,
        id: None,
        compression_level: req.compression_level,
        bypass_size_limit: req.bypass_size_limit,
        compressor: None,
    };

    let file = MajikFile::create(options).map_err(|e| e.to_string())?;
    let mjkb_bytes = file.to_mjkb().map_err(|e| e.to_string())?.to_vec();
    let json = file.to_json().map_err(|e| e.to_string())?;
    let metadata = serde_json::to_value(&json).map_err(|e| e.to_string())?;

    Ok(EncryptResult {
        mjkb_bytes,
        metadata,
    })
}

/// Decrypt a .mjkb binary and return the plaintext bytes.
#[tauri::command]
pub fn cmd_decrypt_file(
    mjkb_bytes: Vec<u8>,
    fingerprint: String,
    ml_kem_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let ml_kem_secret_key = Zeroizing::new(ml_kem_secret_key);
    let identity = MajikFileDecryptIdentity::new(&fingerprint, ml_kem_secret_key.as_slice());
    MajikFile::decrypt(&mjkb_bytes, identity, None).map_err(|e| e.to_string())
}

/// Decrypt a .mjkb binary and return bytes + embedded filename + MIME type.
#[tauri::command]
pub fn cmd_decrypt_file_with_metadata(
    mjkb_bytes: Vec<u8>,
    fingerprint: String,
    ml_kem_secret_key: Vec<u8>,
) -> Result<DecryptWithMetadataResult, String> {
    let ml_kem_secret_key = Zeroizing::new(ml_kem_secret_key);
    let identity = MajikFileDecryptIdentity::new(&fingerprint, ml_kem_secret_key.as_slice());
    let decrypted = MajikFile::decrypt_with_metadata_from(&mjkb_bytes, identity, None, None)
        .map_err(|e| e.to_string())?;

    Ok(DecryptWithMetadataResult {
        bytes: decrypted.bytes,
        original_name: decrypted.original_name,
        mime_type: decrypted.mime_type,
    })
}

/// Quick structural check — returns true if the bytes look like a valid .mjkb file.
#[tauri::command]
pub fn cmd_is_valid_mjkb(data: Vec<u8>) -> bool {
    MajikFile::is_valid_mjkb(&data)
}

/// Compute SHA-256 hex digest of raw bytes.
#[tauri::command]
pub fn cmd_sha256_hex(data: Vec<u8>) -> String {
    sha256_hex(&data)
}

/// Compute SHA-256 base64 digest (used for ML-KEM key fingerprints).
#[tauri::command]
pub fn cmd_sha256_base64(data: Vec<u8>) -> String {
    sha256_base64(&data)
}

/// Format a byte count as a human-readable string (e.g. "4.2 MB").
#[tauri::command]
pub fn cmd_format_bytes(bytes: u64) -> String {
    format_bytes(bytes)
}

/// Infer a MIME type from a filename extension.
#[tauri::command]
pub fn cmd_infer_mime_type(filename: String) -> Option<String> {
    infer_mime_type_from_filename(&filename).map(|s| s.to_string())
}
