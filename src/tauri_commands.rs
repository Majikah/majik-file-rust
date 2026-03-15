//! tauri_commands.rs
//!
//! Tauri command bindings for MajikFile.
//!
//! Drop these commands into your Tauri `src-tauri/src/main.rs`:
//!
//! ```rust
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
//! const mjkbBytes = await invoke<number[]>('cmd_encrypt_file', {
//!   data: Array.from(fileBytes),
//!   userId: 'user-uuid',
//!   identityFingerprint: fingerprint,
//!   identityPublicKey: publicKeyString,
//!   identityMlKemPublicKey: Array.from(mlKemPubKeyBytes),
//!   identityMlKemSecretKey: Array.from(mlKemSecKeyBytes),
//!   context: 'user_upload',
//!   isTemporary: false,
//! });
//! ```

use serde::{Deserialize, Serialize};

// This module is optional and intended for Tauri desktop apps only.
// Enable with `--features tauri` when building the library.
#[cfg(feature = "tauri")]
use serde as _serde_guard; // compile-time marker when feature enabled

use crate::core::crypto::generate_ml_kem_keypair;
use crate::core::types::{
    CreateOptions, FileContext, MajikFileIdentity, MajikFileRecipient, TempFileDuration,
};
use crate::core::utils::{format_bytes, infer_mime_type_from_filename, sha256_base64, sha256_hex};
use crate::majik_file::MajikFile;

// ─── Serialisable DTOs ────────────────────────────────────────────────────────

/// Passed from TypeScript → Rust for identity fields.
#[derive(Debug, Deserialize)]
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
            ml_kem_secret_key: p.ml_kem_secret_key,
        }
    }
}

/// Passed from TypeScript → Rust for a single recipient.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Serialize)]
pub struct KeypairResult {
    /// ML-KEM-768 public key (1184 bytes).
    pub public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub secret_key: Vec<u8>,
}

/// Compact file metadata returned to TypeScript after encryption.
#[derive(Debug, Serialize)]
pub struct EncryptResult {
    /// Encrypted .mjkb binary bytes — upload this to R2.
    pub mjkb_bytes: Vec<u8>,
    /// Supabase row metadata — insert this into the majik_files table.
    pub metadata: serde_json::Value,
}

/// DTO used by the Tauri invoke call for encryption to avoid many positional parameters.
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    pub data: Vec<u8>,
    pub user_id: String,
    pub identity: IdentityPayload,
    pub context: String,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub recipients: Vec<RecipientPayload>,
    #[serde(default)]
    pub is_temporary: bool,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub chat_message_id: Option<String>,
    #[serde(default)]
    pub thread_message_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub expires_at_days: Option<u8>,
    #[serde(default)]
    pub compression_level: Option<i32>,
    #[serde(default)]
    pub bypass_size_limit: bool,
}

/// Result returned to TypeScript after a successful `cmd_decrypt_file_with_metadata`.
#[derive(Debug, Serialize)]
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
    let (public_key, secret_key) = generate_ml_kem_keypair();
    KeypairResult {
        public_key,
        secret_key,
    }
}

/// Encrypt a file and return the .mjkb bytes + Supabase metadata.
#[tauri::command]
pub fn cmd_encrypt_file(req: EncryptRequest) -> Result<EncryptResult, String> {
    let ctx = parse_context(&req.context)?;
    let expires_at = parse_duration(req.expires_at_days);

    let options = CreateOptions {
        data: req.data,
        user_id: req.user_id,
        identity: req.identity.into(),
        context: ctx,
        original_name: req.original_name,
        mime_type: req.mime_type,
        recipients: req.recipients.into_iter().map(Into::into).collect(),
        is_temporary: req.is_temporary,
        is_shared: req.is_shared,
        conversation_id: req.conversation_id,
        chat_message_id: req.chat_message_id,
        thread_message_id: req.thread_message_id,
        thread_id: req.thread_id,
        expires_at,
        compression_level: req.compression_level,
        bypass_size_limit: req.bypass_size_limit,
        ..Default::default()
    };

    let file = MajikFile::create(options).map_err(|e| e.to_string())?;
    let mjkb_bytes = file.to_mjkb().map_err(|e| e.to_string())?;
    let json = file.to_json().map_err(|e| e.to_string())?;
    let metadata = serde_json::to_value(&json).map_err(|e| e.to_string())?;

    Ok(EncryptResult { mjkb_bytes, metadata })
}

/// Decrypt a .mjkb binary and return the plaintext bytes.
#[tauri::command]
pub fn cmd_decrypt_file(
    /// Raw .mjkb bytes fetched from R2.
    mjkb_bytes: Vec<u8>,
    fingerprint: String,
    ml_kem_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    MajikFile::decrypt(&mjkb_bytes, &fingerprint, &ml_kem_secret_key).map_err(|e| e.to_string())
}

/// Decrypt a .mjkb binary and return bytes + embedded filename + MIME type.
#[tauri::command]
pub fn cmd_decrypt_file_with_metadata(
    mjkb_bytes: Vec<u8>,
    fingerprint: String,
    ml_kem_secret_key: Vec<u8>,
) -> Result<DecryptWithMetadataResult, String> {
    let (bytes, original_name, mime_type) =
        MajikFile::decrypt_with_metadata(&mjkb_bytes, &fingerprint, &ml_kem_secret_key)
            .map_err(|e| e.to_string())?;

    Ok(DecryptWithMetadataResult {
        bytes,
        original_name,
        mime_type,
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

// ─── Internal helpers ────────────────────────────────────────────────────────

fn parse_context(s: &str) -> Result<FileContext, String> {
    match s {
        "user_upload" => Ok(FileContext::UserUpload),
        "chat_attachment" => Ok(FileContext::ChatAttachment),
        "chat_image" => Ok(FileContext::ChatImage),
        "thread_attachment" => Ok(FileContext::ThreadAttachment),
        other => Err(format!("Invalid context: \"{other}\"")),
    }
}

fn parse_duration(days: Option<u8>) -> TempFileDuration {
    match days {
        Some(1) => TempFileDuration::One,
        Some(2) => TempFileDuration::Two,
        Some(3) => TempFileDuration::Three,
        Some(5) => TempFileDuration::Five,
        Some(7) => TempFileDuration::Seven,
        _ => TempFileDuration::Fifteen,
    }
}
