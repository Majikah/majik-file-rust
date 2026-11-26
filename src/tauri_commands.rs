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
//! const { publicKey } = await invoke('cmd_generate_ml_kem_keypair');
//!
//! const { mjkbBytes, metadata } = await invoke('cmd_encrypt_file', {
//!   req: {
//!     data: Array.from(fileBytes),
//!     userId: 'user-uuid',
//!     identity: {
//!       publicKey: publicKeyString,
//!       fingerprint,
//!       mlKemPublicKey: Array.from(mlKemPubKeyBytes),
//!     },
//!   },
//! });
//! ```

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::core::crypto::crypto_provider::generate_ml_kem_keypair;
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::streaming::{
    decrypt_reader_to_writer, encrypt_reader_to_writer, StreamingOptions,
};
use crate::core::types::{
    MajikFileCreateOptions, MajikFileDecryptIdentity, MajikFileEncryptionIdentity,
    MajikFileRecipient,
};
use crate::core::utils::{format_bytes, generate_uuid, infer_mime_type_from_filename, sha256_base64, sha256_hex};
use crate::majik_file::MajikFile;

// ─── Serialisable DTOs ────────────────────────────────────────────────────────

/// Public identity material passed from TypeScript → Rust for encryption.
/// Decryption commands accept private key material separately.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionIdentityPayload {
    pub public_key: String,
    pub fingerprint: String,
    /// ML-KEM-768 public key as a byte array.
    pub ml_kem_public_key: Vec<u8>,
}

impl From<EncryptionIdentityPayload> for MajikFileEncryptionIdentity {
    fn from(p: EncryptionIdentityPayload) -> Self {
        MajikFileEncryptionIdentity {
            public_key: p.public_key,
            fingerprint: p.fingerprint,
            ml_kem_public_key: p.ml_kem_public_key,
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
    pub identity: EncryptionIdentityPayload,
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

/// Result of decrypting a file path. Legacy v1/v2 formats are decoded with
/// their existing one-shot AES-GCM implementation; v3 is streamed.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePathDecryptResult {
    pub format_version: u8,
    pub original_bytes: u64,
    pub file_hash: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub chunks: Option<u64>,
}

fn mjkb_content_len<R: Read + Seek>(reader: &mut R, file_len: u64) -> Result<u64, String> {
    if file_len < 8 {
        return Err("MJKB file is too short".to_string());
    }
    reader
        .seek(SeekFrom::End(-8))
        .map_err(|error| error.to_string())?;
    let mut footer = [0u8; 8];
    reader.read_exact(&mut footer).map_err(|error| error.to_string())?;
    if &footer[4..8] != b"MJKS" {
        return Ok(file_len);
    }

    let signature_len = u32::from_be_bytes(footer[0..4].try_into().unwrap()) as u64;
    let trailer_len = signature_len
        .checked_add(8)
        .ok_or_else(|| "MJKS trailer length overflow".to_string())?;
    let content_len = file_len
        .checked_sub(trailer_len)
        .filter(|length| *length >= 21)
        .ok_or_else(|| "Malformed MJKS signature trailer".to_string())?;
    if signature_len == 0 {
        return Err("Malformed MJKS signature trailer: empty signature".to_string());
    }
    Ok(content_len)
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


/// File-path streaming encryption request. File bytes stay in native Rust and
/// are never copied through Tauri IPC as a Vec<u8>.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingEncryptRequest {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub identity: EncryptionIdentityPayload,
    #[serde(default)]
    pub recipients: Vec<RecipientPayload>,
    #[serde(default)]
    pub original_name: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub compression: Option<bool>,
    #[serde(default)]
    pub compression_level: Option<i32>,
    #[serde(default)]
    pub chunk_size: Option<usize>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

/// File-path streaming decryption request. This command accepts MJKB v3;
/// the existing buffer commands continue to decode MJKB v1/v2.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingDecryptRequest {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub fingerprint: String,
    pub ml_kem_secret_key: Vec<u8>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

fn streaming_temp_path(output: &Path) -> Result<PathBuf, String> {
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Output path must include a valid filename".to_string())?;
    Ok(output.with_file_name(format!(".{file_name}.{}.partial", generate_uuid())))
}

/// Stream-encrypt a filesystem path into an MJKB v3 file. The output is first
/// written to a sibling temporary file and renamed into place after the final
/// authenticated manifest is complete.
#[tauri::command]
pub async fn cmd_encrypt_file_streaming(
    req: StreamingEncryptRequest,
) -> Result<crate::core::streaming::StreamingEncryptResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if req.output_path.exists() {
            return Err("Output file already exists".to_string());
        }
        let input = File::open(&req.input_path).map_err(|error| error.to_string())?;
        let total_bytes = input.metadata().map_err(|error| error.to_string())?.len();
        let mut reader = BufReader::new(input);
        let temp_path = streaming_temp_path(&req.output_path)?;
        let result = (|| {
            let output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| error.to_string())?;
            let mut writer = BufWriter::new(output);
            let mut options = StreamingOptions {
                chunk_size: req.chunk_size.unwrap_or(
                    crate::core::streaming::DEFAULT_STREAM_CHUNK_SIZE,
                ),
                compression: req.compression,
                compression_level: req.compression_level,
                total_bytes: Some(total_bytes),
                max_bytes: req.max_bytes,
                ..StreamingOptions::default()
            };
            let mime_type = req.mime_type.clone().or_else(|| {
                req.original_name
                    .as_deref()
                    .or_else(|| req.input_path.file_name().and_then(|name| name.to_str()))
                    .and_then(infer_mime_type_from_filename)
            });
            let identity: MajikFileEncryptionIdentity = req.identity.into();
            let recipients = req.recipients.into_iter().map(Into::into).collect::<Vec<_>>();
            let encrypted = encrypt_reader_to_writer(
                &mut reader,
                &mut writer,
                &identity,
                &recipients,
                req.original_name.as_deref().or_else(|| {
                    req.input_path.file_name().and_then(|name| name.to_str())
                }),
                mime_type.as_deref(),
                &mut options,
            )
            .map_err(|error| error.to_string())?;
            writer.flush().map_err(|error| error.to_string())?;
            writer.get_ref().sync_all().map_err(|error| error.to_string())?;
            drop(writer);
            fs::rename(&temp_path, &req.output_path).map_err(|error| error.to_string())?;
            Ok(encrypted)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Decrypt a file path with automatic MJKB version detection.
///
/// V3 is decrypted incrementally. V1/v2 retain their legacy whole-buffer
/// AES-GCM format and are passed through MajikFile's existing decoder.
#[tauri::command]
pub async fn cmd_decrypt_file_streaming(
    req: StreamingDecryptRequest,
) -> Result<FilePathDecryptResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if req.output_path.exists() {
            return Err("Output file already exists".to_string());
        }
        let input = File::open(&req.input_path).map_err(|error| error.to_string())?;
        let file_len = input.metadata().map_err(|error| error.to_string())?.len();
        let mut reader = BufReader::new(input);
        let mut prefix = [0u8; 5];
        reader.read_exact(&mut prefix).map_err(|error| {
            format!("Unable to read MJKB header: {error}")
        })?;
        if &prefix[..4] != b"MJKB" {
            return Err("Input does not have MJKB magic bytes".to_string());
        }
        let format_version = prefix[4];
        reader.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;

        let temp_path = streaming_temp_path(&req.output_path)?;
        let result = (|| {
            let output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| error.to_string())?;
            let mut writer = BufWriter::new(output);
            let secret = Zeroizing::new(req.ml_kem_secret_key);
            let identity = MajikFileDecryptIdentity::new(
                &req.fingerprint,
                secret.as_slice(),
            );

            let decrypted_result = match format_version {
                crate::core::crypto::constants::MJKB_VERSION_STREAMING => {
                    let body_len = mjkb_content_len(&mut reader, file_len)?;
                    reader.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
                    let mut limited_reader = reader.take(body_len);
                    let mut options = StreamingOptions {
                        max_bytes: req.max_bytes,
                        ..StreamingOptions::default()
                    };
                    let decrypted = decrypt_reader_to_writer(
                        &mut limited_reader,
                        &mut writer,
                        identity,
                        &mut options,
                    )
                    .map_err(|error| error.to_string())?;
                    FilePathDecryptResult {
                        format_version,
                        original_bytes: decrypted.original_bytes,
                        file_hash: decrypted.file_hash,
                        original_name: decrypted.original_name,
                        mime_type: decrypted.mime_type,
                        chunks: Some(decrypted.chunks),
                    }
                }
                crate::core::crypto::constants::MJKB_VERSION_LEGACY
                | crate::core::crypto::constants::MJKB_VERSION => {
                    reader.seek(SeekFrom::Start(0)).map_err(|error| error.to_string())?;
                    let mut encrypted = Vec::new();
                    reader.read_to_end(&mut encrypted).map_err(|error| error.to_string())?;
                    let decrypted = MajikFile::decrypt_with_metadata_from(
                        &encrypted,
                        identity,
                        None,
                        None,
                    )
                    .map_err(|error| error.to_string())?;
                    if req.max_bytes.is_some_and(|maximum| decrypted.bytes.len() as u64 > maximum) {
                        return Err("Decrypted output exceeds configured maximum".to_string());
                    }
                    writer
                        .write_all(&decrypted.bytes)
                        .map_err(|error| error.to_string())?;
                    FilePathDecryptResult {
                        format_version,
                        original_bytes: decrypted.bytes.len() as u64,
                        file_hash: sha256_hex(&decrypted.bytes),
                        original_name: decrypted.original_name,
                        mime_type: decrypted.mime_type,
                        chunks: None,
                    }
                }
                other => return Err(format!("Unsupported MJKB format version: {other}")),
            };

            writer.flush().map_err(|error| error.to_string())?;
            writer.get_ref().sync_all().map_err(|error| error.to_string())?;
            drop(writer);
            fs::rename(&temp_path, &req.output_path).map_err(|error| error.to_string())?;
            Ok(decrypted_result)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    })
    .await
    .map_err(|error| error.to_string())?
}
