//! utils.rs
//!
//! Utility functions for MajikFile:
//!  - Base64 encode / decode
//!  - SHA-256 hashing
//!  - UUID generation
//!  - .mjkb binary encode / decode
//!  - R2 key construction
//!  - MIME type helpers
//!  - Human-readable file size formatting
//!  - Expiry helpers

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::core::constants::{
    extension_to_mime, incompressible_mime_types, inline_viewable_mime_types, R2Prefix,
    MAX_RECIPIENTS, MJKB_MAGIC, MJKB_VERSION,
};
use crate::core::error::MajikFileError;
use crate::core::types::{DecodedMjkb, MajikFileRecipient, MjkbPayload, TempFileDuration};

// ─── Base64 ───────────────────────────────────────────────────────────────────

/// Encode bytes to a standard base64 string.
/// Mirrors `arrayToBase64()` in TypeScript.
pub fn array_to_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Decode a standard base64 string to bytes.
/// Mirrors `base64ToUint8Array()` in TypeScript.
pub fn base64_to_bytes(s: &str) -> Result<Vec<u8>, MajikFileError> {
    BASE64.decode(s).map_err(|e| {
        MajikFileError::invalid_input(format!("base64_to_bytes: invalid base64 — {e}"))
    })
}

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

/// Synchronous SHA-256 digest → lowercase hex string (64 chars).
/// Mirrors `sha256Hex()` in TypeScript.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Synchronous SHA-256 digest → base64 string.
/// Used for ML-KEM public key fingerprints.
/// Mirrors `sha256Base64()` in TypeScript.
pub fn sha256_base64(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    BASE64.encode(hasher.finalize())
}

// ─── UUID ─────────────────────────────────────────────────────────────────────

/// Generate a random UUID v4.
/// Mirrors `generateUUID()` in TypeScript.
pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

// ─── Human-readable Size ──────────────────────────────────────────────────────

/// Format bytes as a human-readable string (e.g. "4.2 MB").
/// Mirrors `formatBytes()` in TypeScript.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    if bytes < 1024u64.pow(2) {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    if bytes < 1024u64.pow(3) {
        return format!("{:.1} MB", bytes as f64 / 1024.0f64.powi(2));
    }
    format!("{:.1} GB", bytes as f64 / 1024.0f64.powi(3))
}

// ─── R2 Key Construction ──────────────────────────────────────────────────────

/// Build an R2 object key for a permanent file.
///   files/user/<userId>/<fileHash>.mjkb
/// Mirrors `buildPermanentR2Key()` in TypeScript.
pub fn build_permanent_r2_key(user_id: &str, file_hash: &str) -> String {
    format!("{}/{}/{}.mjkb", R2Prefix::PERMANENT, user_id, file_hash)
}

/// Build an R2 object key for a temporary file.
///   files/public/<duration>/<userId>_<fileHash>.mjkb
/// Mirrors `buildTemporaryR2Key()` in TypeScript.
pub fn build_temporary_r2_key(
    user_id: &str,
    file_hash: &str,
    duration: TempFileDuration,
) -> String {
    format!(
        "{}/{}/{}_{}.mjkb",
        R2Prefix::TEMPORARY,
        duration.days(),
        user_id,
        file_hash
    )
}

/// Build an R2 object key for an encrypted WebP chat image.
///   images/chats/<conversationId>/<userId>_<fileHash>.mjkb
/// Mirrors `buildChatImageR2Key()` in TypeScript.
pub fn build_chat_image_r2_key(conversation_id: &str, user_id: &str, file_hash: &str) -> String {
    format!(
        "{}/{}/{}_{}.mjkb",
        R2Prefix::CHAT_IMAGE,
        conversation_id,
        user_id,
        file_hash
    )
}

// ─── MIME Type Helpers ────────────────────────────────────────────────────────

/// Returns true if the MIME type can be rendered inline in a browser.
/// Mirrors `isMimeTypeInlineViewable()` in TypeScript.
pub fn is_mime_type_inline_viewable(mime_type: Option<&str>) -> bool {
    let Some(mt) = mime_type else { return false };
    let normalised = mt.to_lowercase();
    let base = normalised.split(';').next().unwrap_or("").trim();
    inline_viewable_mime_types().contains(base)
}

/// Infer a MIME type from a filename extension.
/// Mirrors `inferMimeTypeFromFilename()` in TypeScript.
pub fn infer_mime_type_from_filename(filename: &str) -> Option<&'static str> {
    let dot = filename.rfind('.')?;
    let ext = &filename[dot + 1..];
    extension_to_mime(ext)
}

/// Derive a safe download filename from the file hash + original extension.
/// Mirrors `deriveFilename()` in TypeScript.
pub fn derive_filename(file_hash: &str, original_name: Option<&str>) -> String {
    let Some(name) = original_name else {
        return format!("{file_hash}.mjkb");
    };
    let Some(dot) = name.rfind('.') else {
        return format!("{file_hash}.mjkb");
    };
    let ext = name[dot..].to_lowercase();
    // Validate: dot + 1–10 alphanumeric chars
    let valid = ext.len() >= 2 && ext.len() <= 11 && ext[1..].chars().all(|c| c.is_alphanumeric());
    if valid {
        format!("{file_hash}{ext}")
    } else {
        format!("{file_hash}.mjkb")
    }
}

// ─── shouldCompress ───────────────────────────────────────────────────────────

/// Returns false for MIME types already compressed at the codec level.
/// Mirrors `shouldCompress()` in TypeScript.
pub fn should_compress(mime_type: Option<&str>) -> bool {
    let Some(mt) = mime_type else { return true };
    let normalised = mt.to_lowercase();
    let base = normalised
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    !incompressible_mime_types().contains(base.as_str())
}

// ─── .mjkb Binary Codec ───────────────────────────────────────────────────────
//
//  ┌────────────────────────────────────────────────────────────────────────────┐
//  │  4 bytes  │ Magic "MJKB"  (0x4D 0x4A 0x4B 0x42)                           │
//  │  1 byte   │ Version       (0x01)                                            │
//  │ 12 bytes  │ AES-GCM IV                                                      │
//  │  4 bytes  │ Payload JSON length  (big-endian uint32)                        │
//  │  N bytes  │ Payload JSON  (UTF-8; MjkbSinglePayload | MjkbGroupPayload)     │
//  │  M bytes  │ AES-GCM ciphertext   (Zstd-compressed plaintext + 16-byte tag) │
//  └────────────────────────────────────────────────────────────────────────────┘

const MJKB_FIXED_HEADER: usize = 4 + 1 + 12 + 4; // 21 bytes

/// Encode a .mjkb binary from its constituent parts.
/// Mirrors `encodeMjkb()` in TypeScript.
pub fn encode_mjkb(iv: &[u8], payload: &MjkbPayload, ciphertext: &[u8]) -> Vec<u8> {
    let payload_bytes = serde_json::to_vec(payload).expect("payload serialisation cannot fail");
    let payload_len = payload_bytes.len() as u32;

    let total = MJKB_FIXED_HEADER + payload_bytes.len() + ciphertext.len();
    let mut buf = Vec::with_capacity(total);

    // Magic
    buf.extend_from_slice(&MJKB_MAGIC);
    // Version
    buf.push(MJKB_VERSION);
    // IV (12 bytes)
    buf.extend_from_slice(iv);
    // Payload JSON length (big-endian uint32)
    buf.push((payload_len >> 24) as u8);
    buf.push((payload_len >> 16) as u8);
    buf.push((payload_len >> 8) as u8);
    buf.push(payload_len as u8);
    // Payload JSON
    buf.extend_from_slice(&payload_bytes);
    // Ciphertext
    buf.extend_from_slice(ciphertext);

    buf
}

/// Decode a raw .mjkb buffer into its constituent parts.
/// Mirrors `decodeMjkb()` in TypeScript.
pub fn decode_mjkb(raw: &[u8]) -> Result<DecodedMjkb, MajikFileError> {
    if raw.len() < MJKB_FIXED_HEADER + 2 {
        return Err(MajikFileError::format_error(format!(
            ".mjkb binary is too short ({} bytes) — minimum is {} bytes",
            raw.len(),
            MJKB_FIXED_HEADER + 2
        )));
    }

    // Magic check
    if raw[..4] != MJKB_MAGIC {
        return Err(MajikFileError::format_error(
            "Invalid .mjkb magic bytes — this is not a MajikFile binary",
        ));
    }

    let mut offset = 4usize;
    let version = raw[offset];
    offset += 1;

    if version != MJKB_VERSION {
        return Err(MajikFileError::unsupported_version(version, MJKB_VERSION));
    }

    // IV (12 bytes)
    let iv = raw[offset..offset + 12].to_vec();
    offset += 12;

    // Payload JSON length (big-endian uint32)
    let payload_len = u32::from_be_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]) as usize;
    offset += 4;

    if payload_len == 0 || raw.len() < offset + payload_len + 1 {
        return Err(MajikFileError::format_error(format!(
            ".mjkb binary is truncated — payload JSON declares {payload_len} bytes but insufficient data remains"
        )));
    }

    // Payload JSON
    let payload_json = &raw[offset..offset + payload_len];
    let payload: MjkbPayload = serde_json::from_slice(payload_json).map_err(|_| {
        MajikFileError::format_error(".mjkb payload JSON is malformed and could not be parsed")
    })?;
    offset += payload_len;

    // Ciphertext (remainder)
    let ciphertext = raw[offset..].to_vec();
    if ciphertext.is_empty() {
        return Err(MajikFileError::format_error(
            ".mjkb ciphertext section is empty",
        ));
    }

    Ok(DecodedMjkb {
        version,
        iv,
        payload,
        ciphertext,
    })
}

// ─── Expiry Helpers ───────────────────────────────────────────────────────────

/// Returns true if the given ISO-8601 timestamp is in the past.
/// Mirrors `isExpired()` in TypeScript.
pub fn is_expired(expires_at: Option<&str>) -> bool {
    let Some(ts) = expires_at else { return false };
    let Ok(dt) = ts.parse::<chrono::DateTime<Utc>>() else {
        return false;
    };
    dt < Utc::now()
}

/// Build a default expiry ISO string for temporary files.
/// Mirrors `buildExpiryDate()` in TypeScript.
pub fn build_expiry_date(days: TempFileDuration) -> String {
    let dt = Utc::now() + Duration::days(days.days());
    dt.to_rfc3339()
}

// ─── Recipient helpers ────────────────────────────────────────────────────────

/// Deduplicate a recipient list and strip the owner's own key.
/// Mirrors `deduplicateRecipients()` in TypeScript.
pub fn deduplicate_recipients(
    recipients: Vec<MajikFileRecipient>,
    owner_fingerprint: &str,
) -> Vec<MajikFileRecipient> {
    let mut seen = std::collections::HashSet::new();
    seen.insert(owner_fingerprint.to_string());
    let mut result = Vec::new();
    for r in recipients {
        if seen.contains(&r.fingerprint) {
            continue;
        }
        seen.insert(r.fingerprint.clone());
        result.push(r);
    }
    result
}

/// Assert that the recipient count does not exceed MAX_RECIPIENTS.
/// Mirrors `assertRecipientLimit()` in TypeScript.
pub fn assert_recipient_limit(recipients: &[MajikFileRecipient]) -> Result<(), MajikFileError> {
    if recipients.len() > MAX_RECIPIENTS {
        return Err(MajikFileError::invalid_input(format!(
            "Too many recipients: {} (maximum is {MAX_RECIPIENTS} excluding the owner). \
             Consider splitting into multiple files or threads.",
            recipients.len()
        )));
    }
    Ok(())
}
