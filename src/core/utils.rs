//! utils.rs — generic helpers for the base MajikFile (hashing, base64,
//! UUID, MIME policy, size formatting, recipient dedup).
//!
//! Intentionally omitted vs TS: `normaliseToUint8Array*` (Rust takes `&[u8]`
//! / `Vec<u8>` directly) and `convertImageToWebP` (browser-only; belongs in a
//! `MajikFileHooks::pre_process` implementation in the message-file layer).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::core::error::{MajikFileError, Result};
use crate::core::types::MajikFileRecipient;

// ─── Hashing ────────────────────────────────────────────────────────────────

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn sha256_base64(data: &[u8]) -> String {
    B64.encode(Sha256::digest(data))
}

pub fn generate_uuid() -> String {
    Uuid::new_v4().to_string()
}

// ─── Base64 ─────────────────────────────────────────────────────────────────

pub fn array_to_base64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn base64_to_array(b64: &str) -> Result<Vec<u8>> {
    B64.decode(b64).map_err(|e| {
        MajikFileError::invalid_input(format!("base64_to_array: invalid base64 — {e}"))
    })
}

// ─── Human-readable size ────────────────────────────────────────────────────

const SIZE_UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

pub fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut value = bytes as f64;
    let mut exp = 0usize;
    while value >= 1024.0 && exp < SIZE_UNITS.len() - 1 {
        value /= 1024.0;
        exp += 1;
    }
    let decimals = if exp == 0 { 0 } else { 2 };
    format!("{:.*} {}", decimals, value, SIZE_UNITS[exp])
}

// ─── MIME helpers ───────────────────────────────────────────────────────────

const INLINE_VIEWABLE_PREFIXES: [&str; 4] = ["image/", "video/", "audio/", "text/"];
const INLINE_VIEWABLE_EXACT: [&str; 2] = ["application/pdf", "application/json"];

pub fn is_mime_type_inline_viewable(mime: Option<&str>) -> bool {
    let Some(mime) = mime.filter(|m| !m.is_empty()) else {
        return false;
    };
    INLINE_VIEWABLE_EXACT.contains(&mime)
        || INLINE_VIEWABLE_PREFIXES.iter().any(|p| mime.starts_with(p))
}

fn ext_to_mime(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "zip" => "application/zip",
        _ => return None,
    })
}

/// Same table as the TS SDK so the MIME stamped into payloads is identical.
pub fn infer_mime_type_from_filename(filename: &str) -> Option<String> {
    let dot = filename.rfind('.')?;
    ext_to_mime(&filename[dot + 1..].to_lowercase()).map(str::to_string)
}

/// `<first 16 hash chars><.ext>`.
pub fn derive_filename(file_hash: &str, original_name: Option<&str>) -> String {
    let ext = original_name
        .and_then(|n| n.rfind('.').map(|d| &n[d..]))
        .unwrap_or("");
    let prefix: String = file_hash.chars().take(16).collect();
    format!("{prefix}{ext}")
}

const INCOMPRESSIBLE_MIME_PREFIXES: [&str; 2] = ["video/", "audio/"];
const INCOMPRESSIBLE_MIME_EXACT: [&str; 12] = [
    "image/jpeg",
    "image/webp",
    "image/avif",
    "image/gif",
    "image/heic",
    "image/heif",
    "application/zip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-zstd",
];

/// Mime-driven compression policy (also the fallback for legacy v1 binaries).
pub fn should_compress_mime(mime: Option<&str>) -> bool {
    let Some(mime) = mime.filter(|m| !m.is_empty()) else {
        return true;
    };
    if INCOMPRESSIBLE_MIME_EXACT.contains(&mime) {
        return false;
    }
    !INCOMPRESSIBLE_MIME_PREFIXES
        .iter()
        .any(|p| mime.starts_with(p))
}

// ─── Recipients ─────────────────────────────────────────────────────────────

/// Strip the owner's fingerprint and duplicates. Order-preserving, first wins.
pub fn deduplicate_recipients(
    recipients: &[MajikFileRecipient],
    owner_fingerprint: &str,
) -> Vec<MajikFileRecipient> {
    let mut seen = std::collections::HashSet::new();
    seen.insert(owner_fingerprint.to_string());
    recipients
        .iter()
        .filter(|r| seen.insert(r.fingerprint.clone()))
        .cloned()
        .collect()
}
