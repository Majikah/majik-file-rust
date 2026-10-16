//! mjkb_codec.rs — encode/decode of the .mjkb binary plus AES key recovery.
//! The only module that understands the byte layout:
//! `[4 "MJKB"][1 version][12 IV][4 payload len BE][payload JSON][ciphertext]`.
//! It does not decide compression policy (that is `_decryptCore`'s job).

use crate::core::crypto::constants::{
    AES_KEY_LEN, IV_LENGTH, MJKB_SUPPORTED_VERSIONS, MJKB_VERSION,
};
use crate::core::crypto::crypto_provider::ml_kem_decapsulate;
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::error::{MajikFileError, Result};
use crate::core::types::{AnyMjkbPayload, DecodedMjkb, MjkbPayload};
use crate::core::utils::base64_to_array;

pub const MJKB_MAGIC: [u8; 4] = [0x4d, 0x4a, 0x4b, 0x42]; // "MJKB"

/// magic + version + IV + payload-length field (21 bytes).
pub const MJKB_HEADER_LEN: usize = 4 + 1 + IV_LENGTH + 4;

pub fn is_mjkb_group_payload(p: &AnyMjkbPayload) -> bool {
    p.is_group()
}
pub fn is_mjkb_single_payload(p: &AnyMjkbPayload) -> bool {
    p.is_single()
}
/// True if this is a v2 payload (explicit `z` flag).
pub fn has_compression_flag(p: &AnyMjkbPayload) -> bool {
    p.z().is_some()
}
/// True if the payload carries an explicit compression algorithm tag.
pub fn has_compression_alg(p: &AnyMjkbPayload) -> bool {
    p.ca().is_some()
}

// ─── Encode ─────────────────────────────────────────────────────────────────

/// Always writes the current `MJKB_VERSION` (v1 is read-only).
pub fn encode_mjkb(iv: &[u8], payload: &MjkbPayload, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != IV_LENGTH {
        return Err(MajikFileError::invalid_input(format!(
            "encodeMjkb: iv must be {IV_LENGTH} bytes (got {})",
            iv.len()
        )));
    }
    let payload_json = serde_json::to_vec(payload)
        .map_err(|e| MajikFileError::encryption_failed(Some(Box::new(e))))?;
    let len = u32::try_from(payload_json.len())
        .map_err(|_| MajikFileError::format_error("payload too large"))?;

    let mut out = Vec::with_capacity(MJKB_HEADER_LEN + payload_json.len() + ciphertext.len());
    out.extend_from_slice(&MJKB_MAGIC);
    out.push(MJKB_VERSION);
    out.extend_from_slice(iv);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload_json);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

// ─── Decode ─────────────────────────────────────────────────────────────────

pub fn decode_mjkb(raw: &[u8]) -> Result<DecodedMjkb> {
    // +2 == at least 1 byte of payload JSON + 1 byte of ciphertext
    if raw.len() < MJKB_HEADER_LEN + 2 {
        return Err(MajikFileError::format_error(
            "Malformed .mjkb: too short to contain a valid header",
        ));
    }
    if raw[..4] != MJKB_MAGIC {
        return Err(MajikFileError::format_error(
            "Malformed .mjkb: missing \"MJKB\" magic bytes",
        ));
    }
    let version = raw[4];
    if !MJKB_SUPPORTED_VERSIONS.contains(&version) {
        return Err(MajikFileError::unsupported_version(version, MJKB_VERSION));
    }
    let iv = raw[5..5 + IV_LENGTH].to_vec();

    let len_off = 5 + IV_LENGTH;
    let payload_len = u32::from_be_bytes([
        raw[len_off],
        raw[len_off + 1],
        raw[len_off + 2],
        raw[len_off + 3],
    ]);
    // The TS reader treats the length as a signed int32: 0 and ≥2^31 are invalid.
    if payload_len == 0 || payload_len > i32::MAX as u32 {
        return Err(MajikFileError::format_error(
            "Malformed .mjkb: invalid payload length",
        ));
    }

    let payload_start = len_off + 4;
    let ct_start = payload_start
        .checked_add(payload_len as usize)
        .filter(|&e| e <= raw.len())
        .ok_or_else(|| {
            MajikFileError::format_error("Malformed .mjkb: declared payload length exceeds buffer")
        })?;

    let payload: AnyMjkbPayload =
        serde_json::from_slice(&raw[payload_start..ct_start]).map_err(|_| {
            MajikFileError::format_error("Malformed .mjkb: payload JSON failed to parse")
        })?;

    let ciphertext = raw[ct_start..].to_vec();
    if ciphertext.is_empty() {
        return Err(MajikFileError::format_error(
            "Malformed .mjkb: empty ciphertext section",
        ));
    }
    Ok(DecodedMjkb {
        version,
        iv,
        ciphertext,
        payload,
    })
}

// ─── AES key recovery ───────────────────────────────────────────────────────

/// Single: the shared secret *is* the AES key. Group: XOR-unwrap this
/// recipient's key entry. The intermediate shared secret is wiped on drop.
pub fn resolve_aes_key_from_payload(
    payload: &AnyMjkbPayload,
    fingerprint: &str,
    ml_kem_secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use crate::core::types::{MjkbPayloadV1, MjkbPayloadV2};

    let (single_ct, group_keys) = match payload {
        AnyMjkbPayload::V2(MjkbPayloadV2::Single(p)) => (Some(&p.ml_kem_cipher_text), None),
        AnyMjkbPayload::V1(MjkbPayloadV1::Single(p)) => (Some(&p.ml_kem_cipher_text), None),
        AnyMjkbPayload::V2(MjkbPayloadV2::Group(p)) => (None, Some(&p.keys)),
        AnyMjkbPayload::V1(MjkbPayloadV1::Group(p)) => (None, Some(&p.keys)),
    };

    if let Some(ct_b64) = single_ct {
        return ml_kem_decapsulate(&base64_to_array(ct_b64)?, ml_kem_secret_key);
    }

    let keys = group_keys.ok_or_else(|| {
        MajikFileError::format_error(
            "Malformed .mjkb payload: neither single- nor group-recipient shape recognised",
        )
    })?;
    let entry = keys.iter().find(|k| k.fingerprint == fingerprint).ok_or_else(|| {
        MajikFileError::decryption_failed(
            format!("No key entry found for fingerprint \"{fingerprint}\" — this identity is not a participant of this file"),
            None,
        )
    })?;
    let ct = base64_to_array(&entry.ml_kem_cipher_text)?;
    let wrapped = base64_to_array(&entry.encrypted_aes_key)?;
    if wrapped.len() != AES_KEY_LEN {
        return Err(MajikFileError::format_error(
            "Malformed .mjkb payload: encryptedAesKey must be 32 bytes",
        ));
    }
    let shared = ml_kem_decapsulate(&ct, ml_kem_secret_key)?;
    let mut aes_key = Zeroizing::new(vec![0u8; AES_KEY_LEN]);
    for i in 0..AES_KEY_LEN {
        aes_key[i] = wrapped[i] ^ shared[i];
    }
    Ok(aes_key)
}
