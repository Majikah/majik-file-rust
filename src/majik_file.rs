//! majik_file.rs — `MajikFile`: post-quantum binary file encryption.
//! Platform-agnostic: knows nothing about chat, threads or storage backends.
//!
//! ## Extensibility (replaces TS subclassing)
//! Rust has no inheritance, so the TS protected static hooks become the
//! [`MajikFileHooks`] trait, and a `MajikMessageFile` is expected to *compose*
//! a `MajikFile` (`impl AsRef<MajikFile> / AsMut<MajikFile>`), calling
//! [`MajikFile::encrypt_core`] with its own hooks and [`MajikFile::from_parts`]
//! to build the base record. [`MajikFile::collect_errors`] is public so the
//! subclass can append its own errors and fail once.
//!
//! ## Signatures
//! `@majikah/majik-signature` has no Rust port yet, so signing goes through
//! the [`SignatureProvider`] trait; the file only stores the serialized
//! signature string.
//!
//! ## .mjkb v2
//! `[4 "MJKB"][1 ver][12 IV][4 len BE][payload JSON][AES-GCM ciphertext]`
//! with the explicit `z` compression flag and optional `ca` algorithm tag.

use std::any::Any;
use std::borrow::Cow;

use chrono::{SecondsFormat, Utc};

use crate::core::compressor::majik_compressor::{CompressionLevel, MajikCompressor, ZSTD_CODEC};
use crate::core::crypto::constants::*;
use crate::core::crypto::crypto_provider::{
    aes_gcm_decrypt, aes_gcm_encrypt, generate_random_bytes, ml_kem_encapsulate,
};
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::error::{MajikFileError, Result};
use crate::core::mjkb_codec::{decode_mjkb, encode_mjkb, resolve_aes_key_from_payload, MJKB_MAGIC};
use crate::core::types::*;
use crate::core::utils::*;
use crate::core::validator::MajikFileValidator;

/// MIME type used when exporting .mjkb bytes.
pub const MJKB_MIME_TYPE: &str = "application/vnd.majikah.bundle";

// ── Batch / core types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BatchDecryptError {
    pub id: String,
    pub reason: String,
}

/// Files are hydrated **in place**; `decrypted` lists their ids.
#[derive(Debug, Clone)]
pub struct BatchDecryptResult {
    pub success: bool,
    pub decrypted: Vec<String>,
    pub errors: Vec<BatchDecryptError>,
}

#[derive(Debug, Clone, Copy)]
pub struct BatchLockResult {
    pub locked: usize,
    /// Files with nothing hydrated.
    pub skipped: usize,
}

/// Internal shape returned by [`MajikFile::encrypt_core`].
#[derive(Debug, Clone)]
pub struct EncryptCoreResult {
    pub binary: Vec<u8>,
    pub iv_hex: String,
    pub file_hash: String,
    pub size_original: usize,
    pub size_stored: usize,
    pub resolved_mime_type: Option<String>,
    pub participants: Vec<MajikKeyAddress>,
    pub is_group: bool,
    /// Set only when compressed AND a non-default codec was used.
    pub compression_alg: Option<String>,
}

pub struct EncryptCoreInput<'a> {
    pub data: &'a [u8],
    pub identity: &'a MajikFileIdentity,
    pub recipients: &'a [MajikFileRecipient],
    pub original_name: Option<&'a str>,
    pub mime_type: Option<&'a str>,
    pub bypass_size_limit: bool,
    pub compression_level: Option<i32>,
    pub compressor: Option<&'a dyn CompressionCodec>,
    /// Opaque passthrough to `MajikFileHooks::pre_process` (base ignores it).
    pub pre_process_extra: Option<&'a dyn Any>,
}

pub struct PreProcessed<'a> {
    pub bytes: Cow<'a, [u8]>,
    pub mime_type: Option<String>,
}

/// Extension points a subclass-style wrapper may override.
pub trait MajikFileHooks {
    /// No-op by default.
    fn pre_process<'a>(
        &self,
        raw: &'a [u8],
        mime_type: Option<&str>,
        _extra: Option<&dyn Any>,
    ) -> Result<PreProcessed<'a>> {
        Ok(PreProcessed {
            bytes: Cow::Borrowed(raw),
            mime_type: mime_type.map(str::to_string),
        })
    }
    /// Mime-only policy by default.
    fn resolve_compression_policy(&self, mime_type: Option<&str>) -> bool {
        should_compress_mime(mime_type)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultHooks;
impl MajikFileHooks for DefaultHooks {}

/// Result of `decrypt_with_metadata`. `signature` is the stored serialized
/// signature (not verified; pass it to a [`SignatureProvider`]).
#[derive(Debug, Clone)]
pub struct DecryptedWithMetadata {
    pub bytes: Vec<u8>,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CanDecryptMjkbOptions {
    /// Force a full trial decrypt even on a group fingerprint match.
    pub strict: bool,
    pub compression: DecryptCompressionOptions,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().map(|v| v.trim().is_empty()).unwrap_or(true)
}

// ── MajikFile ──────────────────────────────────────────────────────────────

pub struct MajikFile {
    id: String,
    schema_version: u32,
    kind: String,
    user_id: String,
    original_name: Option<String>,
    mime_type: Option<String>,
    size_original: u64,
    size_stored: u64,
    file_hash: String,
    encryption_iv: String,
    participants: Vec<MajikKeyAddress>,
    kem_alg: String,
    cipher_alg: String,
    compression_level: Option<CompressionLevel>,
    compression_alg: Option<String>,
    timestamp: Option<String>,
    last_update: Option<String>,
    is_group: bool,
    signature: Option<String>,
    /// Encrypted .mjkb binary. NOT serialised via `to_json()`.
    binary: Option<Vec<u8>>,
    /// Runtime-only decrypted cache — wiped on drop / `secure_lock()`.
    decrypted: Option<Zeroizing<Vec<u8>>>,
}

impl AsRef<MajikFile> for MajikFile {
    fn as_ref(&self) -> &MajikFile {
        self
    }
}
impl AsMut<MajikFile> for MajikFile {
    fn as_mut(&mut self) -> &mut MajikFile {
        self
    }
}

impl std::fmt::Display for MajikFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MajikFile {{ id: {}, hash: {}…, size: {}, type: {}, signed: {} }}",
            self.id,
            self.file_hash.chars().take(8).collect::<String>(),
            format_bytes(self.size_original),
            if self.is_group { "group" } else { "single" },
            self.is_signed()
        )
    }
}

impl std::fmt::Debug for MajikFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MajikFile")
            .field("id", &self.id)
            .field("file_hash", &self.file_hash)
            .field("is_group", &self.is_group)
            .field("has_binary", &self.binary.is_some())
            .field("has_decrypted", &self.decrypted.is_some())
            .finish()
    }
}

impl MajikFile {
    // ── Construction ───────────────────────────────────────────────────────

    /// Build + validate from a record (used by `create`, `from_json`, and by
    /// wrapper types). TS: protected constructor + `validate()`.
    pub fn from_parts(
        json: MajikFileJson,
        binary: Option<Vec<u8>>,
        is_group: bool,
    ) -> Result<Self> {
        let f = Self {
            id: json.id,
            schema_version: json.schema_version,
            kind: json.kind,
            user_id: json.user_id,
            original_name: json.original_name,
            mime_type: json.mime_type,
            size_original: json.size_original,
            size_stored: json.size_stored,
            file_hash: json.file_hash,
            encryption_iv: json.encryption_iv,
            participants: json.participants,
            kem_alg: json.kem_alg,
            cipher_alg: json.cipher_alg,
            compression_level: json.compression_level,
            compression_alg: json.compression_alg,
            timestamp: json.timestamp,
            last_update: json.last_update,
            is_group,
            signature: json.signature,
            binary,
            decrypted: None,
        };
        f.validate()?;
        Ok(f)
    }

    // ── Getters ────────────────────────────────────────────────────────────

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn original_name(&self) -> Option<&str> {
        self.original_name.as_deref()
    }
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }
    pub fn size_original(&self) -> u64 {
        self.size_original
    }
    pub fn size_stored(&self) -> u64 {
        self.size_stored
    }
    pub fn file_hash(&self) -> &str {
        &self.file_hash
    }
    pub fn encryption_iv(&self) -> &str {
        &self.encryption_iv
    }
    pub fn kem_alg(&self) -> &str {
        &self.kem_alg
    }
    pub fn cipher_alg(&self) -> &str {
        &self.cipher_alg
    }
    pub fn participants(&self) -> &[MajikKeyAddress] {
        &self.participants
    }
    pub fn timestamp(&self) -> Option<&str> {
        self.timestamp.as_deref()
    }
    pub fn last_update(&self) -> Option<&str> {
        self.last_update.as_deref()
    }
    pub fn compression_alg(&self) -> Option<&str> {
        self.compression_alg.as_deref()
    }
    /// `None` when unset or 0 (TS: `level || null`).
    pub fn compression_level(&self) -> Option<CompressionLevel> {
        self.compression_level.filter(|l| *l != 0)
    }

    fn round3(v: f64) -> f64 {
        (v * 1000.0).round() / 1000.0
    }
    pub fn size_kb(&self) -> f64 {
        Self::round3(self.size_original as f64 / 1024.0)
    }
    pub fn size_mb(&self) -> f64 {
        Self::round3(self.size_original as f64 / 1024f64.powi(2))
    }
    pub fn size_gb(&self) -> f64 {
        Self::round3(self.size_original as f64 / 1024f64.powi(3))
    }
    pub fn size_tb(&self) -> f64 {
        Self::round3(self.size_original as f64 / 1024f64.powi(4))
    }

    pub fn has_binary(&self) -> bool {
        self.binary.is_some()
    }
    pub fn is_group(&self) -> bool {
        self.is_group
    }
    pub fn is_single(&self) -> bool {
        !self.is_group
    }
    pub fn has_decrypted_file(&self) -> bool {
        self.decrypted.is_some()
    }
    /// Cached plaintext, if `decrypt_hydrate()` ran this session.
    pub fn decrypted_file(&self) -> Option<&[u8]> {
        self.decrypted.as_ref().map(|d| d.as_slice())
    }

    /// Serialized base64 signature. `None` when unsigned.
    pub fn signature_raw(&self) -> Option<&str> {
        self.signature.as_deref()
    }
    /// Non-blank signature attached. Does NOT verify.
    pub fn is_signed(&self) -> bool {
        !blank(&self.signature)
    }

    pub fn is_inline_viewable(&self) -> bool {
        is_mime_type_inline_viewable(self.mime_type.as_deref())
    }
    pub fn safe_filename(&self) -> String {
        derive_filename(&self.file_hash, self.original_name.as_deref())
    }

    // ── Encrypt core (shared with wrapper types) ───────────────────────────

    /// hash → pre_process (hook) → compress (policy hook) → encrypt → encode.
    ///
    /// Zeroization: ML-KEM shared secrets and the random group AES key live
    /// in `Zeroizing` buffers and are wiped on drop, even on early error.
    pub fn encrypt_core(
        input: &EncryptCoreInput<'_>,
        hooks: &dyn MajikFileHooks,
    ) -> Result<EncryptCoreResult> {
        let raw = input.data;
        MajikFileValidator::assert_non_empty_data(raw.len())?;
        MajikFileValidator::assert_size_within_limit(
            raw.len(),
            MAX_FILE_SIZE_BYTES,
            input.bypass_size_limit,
        )?;
        if input.identity.fingerprint.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "identity.fingerprint is required",
            ));
        }
        MajikFileValidator::assert_ml_kem_public_key(
            Some(&input.identity.ml_kem_public_key),
            "identity.mlKemPublicKey",
        )?;
        for (i, r) in input.recipients.iter().enumerate() {
            if r.fingerprint.trim().is_empty() {
                return Err(MajikFileError::invalid_input(format!(
                    "recipients[{i}].fingerprint is required"
                )));
            }
            MajikFileValidator::assert_ml_kem_public_key(
                Some(&r.ml_kem_public_key),
                &format!("recipients[{i}].mlKemPublicKey"),
            )?;
        }

        // Hash the ORIGINAL bytes so dedup is stable regardless of preprocessing.
        let file_hash = sha256_hex(raw);

        let PreProcessed {
            bytes: processed,
            mime_type: resolved_mime,
        } = hooks.pre_process(raw, input.mime_type, input.pre_process_extra)?;

        let compress = hooks.resolve_compression_policy(resolved_mime.as_deref());
        let codec: &dyn CompressionCodec = input.compressor.unwrap_or(&ZSTD_CODEC);
        let compressed: Cow<[u8]> = if compress {
            Cow::Owned(codec.compress(&processed, input.compression_level)?)
        } else {
            processed
        };
        // Tag only non-default codecs → default output stays byte-identical to TS.
        let compression_alg = if compress && codec.alg() != COMPRESSION_SUITE.alg {
            Some(codec.alg().to_string())
        } else {
            None
        };

        let iv = generate_random_bytes(IV_LENGTH)?;
        let iv_hex = hex::encode(&iv);

        let cleaned = deduplicate_recipients(input.recipients, &input.identity.fingerprint);
        MajikFileValidator::assert_recipient_limit(cleaned.len(), MAX_GROUP_RECIPIENTS)?;

        let mut all: Vec<MajikFileRecipient> = Vec::with_capacity(cleaned.len() + 1);
        all.push(MajikFileRecipient {
            fingerprint: input.identity.fingerprint.clone(),
            ml_kem_public_key: input.identity.ml_kem_public_key.clone(),
            public_key: input.identity.public_key.clone(),
        });
        all.extend(cleaned);
        let participants: Vec<MajikKeyAddress> = all.iter().map(|r| r.public_key.clone()).collect();
        let is_group = all.len() > 1;

        let n = input.original_name.map(str::to_string);
        let m = resolved_mime.clone();

        let (ciphertext, payload) = if !is_group {
            let enc = ml_kem_encapsulate(&input.identity.ml_kem_public_key)?;
            let ct = aes_gcm_encrypt(&enc.shared_secret, &iv, &compressed)?;
            (
                ct,
                MjkbPayload::Single(MjkbSinglePayloadV2 {
                    ml_kem_cipher_text: array_to_base64(&enc.cipher_text),
                    n,
                    m,
                    z: compress,
                    ca: compression_alg.clone(),
                }),
            )
        } else {
            let aes_key = Zeroizing::new(generate_random_bytes(AES_KEY_LEN)?);
            let ct = aes_gcm_encrypt(&aes_key, &iv, &compressed)?;
            let mut keys = Vec::with_capacity(all.len());
            for r in &all {
                let enc = ml_kem_encapsulate(&r.ml_kem_public_key)?;
                let mut wrapped = [0u8; AES_KEY_LEN];
                for i in 0..AES_KEY_LEN {
                    wrapped[i] = aes_key[i] ^ enc.shared_secret[i];
                }
                keys.push(MajikFileGroupKey {
                    fingerprint: r.fingerprint.clone(),
                    ml_kem_cipher_text: array_to_base64(&enc.cipher_text),
                    encrypted_aes_key: array_to_base64(&wrapped),
                });
            }
            (
                ct,
                MjkbPayload::Group(MjkbGroupPayloadV2 {
                    keys,
                    n,
                    m,
                    z: compress,
                    ca: compression_alg.clone(),
                }),
            )
        };

        let binary = encode_mjkb(&iv, &payload, &ciphertext)?;
        Ok(EncryptCoreResult {
            size_stored: binary.len(),
            binary,
            iv_hex,
            file_hash,
            size_original: raw.len(),
            resolved_mime_type: resolved_mime,
            participants,
            is_group,
            compression_alg,
        })
    }

    // ── Create ─────────────────────────────────────────────────────────────

    pub fn create(options: MajikFileCreateOptions) -> Result<MajikFile> {
        MajikFileValidator::assert_user_id(Some(&options.user_id))?;

        let mime_type = options.mime_type.clone().or_else(|| {
            options
                .original_name
                .as_deref()
                .and_then(infer_mime_type_from_filename)
        });

        let core = Self::encrypt_core(
            &EncryptCoreInput {
                data: &options.data,
                identity: &options.identity,
                recipients: &options.recipients,
                original_name: options.original_name.as_deref(),
                mime_type: mime_type.as_deref(),
                bypass_size_limit: options.bypass_size_limit,
                compression_level: options.compression_level,
                compressor: options.compressor.as_deref(),
                pre_process_extra: None,
            },
            &DefaultHooks,
        )?;

        let now = now_iso();
        let json = MajikFileJson {
            id: options.id.unwrap_or_else(generate_uuid),
            schema_version: FILE_SCHEMA_VERSION,
            kind: FILE_KIND.to_string(),
            user_id: options.user_id,
            original_name: options.original_name,
            mime_type: core.resolved_mime_type,
            size_original: core.size_original as u64,
            size_stored: core.size_stored as u64,
            file_hash: core.file_hash,
            encryption_iv: core.iv_hex,
            participants: core.participants,
            kem_alg: CRYPTO_SUITE.kem_alg.to_string(),
            cipher_alg: CRYPTO_SUITE.cipher_alg.to_string(),
            compression_level: options.compression_level,
            compression_alg: core.compression_alg,
            timestamp: Some(now.clone()),
            last_update: Some(now),
            signature: None,
        };
        Self::from_parts(json, Some(core.binary), core.is_group)
    }

    pub fn create_and_sign<P: SignatureProvider>(
        options: MajikFileCreateOptions,
        provider: &P,
        key: &P::SigningKey,
        sign_options: &SignOptions,
    ) -> Result<MajikFile> {
        let mut file = Self::create(options)?;
        file.sign(provider, key, sign_options)?;
        Ok(file)
    }

    // ── Decrypt ────────────────────────────────────────────────────────────

    fn resolve_decompression_codec<'a>(
        alg: &str,
        options: &'a DecryptCompressionOptions,
    ) -> Result<&'a dyn CompressionCodec> {
        if alg == COMPRESSION_SUITE.alg {
            return Ok(&ZSTD_CODEC);
        }
        options
            .compressors
            .iter()
            .find(|c| c.alg() == alg)
            .map(|c| c.as_ref())
            .ok_or_else(|| MajikFileError::unsupported_compression_alg(alg))
    }

    /// Decode → recover AES key → authenticate+decrypt → decompress using `z`
    /// (v2) or the mime fallback (v1). Keys and the compressed intermediate
    /// are wiped on drop. ML-KEM never fails on a wrong key; AES-GCM auth does.
    fn decrypt_core(
        source: &[u8],
        identity: &MajikFileDecryptIdentity<'_>,
        options: &DecryptCompressionOptions,
    ) -> Result<(Vec<u8>, AnyMjkbPayload)> {
        MajikFileValidator::assert_ml_kem_secret_key(
            Some(identity.ml_kem_secret_key),
            "identity.mlKemSecretKey",
        )?;

        let raw = Self::strip_mjks_trailer(source);
        let decoded = decode_mjkb(raw)?;

        let aes_key = resolve_aes_key_from_payload(
            &decoded.payload,
            identity.fingerprint,
            identity.ml_kem_secret_key,
        )?;
        let decrypted =
            aes_gcm_decrypt(&aes_key, &decoded.iv, &decoded.ciphertext)?.ok_or_else(|| {
                MajikFileError::decryption_failed(
                    "Decryption failed — wrong key or corrupted .mjkb file",
                    None,
                )
            })?;
        drop(aes_key);

        let payload = decoded.payload;
        let should_decompress = payload
            .z()
            .unwrap_or_else(|| should_compress_mime(payload.m()));

        let bytes = if should_decompress {
            let alg = payload.ca().unwrap_or(COMPRESSION_SUITE.alg);
            let codec = Self::resolve_decompression_codec(alg, options)?;
            let compressed = Zeroizing::new(decrypted);
            codec.decompress(&compressed)? // `compressed` wiped when dropped
        } else {
            decrypted
        };
        Ok((bytes, payload))
    }

    pub fn decrypt<'a>(
        source: &[u8],
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<Vec<u8>> {
        let default = DecryptCompressionOptions::default();
        let (bytes, _) = Self::decrypt_core(source, &identity.into(), options.unwrap_or(&default))?;
        Ok(bytes)
    }

    /// Does NOT verify the signature — pass it to a [`SignatureProvider`].
    pub fn decrypt_with_metadata_from<'a>(
        source: &[u8],
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        signature_raw: Option<&str>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<DecryptedWithMetadata> {
        let default = DecryptCompressionOptions::default();
        let (bytes, payload) =
            Self::decrypt_core(source, &identity.into(), options.unwrap_or(&default))?;
        Ok(DecryptedWithMetadata {
            bytes,
            original_name: payload.n().map(str::to_string),
            mime_type: payload.m().map(str::to_string),
            signature: signature_raw
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string),
        })
    }

    pub fn decrypt_with_metadata<'a>(
        &self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<DecryptedWithMetadata> {
        let bin = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        Self::decrypt_with_metadata_from(bin, identity, self.signature.as_deref(), options)
    }

    pub fn decrypt_binary<'a>(
        &self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<Vec<u8>> {
        let bin = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        Self::decrypt(bin, identity, options)
    }

    /// Decrypt and cache plaintext on the instance (any old cache is wiped).
    pub fn decrypt_hydrate<'a>(
        &mut self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<&mut Self> {
        let bin = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        let default = DecryptCompressionOptions::default();
        let (bytes, _) = Self::decrypt_core(bin, &identity.into(), options.unwrap_or(&default))?;
        self.decrypted = Some(Zeroizing::new(bytes)); // old value dropped → wiped
        Ok(self)
    }

    /// Participant check by public key (falling back to fingerprint, as TS).
    pub fn can_decrypt(&self, identity: &MajikFileDecryptIdentity<'_>) -> bool {
        if let Some(pk) = identity.public_key.filter(|p| !p.is_empty()) {
            return self.participants.iter().any(|p| p == pk);
        }
        if !identity.fingerprint.is_empty() {
            return self.participants.iter().any(|p| p == identity.fingerprint);
        }
        false
    }

    // ── Batch ──────────────────────────────────────────────────────────────

    /// Hydrates each file in place; failures are collected, not fatal.
    /// (Sequential — pure-Rust crypto is CPU-bound; wrap in rayon if desired.)
    pub fn batch_decrypt<T: AsMut<MajikFile>>(
        files: &mut [T],
        identity: &MajikFileDecryptIdentity<'_>,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<BatchDecryptResult> {
        MajikFileValidator::assert_ml_kem_secret_key(
            Some(identity.ml_kem_secret_key),
            "identity.mlKemSecretKey",
        )?;
        let mut decrypted = Vec::new();
        let mut errors = Vec::new();
        for item in files.iter_mut() {
            let file = item.as_mut();
            let id = file.id.clone();
            if file.has_decrypted_file() {
                decrypted.push(id);
                continue;
            }
            if !file.can_decrypt(identity) {
                errors.push(BatchDecryptError {
                    id,
                    reason: format!(
                        "Key \"{}\" is not a participant of this file.",
                        identity.fingerprint
                    ),
                });
                continue;
            }
            match file.decrypt_hydrate(*identity, options) {
                Ok(_) => decrypted.push(id),
                Err(e) => errors.push(BatchDecryptError {
                    id,
                    reason: e.message.clone(),
                }),
            }
        }
        Ok(BatchDecryptResult {
            success: errors.is_empty(),
            decrypted,
            errors,
        })
    }

    pub fn batch_lock<T: AsMut<MajikFile>>(files: &mut [T]) -> BatchLockResult {
        let (mut locked, mut skipped) = (0, 0);
        for item in files.iter_mut() {
            let f = item.as_mut();
            if !f.has_decrypted_file() {
                skipped += 1;
                continue;
            }
            f.secure_lock();
            locked += 1;
        }
        BatchLockResult { locked, skipped }
    }

    /// Wipes and clears the decrypted cache.
    pub fn secure_lock(&mut self) -> &mut Self {
        self.decrypted = None; // Zeroizing wipes on drop
        self
    }

    // ── Serialisation ──────────────────────────────────────────────────────

    /// Metadata only — neither the binary nor the decrypted cache.
    pub fn to_json(&self) -> Result<MajikFileJson> {
        self.validate()?;
        Ok(MajikFileJson {
            id: self.id.clone(),
            schema_version: self.schema_version,
            kind: self.kind.clone(),
            user_id: self.user_id.clone(),
            original_name: self.original_name.clone(),
            mime_type: self.mime_type.clone(),
            size_original: self.size_original,
            size_stored: self.size_stored,
            file_hash: self.file_hash.clone(),
            encryption_iv: self.encryption_iv.clone(),
            participants: self.participants.clone(),
            kem_alg: self.kem_alg.clone(),
            cipher_alg: self.cipher_alg.clone(),
            compression_level: self.compression_level,
            compression_alg: self.compression_alg.clone(),
            timestamp: self.timestamp.clone(),
            last_update: self.last_update.clone(),
            signature: self.signature.clone(),
        })
    }

    /// ⚠️ Includes plaintext (base64). Never persist.
    pub fn to_dangerous_json(&self) -> Result<MajikFileDangerousJson> {
        Ok(MajikFileDangerousJson {
            json: self.to_json()?,
            decrypted_base64: self.decrypted.as_ref().map(|d| array_to_base64(d)),
        })
    }

    /// Peek at a binary's payload to detect group vs single mode.
    pub fn detect_is_group_from_binary(binary: Option<&[u8]>) -> bool {
        binary
            .and_then(|b| decode_mjkb(b).ok())
            .map(|d| d.payload.is_group())
            .unwrap_or(false)
    }

    pub fn from_json(json: MajikFileJson, binary: Option<Vec<u8>>) -> Result<MajikFile> {
        MajikFileValidator::assert_schema_version(json.schema_version, FILE_SCHEMA_VERSION)?;
        let is_group = Self::detect_is_group_from_binary(binary.as_deref());
        Self::from_parts(json, binary, is_group)
    }

    // ── .mjkb export ───────────────────────────────────────────────────────

    pub fn to_mjkb(&self) -> Result<&[u8]> {
        self.binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)
    }
    pub fn to_binary_bytes(&self) -> Result<&[u8]> {
        self.to_mjkb()
    }

    // ── MJKS trailer: [.mjkb][sig JSON][u32 BE len]["MJKS"] ────────────────

    pub fn has_mjks_trailer(data: &[u8]) -> bool {
        data.len() >= MJKS_OVERHEAD + 23 && data[data.len() - MJKS_MAGIC_LEN..] == MJKS_MAGIC
    }

    fn mjks_sig_len(data: &[u8]) -> usize {
        let o = data.len() - MJKS_OVERHEAD;
        u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as usize
    }

    /// Raw signature JSON from the trailer, if present and parseable.
    pub fn extract_mjks_signature_json(data: &[u8]) -> Option<serde_json::Value> {
        if !Self::has_mjks_trailer(data) {
            return None;
        }
        let sig_len = Self::mjks_sig_len(data);
        if sig_len == 0 || sig_len > data.len() - MJKS_OVERHEAD || sig_len > i32::MAX as usize {
            return None;
        }
        let start = data.len() - MJKS_OVERHEAD - sig_len;
        serde_json::from_slice(&data[start..start + sig_len]).ok()
    }

    /// Serialized signature from the trailer, via the provider.
    pub fn extract_mjks_signature<P: SignatureProvider>(
        data: &[u8],
        provider: &P,
    ) -> Option<String> {
        let json = Self::extract_mjks_signature_json(data)?;
        provider.from_json(&json).ok()
    }

    pub fn strip_mjks_trailer(data: &[u8]) -> &[u8] {
        if !Self::has_mjks_trailer(data) {
            return data;
        }
        let sig_len = Self::mjks_sig_len(data);
        match data.len().checked_sub(MJKS_OVERHEAD + sig_len) {
            Some(end) => &data[..end],
            None => data,
        }
    }

    /// .mjkb bytes + attached signature as an MJKS trailer (offline-verifiable).
    pub fn to_signed_mjkb<P: SignatureProvider>(&self, provider: &P) -> Result<Vec<u8>> {
        let binary = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        let sig = self
            .signature
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                MajikFileError::invalid_input(
                    "toSignedMJKB: no signature attached — call sign() or createAndSign() first",
                )
            })?;
        let sig_bytes = serde_json::to_vec(&provider.to_json(sig)?)
            .map_err(|e| MajikFileError::invalid_input(format!("toSignedMJKB: {e}")))?;

        let mut out = Vec::with_capacity(binary.len() + sig_bytes.len() + MJKS_OVERHEAD);
        out.extend_from_slice(binary);
        out.extend_from_slice(&sig_bytes);
        out.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&MJKS_MAGIC);
        Ok(out)
    }

    /// One-call verification of a signed .mjkb (verifies the *ciphertext*).
    pub fn verify_signed_mjkb<P: SignatureProvider>(
        source: &[u8],
        provider: &P,
        verifier: &P::Verifier,
    ) -> Result<P::Verification> {
        if !Self::has_mjks_trailer(source) {
            return Err(MajikFileError::invalid_input(
                "verifySignedMJKB: no MJKS trailer found — use toSignedMJKB() to export a signed file",
            ));
        }
        let sig = Self::extract_mjks_signature(source, provider).ok_or_else(|| {
            MajikFileError::invalid_input(
                "verifySignedMJKB: MJKS trailer present but signature could not be parsed",
            )
        })?;
        provider.verify(Self::strip_mjks_trailer(source), &sig, verifier)
    }

    // ── Validate ───────────────────────────────────────────────────────────

    /// Every base-level error, without throwing — public so wrappers can
    /// extend it and fail once.
    pub fn collect_errors(&self) -> Vec<String> {
        [
            MajikFileValidator::check_id(Some(&self.id)),
            MajikFileValidator::check_user_id(Some(&self.user_id)),
            MajikFileValidator::check_file_hash(Some(&self.file_hash)),
            MajikFileValidator::check_encryption_iv(Some(&self.encryption_iv)),
            MajikFileValidator::check_non_negative_size(self.size_original as f64, "size_original"),
            MajikFileValidator::check_non_negative_size(self.size_stored as f64, "size_stored"),
            MajikFileValidator::check_schema_version(self.schema_version, FILE_SCHEMA_VERSION),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn validate(&self) -> Result<()> {
        MajikFileValidator::assert_all(&self.collect_errors())
    }

    // ── Ownership / participants ───────────────────────────────────────────

    pub fn user_is_owner(&self, user_id: &str) -> bool {
        !user_id.trim().is_empty() && self.user_id == user_id
    }

    pub fn attach_binary(&mut self, binary: Vec<u8>) {
        self.binary = Some(binary);
    }
    pub fn clear_binary(&mut self) {
        self.binary = None;
    }

    pub fn has_participant_access(&self, public_key: &str) -> bool {
        !public_key.trim().is_empty() && self.participants.iter().any(|p| p == public_key)
    }

    /// True if SHA-256 (base64) of the public key equals `owner_fingerprint`.
    pub fn has_public_key_access(public_key: &[u8], owner_fingerprint: &str) -> Result<bool> {
        MajikFileValidator::assert_ml_kem_public_key(Some(public_key), "publicKey")?;
        if owner_fingerprint.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "hasPublicKeyAccess: ownerFingerprint is required",
            ));
        }
        Ok(sha256_base64(public_key) == owner_fingerprint)
    }

    // ── Size / stats / dupes ───────────────────────────────────────────────

    pub fn exceeds_size(&self, limit_mb: f64) -> Result<bool> {
        if !limit_mb.is_finite() || limit_mb <= 0.0 {
            return Err(MajikFileError::invalid_input(format!(
                "exceedsSize: limitMB must be a positive finite number (got {limit_mb})"
            )));
        }
        Ok(self.size_original as f64 > limit_mb * 1024.0 * 1024.0)
    }

    pub fn get_stats(&self) -> MajikFileStats {
        MajikFileStats {
            id: self.id.clone(),
            original_name: self.original_name.clone(),
            mime_type: self.mime_type.clone(),
            size_original_human: format_bytes(self.size_original),
            size_stored_human: format_bytes(self.size_stored),
            compression_ratio_pct: MajikCompressor::compression_ratio_pct(
                self.size_original as f64,
                self.size_stored as f64,
            ),
            file_hash: self.file_hash.clone(),
            is_group: self.is_group,
            is_signed: self.is_signed(),
        }
    }

    pub fn is_duplicate_of(&self, other: &MajikFile) -> bool {
        self.file_hash == other.file_hash
    }
    pub fn would_be_duplicate(raw: &[u8], existing_hash: &str) -> bool {
        sha256_hex(raw) == existing_hash
    }

    // ── Static helpers ─────────────────────────────────────────────────────

    pub fn is_mjkb_candidate(data: &[u8]) -> bool {
        data.len() >= 5 && data[..4] == MJKB_MAGIC
    }
    pub fn format_bytes(bytes: u64) -> String {
        format_bytes(bytes)
    }
    pub fn infer_mime_type(filename: &str) -> Option<String> {
        infer_mime_type_from_filename(filename)
    }
    pub fn get_raw_file_size(data: &[u8]) -> usize {
        data.len()
    }

    /// Structural validation beyond the magic-byte check. Does NOT decrypt.
    pub fn is_valid_mjkb(data: &[u8]) -> bool {
        if data.len() < 23 || data[..4] != MJKB_MAGIC {
            return false;
        }
        let o = 17; // 4 magic + 1 version + 12 IV
        let payload_len = u32::from_be_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        if payload_len == 0 || payload_len > i32::MAX as u32 {
            return false;
        }
        let start = o + 4;
        let Some(ct_start) = start.checked_add(payload_len as usize) else {
            return false;
        };
        if ct_start >= data.len() {
            return false;
        }
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&data[start..ct_start])
        else {
            return false;
        };
        let Some(obj) = payload.as_object() else {
            return false;
        };
        let is_single = obj.contains_key("mlKemCipherText") && !obj.contains_key("keys");
        let is_group = obj
            .get("keys")
            .and_then(|k| k.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        is_single || is_group
    }

    // ── Signing ────────────────────────────────────────────────────────────

    pub fn attach_signature<P: SignatureProvider>(
        &mut self,
        provider: &P,
        serialized: &str,
    ) -> Result<()> {
        if serialized.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "attachSignature: signature string must be non-empty",
            ));
        }
        provider.validate(serialized).map_err(|e| {
            MajikFileError::invalid_input(format!(
                "attachSignature: signature string is not a valid serialized MajikSignature — {}",
                e.message
            ))
        })?;
        self.signature = Some(serialized.to_string());
        self.last_update = Some(now_iso());
        Ok(())
    }

    pub fn remove_signature(&mut self) {
        if self.signature.is_none() {
            return;
        }
        self.signature = None;
        self.last_update = Some(now_iso());
    }

    /// Sign the loaded .mjkb binary (covers ciphertext — verifying never
    /// needs decryption). Replaces any existing signature.
    pub fn sign<P: SignatureProvider>(
        &mut self,
        provider: &P,
        key: &P::SigningKey,
        options: &SignOptions,
    ) -> Result<String> {
        let binary = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        let opts = SignOptions {
            content_type: options
                .content_type
                .clone()
                .or_else(|| self.mime_type.clone()),
            timestamp: options.timestamp.clone(),
        };
        let sig = provider.sign(binary, key, &opts)?;
        self.attach_signature(provider, &sig)?;
        Ok(sig)
    }

    /// `Ok(None)` if unsigned, binary not loaded, or the stored signature is corrupt.
    pub fn verify<P: SignatureProvider>(
        &self,
        provider: &P,
        verifier: &P::Verifier,
    ) -> Result<Option<P::Verification>> {
        let (Some(sig), Some(bin)) = (
            self.signature.as_deref().filter(|s| !s.trim().is_empty()),
            self.binary.as_deref(),
        ) else {
            return Ok(None);
        };
        if provider.validate(sig).is_err() {
            return Ok(None);
        }
        provider.verify(bin, sig, verifier).map(Some)
    }

    /// Decrypt (correctness gate) then verify the attached signature.
    pub fn verify_binary<'a, P: SignatureProvider>(
        &self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
        provider: &P,
        verifier: &P::Verifier,
        options: Option<&DecryptCompressionOptions>,
    ) -> Result<P::Verification> {
        let bin = self
            .binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)?;
        let sig = self
            .signature
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                MajikFileError::invalid_input("verifyBinary: this file has no attached signature")
            })?;
        provider.validate(sig).map_err(|e| {
            MajikFileError::invalid_input(format!(
                "verifyBinary: stored signature is corrupt — {}",
                e.message
            ))
        })?;
        Self::decrypt(bin, identity, options)?;
        provider.verify(bin, sig, verifier)
    }

    /// Envelope metadata for UI, without cryptographic verification.
    pub fn get_signature_info<P: SignatureProvider>(&self, provider: &P) -> Option<FileSignature> {
        let sig = self.signature.as_deref().filter(|s| !s.trim().is_empty())?;
        provider.info(sig).ok()
    }

    // ── canDecryptMJKB ─────────────────────────────────────────────────────

    /// Can this identity decrypt a raw .mjkb without instantiating a MajikFile?
    /// Group files: fingerprint fast-path unless `options.strict`. Single
    /// files (or strict): needs `ml_kem_secret_key` for a trial decrypt.
    pub fn can_decrypt_mjkb(
        source: &[u8],
        fingerprint: &str,
        ml_kem_secret_key: Option<&[u8]>,
        options: &CanDecryptMjkbOptions,
    ) -> bool {
        let raw = Self::strip_mjks_trailer(source);
        let Ok(decoded) = decode_mjkb(raw) else {
            return false;
        };

        if decoded.payload.is_group() {
            if !Self::group_has_fingerprint(&decoded.payload, fingerprint) {
                return false;
            }
            if !options.strict {
                return true;
            }
        }

        match ml_kem_secret_key {
            Some(sk) => Self::decrypt_core(
                raw,
                &MajikFileDecryptIdentity::new(fingerprint, sk),
                &options.compression,
            )
            .is_ok(),
            None => false,
        }
    }

    fn group_has_fingerprint(payload: &AnyMjkbPayload, fingerprint: &str) -> bool {
        use crate::core::types::{MjkbPayloadV1, MjkbPayloadV2};
        match payload {
            AnyMjkbPayload::V2(MjkbPayloadV2::Group(p)) => {
                p.keys.iter().any(|k| k.fingerprint == fingerprint)
            }
            AnyMjkbPayload::V1(MjkbPayloadV1::Group(p)) => {
                p.keys.iter().any(|k| k.fingerprint == fingerprint)
            }
            _ => false,
        }
    }
}
