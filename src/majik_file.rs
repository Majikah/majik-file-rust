//! majik_file.rs
//!
//! Post-quantum binary file encryption for Majik Message.
//! Complete 1:1 port of the TypeScript MajikFile class.
//!
//! Single-recipient:
//!   ML-KEM encapsulate → sharedSecret → AES-256-GCM key.
//!
//! Group (2+ recipients):
//!   Random 32-byte AES key encrypts file once.
//!   Per recipient: ML-KEM encapsulate → encryptedAesKey = aesKey XOR sharedSecret.

use crate::core::compressor::MajikCompressor;
use crate::core::constants::{
    R2Prefix, AES_KEY_LEN, IV_LENGTH, MAX_FILE_SIZE_BYTES, MJKB_MAGIC, ML_KEM_PK_LEN, ML_KEM_SK_LEN,
};
use crate::core::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, generate_random_bytes, ml_kem_decapsulate, ml_kem_encapsulate,
};
use crate::core::error::MajikFileError;
use crate::core::types::{
    CreateOptions, FileContext, MajikFileGroupKey, MajikFileIdentity, MajikFileJson,
    MajikFileRecipient, MajikFileStats, MajikMessagePublicKey, MjkbGroupPayload, MjkbPayload,
    MjkbSinglePayload, StorageType, TempFileDuration,
};
use crate::core::utils::{
    array_to_base64, assert_recipient_limit, base64_to_bytes, build_chat_image_r2_key,
    build_expiry_date, build_permanent_r2_key, build_temporary_r2_key, decode_mjkb,
    deduplicate_recipients, derive_filename, encode_mjkb, format_bytes, generate_uuid,
    infer_mime_type_from_filename, is_expired, is_mime_type_inline_viewable, sha256_base64,
    sha256_hex, should_compress,
};

// ─── MajikFile ────────────────────────────────────────────────────────────────

/// Post-quantum binary file encryption — Rust port of the TypeScript MajikFile class.
pub struct MajikFile {
    id: String,
    user_id: String,
    r2_key: String,
    original_name: Option<String>,
    mime_type: Option<String>,
    size_original: u64,
    size_stored: u64,
    file_hash: String,
    /// Hex-encoded 12-byte IV — mirrors Supabase `encryption_iv` column.
    encryption_iv: String,
    storage_type: StorageType,
    is_shared: bool,
    share_token: Option<String>,
    context: Option<FileContext>,
    chat_message_id: Option<String>,
    thread_message_id: Option<String>,
    thread_id: Option<String>,
    conversation_id: Option<String>,
    participants: Vec<MajikMessagePublicKey>,
    expires_at: Option<String>,
    timestamp: Option<String>,
    last_update: Option<String>,
    /// Derived from payload type at create/parse time.
    is_group: bool,
    /// Encrypted .mjkb binary. NOT in JSON / Supabase — lives in R2 only.
    binary: Option<Vec<u8>>,
}

impl MajikFile {
    // ── Internal constructor ─────────────────────────────────────────────────

    fn from_parts(json: MajikFileJson, binary: Option<Vec<u8>>, is_group: bool) -> Self {
        Self {
            id: json.id,
            user_id: json.user_id,
            r2_key: json.r2_key,
            original_name: json.original_name,
            mime_type: json.mime_type,
            size_original: json.size_original,
            size_stored: json.size_stored,
            file_hash: json.file_hash,
            encryption_iv: json.encryption_iv,
            storage_type: json.storage_type,
            is_shared: json.is_shared,
            share_token: json.share_token,
            context: json.context,
            chat_message_id: json.chat_message_id,
            thread_message_id: json.thread_message_id,
            thread_id: json.thread_id,
            conversation_id: json.conversation_id,
            participants: json.participants,
            expires_at: json.expires_at,
            timestamp: json.timestamp,
            last_update: json.last_update,
            is_group,
            binary,
        }
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
    pub fn r2_key(&self) -> &str {
        &self.r2_key
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
    pub fn storage_type(&self) -> &StorageType {
        &self.storage_type
    }
    pub fn is_shared(&self) -> bool {
        self.is_shared
    }
    pub fn share_token(&self) -> Option<&str> {
        self.share_token.as_deref()
    }
    pub fn context(&self) -> Option<&FileContext> {
        self.context.as_ref()
    }
    pub fn chat_message_id(&self) -> Option<&str> {
        self.chat_message_id.as_deref()
    }
    pub fn thread_message_id(&self) -> Option<&str> {
        self.thread_message_id.as_deref()
    }
    pub fn thread_id(&self) -> Option<&str> {
        self.thread_id.as_deref()
    }
    pub fn conversation_id(&self) -> Option<&str> {
        self.conversation_id.as_deref()
    }
    pub fn participants(&self) -> &[MajikMessagePublicKey] {
        &self.participants
    }
    pub fn expires_at(&self) -> Option<&str> {
        self.expires_at.as_deref()
    }
    pub fn timestamp(&self) -> Option<&str> {
        self.timestamp.as_deref()
    }
    pub fn last_update(&self) -> Option<&str> {
        self.last_update.as_deref()
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

    /// Original file size in kilobytes (3 decimal places).
    pub fn size_kb(&self) -> f64 {
        (self.size_original as f64 / 1024.0 * 1000.0).round() / 1000.0
    }
    /// Original file size in megabytes (3 decimal places).
    pub fn size_mb(&self) -> f64 {
        (self.size_original as f64 / 1024.0f64.powi(2) * 1000.0).round() / 1000.0
    }
    /// Original file size in gigabytes (3 decimal places).
    pub fn size_gb(&self) -> f64 {
        (self.size_original as f64 / 1024.0f64.powi(3) * 1000.0).round() / 1000.0
    }
    /// Original file size in terabytes (3 decimal places).
    pub fn size_tb(&self) -> f64 {
        (self.size_original as f64 / 1024.0f64.powi(4) * 1000.0).round() / 1000.0
    }

    // ── CREATE ───────────────────────────────────────────────────────────────

    /// Encrypt a raw binary file and produce a MajikFile instance.
    ///
    /// Single-recipient (empty `recipients`):
    ///   ML-KEM encapsulate → sharedSecret → AES-256-GCM key.
    ///
    /// Group (1+ entries in `recipients`):
    ///   Random 32-byte AES key encrypts the file once.
    ///   Owner + every recipient each get their own ML-KEM key entry.
    ///   encryptedAesKey = aesKey XOR sharedSecret (one-time-pad).
    ///
    /// Mirrors `MajikFile.create()` in TypeScript.
    pub fn create(options: CreateOptions) -> Result<MajikFile, MajikFileError> {
        // ── Input validation ───────────────────────────────────────────────
        if options.data.is_empty() {
            return Err(MajikFileError::invalid_input("data is required"));
        }
        if options.user_id.trim().is_empty() {
            return Err(MajikFileError::invalid_input("user_id is required"));
        }
        if options.identity.fingerprint.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "identity.fingerprint is required",
            ));
        }
        if options.identity.ml_kem_public_key.len() != ML_KEM_PK_LEN {
            return Err(MajikFileError::invalid_input(format!(
                "identity.ml_kem_public_key must be a {ML_KEM_PK_LEN}-byte Vec<u8>"
            )));
        }
        if matches!(options.context, FileContext::ChatImage)
            && options
                .conversation_id
                .as_deref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        {
            return Err(MajikFileError::invalid_input(
                "conversation_id is required when context is ChatImage",
            ));
        }
        if options.chat_message_id.is_some() && options.thread_message_id.is_some() {
            return Err(MajikFileError::invalid_input(
                "chat_message_id and thread_message_id are mutually exclusive",
            ));
        }

        for (i, r) in options.recipients.iter().enumerate() {
            if r.fingerprint.trim().is_empty() {
                return Err(MajikFileError::invalid_input(format!(
                    "recipients[{i}].fingerprint is required"
                )));
            }
            if r.ml_kem_public_key.len() != ML_KEM_PK_LEN {
                return Err(MajikFileError::invalid_input(format!(
                    "recipients[{i}].ml_kem_public_key must be {ML_KEM_PK_LEN} bytes"
                )));
            }
        }

        let raw = &options.data;
        if !options.bypass_size_limit && raw.len() > MAX_FILE_SIZE_BYTES {
            return Err(MajikFileError::size_exceeded(
                raw.len(),
                MAX_FILE_SIZE_BYTES,
            ));
        }

        // ── Infer MIME type from filename if not provided ──────────────────
        let mime_type: Option<String> = options.mime_type.clone().or_else(|| {
            options
                .original_name
                .as_deref()
                .and_then(infer_mime_type_from_filename)
                .map(|s| s.to_string())
        });

        // ── Wrap in closure so we can catch and re-wrap errors ─────────────
        let result: Result<MajikFile, MajikFileError> = (|| {
            // ── 1. Hash (pre-compression, for dedup) ──────────────────────
            let file_hash = sha256_hex(raw);

            // ── 2. Compression ────────────────────────────────────────────
            // Note: WebP conversion is a browser Canvas API feature and is
            // intentionally omitted from the Rust port. Images pass through
            // as raw bytes. The frontend JS can perform WebP re-encoding
            // before calling the Tauri command if desired.
            let resolved_mime_type = mime_type.clone();

            let compressible = match options.context {
                FileContext::UserUpload | FileContext::ThreadAttachment => true,
                _ => should_compress(resolved_mime_type.as_deref()),
            };

            let compressed = if compressible {
                MajikCompressor::compress(raw, options.compression_level)?
            } else {
                raw.clone()
            };

            // ── 3. IV ──────────────────────────────────────────────────────
            let iv = generate_random_bytes(IV_LENGTH)?;
            let iv_hex = hex::encode(&iv);

            // ── 4. Encrypt ─────────────────────────────────────────────────
            let cleaned_recipients =
                deduplicate_recipients(options.recipients.clone(), &options.identity.fingerprint);
            assert_recipient_limit(&cleaned_recipients)?;

            // Owner is always the first key entry
            let all_recipients: Vec<MajikFileRecipient> = std::iter::once(MajikFileRecipient {
                fingerprint: options.identity.fingerprint.clone(),
                public_key: options.identity.public_key.clone(),
                ml_kem_public_key: options.identity.ml_kem_public_key.clone(),
            })
            .chain(cleaned_recipients.iter().cloned())
            .collect();

            let participant_pub_keys: Vec<MajikMessagePublicKey> = all_recipients
                .iter()
                .map(|r| r.public_key.clone())
                .collect();

            let is_group_file = !cleaned_recipients.is_empty();

            let (ciphertext, payload) = if !is_group_file {
                // ── Single ─────────────────────────────────────────────────
                // ML-KEM encapsulate → sharedSecret used as AES-256-GCM key
                let (shared_secret, ml_kem_ct) =
                    ml_kem_encapsulate(&options.identity.ml_kem_public_key)?;
                let ct = aes_gcm_encrypt(&shared_secret, &iv, &compressed)?;

                let p = MjkbPayload::Single(MjkbSinglePayload {
                    ml_kem_cipher_text: array_to_base64(&ml_kem_ct),
                    n: options.original_name.clone(),
                    m: resolved_mime_type.clone(),
                    c: Some(options.context.as_str().to_string()),
                });
                (ct, p)
            } else {
                // ── Group ──────────────────────────────────────────────────
                // Random group AES key encrypts the file once
                let aes_key = generate_random_bytes(AES_KEY_LEN)?;
                let ct = aes_gcm_encrypt(&aes_key, &iv, &compressed)?;

                let mut keys = Vec::with_capacity(all_recipients.len());
                for r in &all_recipients {
                    let (shared_secret, ml_kem_ct) = ml_kem_encapsulate(&r.ml_kem_public_key)?;
                    // One-time-pad: safe because sharedSecret is 32 uniformly random bytes
                    let encrypted_aes_key: Vec<u8> = aes_key
                        .iter()
                        .zip(shared_secret.iter())
                        .map(|(a, s)| a ^ s)
                        .collect();
                    keys.push(MajikFileGroupKey {
                        fingerprint: r.fingerprint.clone(),
                        ml_kem_cipher_text: array_to_base64(&ml_kem_ct),
                        encrypted_aes_key: array_to_base64(&encrypted_aes_key),
                    });
                }

                let p = MjkbPayload::Group(MjkbGroupPayload {
                    keys,
                    n: options.original_name.clone(),
                    m: resolved_mime_type.clone(),
                    c: Some(options.context.as_str().to_string()),
                });
                (ct, p)
            };

            // ── 5. Encode .mjkb ────────────────────────────────────────────
            let mjkb_bytes = encode_mjkb(&iv, &payload, &ciphertext);

            // ── 6. R2 key ──────────────────────────────────────────────────
            let r2_key = match &options.context {
                FileContext::ChatImage => build_chat_image_r2_key(
                    options.conversation_id.as_deref().unwrap(),
                    &options.user_id,
                    &file_hash,
                ),
                _ if options.is_temporary => {
                    build_temporary_r2_key(&options.user_id, &file_hash, options.expires_at)
                }
                _ => build_permanent_r2_key(&options.user_id, &file_hash),
            };

            let now = chrono::Utc::now().to_rfc3339();
            let id = options.id.clone().unwrap_or_else(generate_uuid);

            let json = MajikFileJson {
                id,
                user_id: options.user_id.clone(),
                r2_key,
                original_name: options.original_name.clone(),
                mime_type: resolved_mime_type,
                size_original: raw.len() as u64,
                size_stored: mjkb_bytes.len() as u64,
                file_hash,
                encryption_iv: iv_hex,
                storage_type: if options.is_temporary {
                    StorageType::Temporary
                } else {
                    StorageType::Permanent
                },
                is_shared: options.is_shared,
                share_token: None,
                context: Some(options.context.clone()),
                chat_message_id: options.chat_message_id.clone(),
                thread_message_id: options.thread_message_id.clone(),
                thread_id: options.thread_id.clone(),
                conversation_id: options.conversation_id.clone(),
                participants: participant_pub_keys,
                expires_at: if options.is_temporary {
                    Some(build_expiry_date(options.expires_at))
                } else {
                    None
                },
                timestamp: Some(now.clone()),
                last_update: Some(now),
            };

            let instance = MajikFile::from_parts(json, Some(mjkb_bytes), is_group_file);
            instance.validate_create()?;
            Ok(instance)
        })();

        result.map_err(|e| {
            if matches!(
                e.code,
                crate::core::error::MajikFileErrorCode::EncryptionFailed
            ) {
                e
            } else {
                e // pass through all typed errors as-is
            }
        })
    }

    // ── Quick-create wrappers ────────────────────────────────────────────────

    /// Create a chat image file.
    /// Validates that the MIME type is image/* and size ≤ 25 MB.
    pub fn create_chat_image(
        data: Vec<u8>,
        user_id: String,
        identity: MajikFileIdentity,
        conversation_id: String,
        mime_type: String,
        original_name: Option<String>,
        recipients: Vec<MajikFileRecipient>,
        chat_message_id: Option<String>,
    ) -> Result<MajikFile, MajikFileError> {
        if !mime_type.starts_with("image/") {
            return Err(MajikFileError::invalid_input(format!(
                "create_chat_image: mime_type must be an image/* type (got \"{mime_type}\")"
            )));
        }
        const CHAT_IMAGE_MAX: usize = 25 * 1024 * 1024;
        if data.len() > CHAT_IMAGE_MAX {
            return Err(MajikFileError::size_exceeded(data.len(), CHAT_IMAGE_MAX));
        }
        MajikFile::create(CreateOptions {
            data,
            user_id,
            identity,
            context: FileContext::ChatImage,
            conversation_id: Some(conversation_id),
            mime_type: Some(mime_type),
            original_name,
            recipients,
            chat_message_id,
            is_temporary: false,
            ..Default::default()
        })
    }

    /// Create a chat attachment file.
    pub fn create_chat_attachment(
        data: Vec<u8>,
        user_id: String,
        identity: MajikFileIdentity,
        chat_message_id: String,
        original_name: Option<String>,
        mime_type: Option<String>,
        recipients: Vec<MajikFileRecipient>,
    ) -> Result<MajikFile, MajikFileError> {
        MajikFile::create(CreateOptions {
            data,
            user_id,
            identity,
            context: FileContext::ChatAttachment,
            chat_message_id: Some(chat_message_id),
            original_name,
            mime_type,
            recipients,
            is_temporary: false,
            ..Default::default()
        })
    }

    /// Create a thread attachment file.
    pub fn create_thread_attachment(
        data: Vec<u8>,
        user_id: String,
        identity: MajikFileIdentity,
        thread_id: String,
        thread_message_id: Option<String>,
        original_name: Option<String>,
        mime_type: Option<String>,
        recipients: Vec<MajikFileRecipient>,
    ) -> Result<MajikFile, MajikFileError> {
        MajikFile::create(CreateOptions {
            data,
            user_id,
            identity,
            context: FileContext::ThreadAttachment,
            thread_id: Some(thread_id),
            thread_message_id,
            original_name,
            mime_type,
            recipients,
            is_temporary: false,
            ..Default::default()
        })
    }

    /// Create a permanent user upload.
    pub fn create_user_upload(
        data: Vec<u8>,
        user_id: String,
        identity: MajikFileIdentity,
        original_name: Option<String>,
        mime_type: Option<String>,
        is_shared: bool,
        recipients: Vec<MajikFileRecipient>,
    ) -> Result<MajikFile, MajikFileError> {
        MajikFile::create(CreateOptions {
            data,
            user_id,
            identity,
            context: FileContext::UserUpload,
            original_name,
            mime_type,
            is_shared,
            recipients,
            is_temporary: false,
            ..Default::default()
        })
    }

    /// Create a temporary user upload with a typed TTL.
    pub fn create_temporary_upload(
        data: Vec<u8>,
        user_id: String,
        identity: MajikFileIdentity,
        original_name: Option<String>,
        mime_type: Option<String>,
        duration: Option<TempFileDuration>,
        recipients: Vec<MajikFileRecipient>,
    ) -> Result<MajikFile, MajikFileError> {
        let dur = duration.unwrap_or(TempFileDuration::Fifteen);
        MajikFile::create(CreateOptions {
            data,
            user_id,
            identity,
            context: FileContext::UserUpload,
            original_name,
            mime_type,
            recipients,
            is_temporary: true,
            expires_at: dur,
            ..Default::default()
        })
    }

    // ── PARTICIPANT ACCESS CHECKS ────────────────────────────────────────────

    /// Returns true if the given public key is in the participants list.
    /// O(n) scan — participants lists are small in practice.
    pub fn has_participant_access(&self, public_key: &MajikMessagePublicKey) -> bool {
        if public_key.trim().is_empty() {
            return false;
        }
        self.participants.contains(public_key)
    }

    /// Bind this file to a thread mail after initial creation (once-only).
    pub fn bind_to_thread_mail(
        &mut self,
        thread_id: String,
        thread_message_id: String,
    ) -> Result<(), MajikFileError> {
        if !matches!(self.context, Some(FileContext::ThreadAttachment)) {
            return Err(MajikFileError::invalid_input(
                "bind_to_thread_mail: only thread_attachment files can be bound to a mail",
            ));
        }
        if self.thread_id.is_some() || self.thread_message_id.is_some() {
            return Err(MajikFileError::invalid_input(
                "bind_to_thread_mail: this file is already bound to a thread mail",
            ));
        }
        if thread_id.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "bind_to_thread_mail: thread_id is required",
            ));
        }
        if thread_message_id.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "bind_to_thread_mail: thread_message_id is required",
            ));
        }
        self.thread_id = Some(thread_id);
        self.thread_message_id = Some(thread_message_id);
        self.last_update = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    /// Bind this file to a chat conversation after initial creation (once-only).
    pub fn bind_to_chat_conversation(
        &mut self,
        conversation_id: String,
        chat_message_id: String,
    ) -> Result<(), MajikFileError> {
        if !matches!(self.context, Some(FileContext::ChatAttachment)) {
            return Err(MajikFileError::invalid_input(
                "bind_to_chat_conversation: only chat_attachment files can be bound",
            ));
        }
        if self.chat_message_id.is_some() || self.conversation_id.is_some() {
            return Err(MajikFileError::invalid_input(
                "bind_to_chat_conversation: this file is already bound",
            ));
        }
        if conversation_id.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "bind_to_chat_conversation: conversation_id is required",
            ));
        }
        if chat_message_id.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "bind_to_chat_conversation: chat_message_id is required",
            ));
        }
        self.conversation_id = Some(conversation_id);
        self.chat_message_id = Some(chat_message_id);
        self.last_update = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    // ── DECRYPT ──────────────────────────────────────────────────────────────

    /// Decrypt a .mjkb binary.
    ///
    /// Single: Decapsulate → sharedSecret → AES key → decompress → raw bytes.
    /// Group:  Find key entry by fingerprint → decapsulate → XOR → AES key → decompress.
    ///
    /// ML-KEM decapsulation NEVER fails on a wrong key — AES-GCM auth catches it.
    ///
    /// Mirrors `MajikFile.decrypt()` in TypeScript.
    pub fn decrypt(
        source: &[u8],
        fingerprint: &str,
        ml_kem_secret_key: &[u8],
    ) -> Result<Vec<u8>, MajikFileError> {
        if ml_kem_secret_key.len() != ML_KEM_SK_LEN {
            return Err(MajikFileError::invalid_input(format!(
                "ml_kem_secret_key must be {ML_KEM_SK_LEN} bytes (got {})",
                ml_kem_secret_key.len()
            )));
        }

        let decoded = decode_mjkb(source).map_err(|e| {
            MajikFileError::decryption_failed("File decryption failed", Some(Box::new(e)))
        })?;

        let aes_key = Self::recover_aes_key(&decoded.payload, fingerprint, ml_kem_secret_key)?;

        let decrypted =
            aes_gcm_decrypt(&aes_key, &decoded.iv, &decoded.ciphertext)?.ok_or_else(|| {
                MajikFileError::decryption_failed(
                    "Decryption failed — wrong key or corrupted .mjkb file",
                    None,
                )
            })?;

        let compressible = match decoded.payload.context_str() {
            Some("user_upload") | Some("thread_attachment") => true,
            c => should_compress(c),
        };

        if compressible {
            MajikCompressor::decompress(&decrypted)
        } else {
            Ok(decrypted)
        }
    }

    /// Decrypt and return bytes together with the original filename and MIME type
    /// that were embedded in the payload at encryption time.
    ///
    /// Preferred for File Vault UI — avoids a second parse of the binary.
    ///
    /// Returns `(bytes, original_name, mime_type)`.
    ///
    /// Mirrors `MajikFile.decryptWithMetadata()` in TypeScript.
    pub fn decrypt_with_metadata(
        source: &[u8],
        fingerprint: &str,
        ml_kem_secret_key: &[u8],
    ) -> Result<(Vec<u8>, Option<String>, Option<String>), MajikFileError> {
        if ml_kem_secret_key.len() != ML_KEM_SK_LEN {
            return Err(MajikFileError::invalid_input(format!(
                "ml_kem_secret_key must be {ML_KEM_SK_LEN} bytes (got {})",
                ml_kem_secret_key.len()
            )));
        }

        let decoded = decode_mjkb(source).map_err(|e| {
            MajikFileError::decryption_failed("File decryption failed", Some(Box::new(e)))
        })?;

        let aes_key = Self::recover_aes_key(&decoded.payload, fingerprint, ml_kem_secret_key)?;

        let decrypted =
            aes_gcm_decrypt(&aes_key, &decoded.iv, &decoded.ciphertext)?.ok_or_else(|| {
                MajikFileError::decryption_failed(
                    "Decryption failed — wrong key or corrupted .mjkb file",
                    None,
                )
            })?;

        let original_name = decoded.payload.original_name().map(|s| s.to_string());
        let mime_type_str = decoded.payload.mime_type().map(|s| s.to_string());

        let compressible = match decoded.payload.context_str() {
            Some("user_upload") | Some("thread_attachment") => true,
            c => should_compress(c),
        };

        let bytes = if compressible {
            MajikCompressor::decompress(&decrypted)?
        } else {
            decrypted
        };

        Ok((bytes, original_name, mime_type_str))
    }

    /// Decrypt the .mjkb binary already loaded on this instance.
    /// Mirrors `decryptBinary()` in TypeScript.
    pub fn decrypt_binary(
        &self,
        fingerprint: &str,
        ml_kem_secret_key: &[u8],
    ) -> Result<Vec<u8>, MajikFileError> {
        let binary = self
            .binary
            .as_ref()
            .ok_or_else(MajikFileError::missing_binary)?;
        MajikFile::decrypt(binary, fingerprint, ml_kem_secret_key)
    }

    /// Shared key-recovery logic for single and group payloads.
    fn recover_aes_key(
        payload: &MjkbPayload,
        fingerprint: &str,
        ml_kem_secret_key: &[u8],
    ) -> Result<Vec<u8>, MajikFileError> {
        match payload {
            MjkbPayload::Single(p) => {
                let ml_kem_ct = base64_to_bytes(&p.ml_kem_cipher_text)?;
                ml_kem_decapsulate(&ml_kem_ct, ml_kem_secret_key)
            }
            MjkbPayload::Group(p) => {
                if fingerprint.trim().is_empty() {
                    return Err(MajikFileError::invalid_input(
                        "fingerprint is required to decrypt group files",
                    ));
                }
                let entry = p
                    .keys
                    .iter()
                    .find(|k| k.fingerprint == fingerprint)
                    .ok_or_else(|| {
                        MajikFileError::decryption_failed(
                            format!(
                                "No key entry found for fingerprint \"{fingerprint}\" \
                                 — this identity does not have access to this file"
                            ),
                            None,
                        )
                    })?;

                let ml_kem_ct = base64_to_bytes(&entry.ml_kem_cipher_text)?;
                let shared_secret = ml_kem_decapsulate(&ml_kem_ct, ml_kem_secret_key)?;
                let enc_aes_key = base64_to_bytes(&entry.encrypted_aes_key)?;

                // Recover group AES key: aesKey = encryptedAesKey XOR sharedSecret
                let aes_key: Vec<u8> = enc_aes_key
                    .iter()
                    .zip(shared_secret.iter())
                    .map(|(e, s)| e ^ s)
                    .collect();
                Ok(aes_key)
            }
        }
    }

    // ── STORAGE TYPE MUTATION ────────────────────────────────────────────────

    /// Mutate the storage type in-place and rebuild the R2 key.
    /// Low-level escape hatch — prefer `set_permanent()` / `set_temporary()`.
    pub fn set_storage_type(
        &mut self,
        storage_type: StorageType,
        expires_at: Option<String>,
        duration: TempFileDuration,
    ) -> Result<(), MajikFileError> {
        if storage_type == StorageType::Temporary && expires_at.is_none() {
            return Err(MajikFileError::invalid_input(
                "set_storage_type: expires_at is required when switching to temporary",
            ));
        }
        if matches!(self.context, Some(FileContext::ChatImage)) {
            return Err(MajikFileError::invalid_input(
                "set_storage_type: chat_image files are conversation-scoped \
                 and cannot change storage type",
            ));
        }

        let new_r2_key = match storage_type {
            StorageType::Temporary => {
                build_temporary_r2_key(&self.user_id, &self.file_hash, duration)
            }
            StorageType::Permanent => build_permanent_r2_key(&self.user_id, &self.file_hash),
        };

        self.expires_at = if storage_type == StorageType::Temporary {
            expires_at
        } else {
            None
        };
        self.storage_type = storage_type;
        self.r2_key = new_r2_key;
        self.last_update = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    /// Switch to permanent storage. Clears any expiry date and updates the R2 key.
    pub fn set_permanent(&mut self) -> Result<(), MajikFileError> {
        self.set_storage_type(StorageType::Permanent, None, TempFileDuration::Fifteen)
    }

    /// Switch to temporary storage with a typed TTL.
    pub fn set_temporary(&mut self, duration: TempFileDuration) -> Result<(), MajikFileError> {
        let expires = build_expiry_date(duration);
        self.set_storage_type(StorageType::Temporary, Some(expires), duration)
    }

    // ── SERIALISATION ────────────────────────────────────────────────────────

    /// Serialise metadata to a plain struct matching the Supabase table.
    /// The encrypted binary is intentionally excluded.
    /// Mirrors `toJSON()` in TypeScript.
    pub fn to_json(&self) -> Result<MajikFileJson, MajikFileError> {
        self.validate()?;
        Ok(MajikFileJson {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            r2_key: self.r2_key.clone(),
            original_name: self.original_name.clone(),
            mime_type: self.mime_type.clone(),
            size_original: self.size_original,
            size_stored: self.size_stored,
            file_hash: self.file_hash.clone(),
            encryption_iv: self.encryption_iv.clone(),
            storage_type: self.storage_type.clone(),
            is_shared: self.is_shared,
            share_token: self.share_token.clone(),
            context: self.context.clone(),
            chat_message_id: self.chat_message_id.clone(),
            thread_message_id: self.thread_message_id.clone(),
            thread_id: self.thread_id.clone(),
            participants: self.participants.clone(),
            conversation_id: self.conversation_id.clone(),
            expires_at: self.expires_at.clone(),
            timestamp: self.timestamp.clone(),
            last_update: self.last_update.clone(),
        })
    }

    /// Restore a MajikFile from its serialised JSON representation.
    /// The R2 prefix check is NOT performed here — rows restored from
    /// Supabase may have been written by earlier code and should not fail.
    ///
    /// Mirrors `MajikFile.fromJSON()` in TypeScript.
    pub fn from_json(
        json: MajikFileJson,
        binary: Option<Vec<u8>>,
    ) -> Result<MajikFile, MajikFileError> {
        let mut is_group = false;
        if let Some(ref bin) = binary {
            if let Ok(decoded) = decode_mjkb(bin) {
                is_group = decoded.payload.is_group();
            }
        }
        let instance = MajikFile::from_parts(json, binary, is_group);
        instance.validate()?;
        Ok(instance)
    }

    // ── Binary export ────────────────────────────────────────────────────────

    /// Export the encrypted binary as raw bytes.
    /// Mirrors `toBinaryBytes()` in TypeScript.
    pub fn to_binary_bytes(&self) -> Result<&[u8], MajikFileError> {
        self.binary
            .as_deref()
            .ok_or_else(MajikFileError::missing_binary)
    }

    /// Export the encrypted binary as an owned `Vec<u8>`.
    /// Mirrors `toMJKB()` in TypeScript.
    pub fn to_mjkb(&self) -> Result<Vec<u8>, MajikFileError> {
        Ok(self.to_binary_bytes()?.to_vec())
    }

    // ── VALIDATE ─────────────────────────────────────────────────────────────

    /// Validate all required properties against business invariants.
    /// Collects ALL errors before throwing — mirrors TypeScript behaviour.
    ///
    /// Mirrors `validate()` in TypeScript.
    pub fn validate(&self) -> Result<(), MajikFileError> {
        let mut errors: Vec<String> = Vec::new();

        if self.id.trim().is_empty() {
            errors.push("id is required".into());
        }
        if self.user_id.trim().is_empty() {
            errors.push("user_id is required".into());
        }
        if self.r2_key.trim().is_empty() {
            errors.push("r2_key is required".into());
        }
        if self.file_hash.trim().is_empty() {
            errors.push("file_hash is required".into());
        }
        if self.encryption_iv.trim().is_empty() {
            errors.push("encryption_iv is required".into());
        }
        if self.chat_message_id.is_some() && self.thread_message_id.is_some() {
            errors.push("chat_message_id and thread_message_id cannot both be set".into());
        }
        if matches!(self.context, Some(FileContext::ChatImage))
            && self
                .conversation_id
                .as_deref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        {
            errors.push("conversation_id is required for chat_image context".into());
        }
        if self.storage_type == StorageType::Temporary && self.expires_at.is_none() {
            errors.push("expires_at is required for temporary files".into());
        }

        if !errors.is_empty() {
            return Err(MajikFileError::validation_failed(errors));
        }
        Ok(())
    }

    /// Stricter validation used only during create() — includes R2 prefix checks.
    fn validate_create(&self) -> Result<(), MajikFileError> {
        self.validate()?;

        let mut errors: Vec<String> = Vec::new();
        let permanent_prefix = format!("{}/{}/", R2Prefix::PERMANENT, self.user_id);
        let temporary_prefix = format!("{}/", R2Prefix::TEMPORARY);
        let chat_image_prefix = format!("{}/", R2Prefix::CHAT_IMAGE);

        match &self.context {
            Some(FileContext::ChatImage) => {
                if !self.r2_key.starts_with(&chat_image_prefix) {
                    errors.push(format!(
                        "r2_key for chat_image files must start with \"{chat_image_prefix}\""
                    ));
                }
            }
            _ if self.storage_type == StorageType::Permanent => {
                if !self.r2_key.starts_with(&permanent_prefix) {
                    errors.push(format!(
                        "r2_key for permanent files must start with \"{permanent_prefix}\""
                    ));
                }
            }
            _ if self.storage_type == StorageType::Temporary => {
                if !self.r2_key.starts_with(&temporary_prefix) {
                    errors.push(format!(
                        "r2_key for temporary files must start with \"{temporary_prefix}\""
                    ));
                }
            }
            _ => {}
        }

        if !errors.is_empty() {
            return Err(MajikFileError::validation_failed(errors));
        }
        Ok(())
    }

    // ── OWNERSHIP ────────────────────────────────────────────────────────────

    /// Returns true if the given user_id matches the file's owner.
    pub fn user_is_owner(&self, user_id: &str) -> bool {
        !user_id.trim().is_empty() && self.user_id == user_id
    }

    // ── BINARY MANAGEMENT ────────────────────────────────────────────────────

    /// Attach (or replace) the encrypted .mjkb binary on this instance.
    pub fn attach_binary(&mut self, binary: Vec<u8>) {
        self.binary = Some(binary);
    }

    /// Clear the in-memory binary to free memory after an upload completes.
    pub fn clear_binary(&mut self) {
        self.binary = None;
    }

    // ── SHARING ──────────────────────────────────────────────────────────────

    /// Returns true if this file has an active share token.
    pub fn has_share_token(&self) -> bool {
        self.share_token
            .as_ref()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
    }

    /// Toggle sharing state.
    /// - Not shared → sets is_shared = true, assigns token (auto-generated if None).
    /// - Shared      → sets is_shared = false, clears token.
    /// Returns the active share token, or None if sharing was disabled.
    ///
    /// Mirrors `toggleSharing()` in TypeScript.
    pub fn toggle_sharing(
        &mut self,
        token: Option<String>,
    ) -> Result<Option<String>, MajikFileError> {
        if self.is_shared {
            self.is_shared = false;
            self.share_token = None;
            self.last_update = Some(chrono::Utc::now().to_rfc3339());
            Ok(None)
        } else {
            if let Some(ref t) = token {
                if t.trim().is_empty() {
                    return Err(MajikFileError::invalid_input(
                        "toggle_sharing: token must be a non-empty string when provided",
                    ));
                }
            }
            let t = token.unwrap_or_else(generate_uuid);
            self.is_shared = true;
            self.share_token = Some(t.clone());
            self.last_update = Some(chrono::Utc::now().to_rfc3339());
            Ok(Some(t))
        }
    }

    // ── EXPIRY ────────────────────────────────────────────────────────────────

    /// Returns true if this file has passed its expiry date.
    pub fn is_expired(&self) -> bool {
        is_expired(self.expires_at.as_deref())
    }

    /// Returns true if this file uses temporary storage.
    pub fn is_temporary(&self) -> bool {
        self.storage_type == StorageType::Temporary
    }

    // ── MIME / FORMAT HELPERS ─────────────────────────────────────────────────

    /// Returns true if the MIME type can be rendered inline in a browser.
    pub fn is_inline_viewable(&self) -> bool {
        is_mime_type_inline_viewable(self.mime_type.as_deref())
    }

    /// Safe download filename derived from the hash + original extension.
    pub fn safe_filename(&self) -> String {
        derive_filename(&self.file_hash, self.original_name.as_deref())
    }

    // ── SIZE CHECK ────────────────────────────────────────────────────────────

    /// Returns true if the original file size exceeds the given limit in MB.
    pub fn exceeds_size(&self, limit_mb: f64) -> Result<bool, MajikFileError> {
        if limit_mb <= 0.0 || !limit_mb.is_finite() {
            return Err(MajikFileError::invalid_input(format!(
                "exceeds_size: limit_mb must be a positive finite number (got {limit_mb})"
            )));
        }
        Ok(self.size_original > (limit_mb * 1024.0 * 1024.0) as u64)
    }

    // ── ACCESS CHECK ─────────────────────────────────────────────────────────

    /// Lightweight fingerprint check.
    /// Returns true if sha256_base64(public_key) == owner_fingerprint.
    /// Does NOT attempt decryption.
    ///
    /// Mirrors `MajikFile.hasPublicKeyAccess()` in TypeScript.
    pub fn has_public_key_access(
        public_key: &[u8],
        owner_fingerprint: &str,
    ) -> Result<bool, MajikFileError> {
        if public_key.len() != ML_KEM_PK_LEN {
            return Err(MajikFileError::invalid_input(format!(
                "has_public_key_access: public_key must be {ML_KEM_PK_LEN} bytes (got {})",
                public_key.len()
            )));
        }
        if owner_fingerprint.trim().is_empty() {
            return Err(MajikFileError::invalid_input(
                "has_public_key_access: owner_fingerprint is required",
            ));
        }
        Ok(sha256_base64(public_key) == owner_fingerprint)
    }

    // ── STATS ─────────────────────────────────────────────────────────────────

    /// Return a human-readable stats snapshot for display in a file manager UI.
    pub fn get_stats(&self) -> MajikFileStats {
        MajikFileStats {
            id: self.id.clone(),
            original_name: self.original_name.clone(),
            mime_type: self.mime_type.clone(),
            size_original_human: format_bytes(self.size_original),
            size_stored_human: format_bytes(self.size_stored),
            compression_ratio_pct: MajikCompressor::compression_ratio_pct(
                self.size_original,
                self.size_stored,
            ),
            file_hash: self.file_hash.clone(),
            storage_type: self.storage_type.clone(),
            is_group: self.is_group,
            context: self.context.clone(),
            is_shared: self.is_shared,
            is_expired: self.is_expired(),
            expires_at: self.expires_at.clone(),
            timestamp: self.timestamp.clone(),
            r2_key: self.r2_key.clone(),
        }
    }

    // ── DUPLICATE DETECTION ───────────────────────────────────────────────────

    /// Returns true if this file has the same plaintext content as another
    /// (comparison by SHA-256 file_hash of original bytes).
    pub fn is_duplicate_of(&self, other: &MajikFile) -> bool {
        self.file_hash == other.file_hash
    }

    /// Returns true if raw bytes would produce a duplicate.
    /// Use this to short-circuit the encrypt + upload flow.
    pub fn would_be_duplicate(raw_bytes: &[u8], existing_hash: &str) -> bool {
        sha256_hex(raw_bytes) == existing_hash
    }

    // ── STATIC HELPERS ────────────────────────────────────────────────────────

    /// Quick magic-byte check. Does NOT fully parse.
    pub fn is_mjkb_candidate(data: &[u8]) -> bool {
        data.len() >= 5 && data[..4] == MJKB_MAGIC
    }

    /// Full structural validation of a .mjkb binary (without decrypting).
    /// Mirrors `MajikFile.isValidMJKB()` in TypeScript.
    pub fn is_valid_mjkb(data: &[u8]) -> bool {
        let Ok(decoded) = decode_mjkb(data) else {
            return false;
        };
        match &decoded.payload {
            MjkbPayload::Single(p) => !p.ml_kem_cipher_text.is_empty(),
            MjkbPayload::Group(p) => !p.keys.is_empty(),
        }
    }

    /// Build a default ISO-8601 expiry date for temporary files.
    pub fn build_expiry_date(days: TempFileDuration) -> String {
        build_expiry_date(days)
    }

    /// Format bytes as a human-readable string (e.g. "4.2 MB").
    pub fn format_bytes(bytes: u64) -> String {
        format_bytes(bytes)
    }

    /// Infer a MIME type from a filename extension.
    pub fn infer_mime_type(filename: &str) -> Option<&'static str> {
        infer_mime_type_from_filename(filename)
    }

    /// Return the raw byte length of a slice.
    pub fn get_raw_file_size(data: &[u8]) -> usize {
        data.len()
    }
}

impl std::fmt::Display for MajikFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MajikFile {{ id: {}, hash: {}…, size: {}, type: {}, storage: {} }}",
            self.id,
            &self.file_hash[..8.min(self.file_hash.len())],
            format_bytes(self.size_original),
            if self.is_group { "group" } else { "single" },
            self.storage_type,
        )
    }
}
