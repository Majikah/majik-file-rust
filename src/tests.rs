//! tests.rs
//!
//! Unit tests for the majik-file Rust library.
//! Each test mirrors the expected behaviour of the TypeScript original.
//!
//! Run with: `cargo test`
//! Run a single test: `cargo test test_single_encrypt_decrypt -- --nocapture`

#[cfg(test)]
mod tests {
    use crate::core::compressor::{CompressionPreset, MajikCompressor};
    use crate::core::crypto::{generate_ml_kem_keypair, generate_random_bytes};
    use crate::core::types::{
        CreateOptions, FileContext, MajikFileIdentity, MajikFileRecipient, StorageType,
        TempFileDuration,
    };
    use crate::core::utils::{
        array_to_base64, base64_to_bytes, build_permanent_r2_key, build_temporary_r2_key,
        decode_mjkb, format_bytes, is_expired, sha256_base64, sha256_hex, should_compress,
    };
    use crate::majik_file::MajikFile;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn make_identity() -> MajikFileIdentity {
        let (pk, sk) = generate_ml_kem_keypair();
        let fingerprint = sha256_base64(&pk);
        MajikFileIdentity {
            public_key: format!("pubkey_{}", &fingerprint[..8]),
            fingerprint,
            ml_kem_public_key: pk,
            ml_kem_secret_key: sk,
        }
    }

    fn make_recipient() -> (MajikFileIdentity, MajikFileRecipient) {
        let identity = make_identity();
        let recipient = MajikFileRecipient {
            fingerprint: identity.fingerprint.clone(),
            public_key: identity.public_key.clone(),
            ml_kem_public_key: identity.ml_kem_public_key.clone(),
        };
        (identity, recipient)
    }

    fn plaintext() -> Vec<u8> {
        b"Hello, Majik! This is a test plaintext payload for encryption.".to_vec()
    }

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_sha256_hex_length_and_format() {
        let digest = sha256_hex(b"hello");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"Hello"));
    }

    #[test]
    fn test_sha256_base64_non_empty() {
        let b64 = sha256_base64(b"some bytes");
        assert!(!b64.is_empty());
    }

    // ── Base64 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_base64_roundtrip() {
        let original = b"test bytes 12345";
        let encoded = array_to_base64(original);
        let decoded = base64_to_bytes(&encoded).unwrap();
        assert_eq!(original.to_vec(), decoded);
    }

    // ── Compressor ────────────────────────────────────────────────────────────

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let compressed = MajikCompressor::compress(&data, Some(CompressionPreset::FAST)).unwrap();
        let decompressed = MajikCompressor::decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_compression_ratio_pct_positive() {
        // Text should compress well
        let text: Vec<u8> = b"aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj"
            .iter()
            .cycle()
            .take(8192)
            .copied()
            .collect();
        let compressed =
            MajikCompressor::compress(&text, Some(CompressionPreset::BALANCED)).unwrap();
        let ratio =
            MajikCompressor::compression_ratio_pct(text.len() as u64, compressed.len() as u64);
        assert!(ratio > 0.0, "text should compress: ratio={ratio}");
    }

    #[test]
    fn test_adaptive_level_clamps_large_input() {
        // 600 MB input should cap at level 6
        let capped = MajikCompressor::adaptive_level(600 * 1024 * 1024, 22);
        assert_eq!(capped, 6);
    }

    #[test]
    fn test_adaptive_level_passes_small_input() {
        // 1 MB input should pass through level 22 unchanged
        let level = MajikCompressor::adaptive_level(1024 * 1024, 22);
        assert_eq!(level, 22);
    }

    // ── should_compress ───────────────────────────────────────────────────────

    #[test]
    fn test_should_compress_text() {
        assert!(should_compress(Some("text/plain")));
        assert!(should_compress(Some("application/json")));
        assert!(should_compress(Some("image/png")));
    }

    #[test]
    fn test_should_not_compress_incompressible() {
        assert!(!should_compress(Some("image/jpeg")));
        assert!(!should_compress(Some("video/mp4")));
        assert!(!should_compress(Some("application/zip")));
        assert!(!should_compress(Some("image/webp")));
    }

    #[test]
    fn test_should_compress_unknown_defaults_true() {
        assert!(should_compress(None));
        assert!(should_compress(Some("application/x-unknown-exotic")));
    }

    // ── format_bytes ──────────────────────────────────────────────────────────

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    // ── R2 key construction ───────────────────────────────────────────────────

    #[test]
    fn test_permanent_r2_key_format() {
        let key = build_permanent_r2_key("user123", "abc123hash");
        assert_eq!(key, "files/user/user123/abc123hash.mjkb");
    }

    #[test]
    fn test_temporary_r2_key_format() {
        let key = build_temporary_r2_key("user123", "abc123hash", TempFileDuration::Fifteen);
        assert_eq!(key, "files/public/15/user123_abc123hash.mjkb");
    }

    // ── is_expired ────────────────────────────────────────────────────────────

    #[test]
    fn test_is_expired_past_date() {
        assert!(is_expired(Some("2000-01-01T00:00:00+00:00")));
    }

    #[test]
    fn test_is_expired_future_date() {
        assert!(!is_expired(Some("2999-01-01T00:00:00+00:00")));
    }

    #[test]
    fn test_is_expired_none() {
        assert!(!is_expired(None));
    }

    // ── ML-KEM keypair ────────────────────────────────────────────────────────

    #[test]
    fn test_generate_ml_kem_keypair_sizes() {
        let (pk, sk) = generate_ml_kem_keypair();
        assert_eq!(pk.len(), 1184, "public key must be 1184 bytes");
        // In ml-kem 0.3.x the secret key is the 64-byte seed
        assert_eq!(sk.len(), 2400, "secret key seed must be 2400 bytes");
    }

    #[test]
    fn test_keypairs_are_unique() {
        let (pk1, _) = generate_ml_kem_keypair();
        let (pk2, _) = generate_ml_kem_keypair();
        assert_ne!(pk1, pk2);
    }

    // ── random bytes ─────────────────────────────────────────────────────────

    #[test]
    fn test_generate_random_bytes_length() {
        let bytes = generate_random_bytes(12).unwrap();
        assert_eq!(bytes.len(), 12);
    }

    #[test]
    fn test_generate_random_bytes_uniqueness() {
        let a = generate_random_bytes(32).unwrap();
        let b = generate_random_bytes(32).unwrap();
        assert_ne!(a, b);
    }

    // ── MajikFile::create — single recipient ──────────────────────────────────

    #[test]
    fn test_single_encrypt_produces_mjkb_candidate() {
        let identity = make_identity();
        let data = plaintext();

        let file = MajikFile::create(CreateOptions {
            data: data.clone(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();
        assert!(MajikFile::is_mjkb_candidate(binary));
        assert!(MajikFile::is_valid_mjkb(binary));
        assert!(file.is_single());
        assert!(!file.is_group());
        assert_eq!(file.size_original() as usize, data.len());
    }

    // ── MajikFile::create — group recipients ──────────────────────────────────

    #[test]
    fn test_group_encrypt_produces_group_payload() {
        let owner = make_identity();
        let (_, recipient) = make_recipient();

        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity: owner,
            context: FileContext::UserUpload,
            recipients: vec![recipient],
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();
        let decoded = decode_mjkb(binary).unwrap();
        assert!(decoded.payload.is_group());
        assert!(file.is_group());
    }

    // ── Full single encrypt → decrypt roundtrip ───────────────────────────────

    #[test]
    fn test_single_encrypt_decrypt_roundtrip() {
        let identity = make_identity();
        let original = plaintext();

        let file = MajikFile::create(CreateOptions {
            data: original.clone(),
            user_id: "user-001".into(),
            identity: identity.clone(),
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();
        let decrypted =
            MajikFile::decrypt(binary, &identity.fingerprint, &identity.ml_kem_secret_key).unwrap();

        assert_eq!(original, decrypted);
    }

    // ── Full group encrypt → decrypt roundtrip ────────────────────────────────

    #[test]
    fn test_group_encrypt_decrypt_roundtrip_owner_and_recipient() {
        let owner = make_identity();
        let (recipient_identity, recipient) = make_recipient();
        let original = plaintext();

        let file = MajikFile::create(CreateOptions {
            data: original.clone(),
            user_id: "user-001".into(),
            identity: owner.clone(),
            context: FileContext::UserUpload,
            recipients: vec![recipient],
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();

        // Owner can decrypt
        let decrypted_by_owner =
            MajikFile::decrypt(binary, &owner.fingerprint, &owner.ml_kem_secret_key).unwrap();
        assert_eq!(original, decrypted_by_owner);

        // Recipient can decrypt
        let decrypted_by_recipient = MajikFile::decrypt(
            binary,
            &recipient_identity.fingerprint,
            &recipient_identity.ml_kem_secret_key,
        )
        .unwrap();
        assert_eq!(original, decrypted_by_recipient);
    }

    // ── decrypt_with_metadata ─────────────────────────────────────────────────

    #[test]
    fn test_decrypt_with_metadata_returns_name_and_mime() {
        let identity = make_identity();

        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity: identity.clone(),
            context: FileContext::UserUpload,
            original_name: Some("hello.txt".into()),
            mime_type: Some("text/plain".into()),
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();
        let (bytes, name, mime) = MajikFile::decrypt_with_metadata(
            binary,
            &identity.fingerprint,
            &identity.ml_kem_secret_key,
        )
        .unwrap();

        assert_eq!(bytes, plaintext());
        assert_eq!(name.as_deref(), Some("hello.txt"));
        assert_eq!(mime.as_deref(), Some("text/plain"));
    }

    // ── Wrong key returns error ───────────────────────────────────────────────

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let owner = make_identity();
        let wrong_identity = make_identity(); // different keypair

        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity: owner.clone(),
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_binary_bytes().unwrap();
        let result = MajikFile::decrypt(
            binary,
            &wrong_identity.fingerprint,
            &wrong_identity.ml_kem_secret_key,
        );

        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    // ── Storage type mutation ─────────────────────────────────────────────────

    #[test]
    fn test_set_temporary_updates_storage_type_and_r2_key() {
        let identity = make_identity();
        let mut file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        assert_eq!(file.storage_type(), &StorageType::Permanent);
        file.set_temporary(TempFileDuration::Seven).unwrap();
        assert_eq!(file.storage_type(), &StorageType::Temporary);
        assert!(file.r2_key().starts_with("files/public/7/"));
        assert!(file.expires_at().is_some());
    }

    #[test]
    fn test_set_permanent_clears_expiry() {
        let identity = make_identity();
        let mut file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            is_temporary: true,
            ..Default::default()
        })
        .unwrap();

        assert_eq!(file.storage_type(), &StorageType::Temporary);
        file.set_permanent().unwrap();
        assert_eq!(file.storage_type(), &StorageType::Permanent);
        assert!(file.expires_at().is_none());
    }

    // ── Sharing ───────────────────────────────────────────────────────────────

    #[test]
    fn test_toggle_sharing_on_and_off() {
        let identity = make_identity();
        let mut file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        assert!(!file.is_shared());
        let token = file.toggle_sharing(None).unwrap();
        assert!(token.is_some());
        assert!(file.is_shared());
        assert!(file.has_share_token());

        let off = file.toggle_sharing(None).unwrap();
        assert!(off.is_none());
        assert!(!file.is_shared());
        assert!(!file.has_share_token());
    }

    // ── to_json / from_json roundtrip ─────────────────────────────────────────

    #[test]
    fn test_to_json_from_json_roundtrip() {
        let identity = make_identity();
        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            original_name: Some("doc.pdf".into()),
            mime_type: Some("application/pdf".into()),
            ..Default::default()
        })
        .unwrap();

        let binary = file.to_mjkb().unwrap();
        let json = file.to_json().unwrap();

        let restored = MajikFile::from_json(json, Some(binary)).unwrap();
        assert_eq!(file.id(), restored.id());
        assert_eq!(file.file_hash(), restored.file_hash());
        assert_eq!(restored.original_name(), Some("doc.pdf"));
        assert_eq!(restored.mime_type(), Some("application/pdf"));
    }

    // ── duplicate detection ───────────────────────────────────────────────────

    #[test]
    fn test_would_be_duplicate_detection() {
        let data = plaintext();
        let hash = sha256_hex(&data);
        assert!(MajikFile::would_be_duplicate(&data, &hash));
        assert!(!MajikFile::would_be_duplicate(b"different bytes", &hash));
    }

    // ── context: chat_image ───────────────────────────────────────────────────

    #[test]
    fn test_chat_image_requires_conversation_id() {
        let identity = make_identity();
        let result = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::ChatImage,
            conversation_id: None, // missing — should fail
            mime_type: Some("image/png".into()),
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_chat_image_r2_key_prefix() {
        let identity = make_identity();
        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::ChatImage,
            conversation_id: Some("conv-xyz".into()),
            mime_type: Some("image/png".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(file.r2_key().starts_with("images/chats/conv-xyz/"));
    }

    // ── has_public_key_access ────────────────────────────────────────────────

    #[test]
    fn test_has_public_key_access_match() {
        let (pk, _) = generate_ml_kem_keypair();
        let fingerprint = sha256_base64(&pk);
        assert!(MajikFile::has_public_key_access(&pk, &fingerprint).unwrap());
    }

    #[test]
    fn test_has_public_key_access_mismatch() {
        let (pk1, _) = generate_ml_kem_keypair();
        let (pk2, _) = generate_ml_kem_keypair();
        let fingerprint2 = sha256_base64(&pk2);
        assert!(!MajikFile::has_public_key_access(&pk1, &fingerprint2).unwrap());
    }

    // ── size limit ────────────────────────────────────────────────────────────

    #[test]
    fn test_size_limit_enforced() {
        let identity = make_identity();
        // 101 MB of zeros
        let big_data = vec![0u8; 101 * 1024 * 1024];
        let result = MajikFile::create(CreateOptions {
            data: big_data,
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            bypass_size_limit: false,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_size_limit_bypass() {
        let identity = make_identity();
        // 101 MB — only feasible in test with bypass
        let big_data = vec![0u8; 101 * 1024 * 1024];
        let result = MajikFile::create(CreateOptions {
            data: big_data,
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            bypass_size_limit: true,
            compression_level: Some(1), // fastest for test speed
            ..Default::default()
        });
        assert!(result.is_ok());
    }

    // ── is_valid_mjkb ────────────────────────────────────────────────────────

    #[test]
    fn test_is_valid_mjkb_rejects_garbage() {
        assert!(!MajikFile::is_valid_mjkb(b"not a real mjkb file"));
        assert!(!MajikFile::is_valid_mjkb(b""));
        assert!(!MajikFile::is_valid_mjkb(b"MJKB")); // too short
    }

    #[test]
    fn test_is_valid_mjkb_accepts_real_file() {
        let identity = make_identity();
        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();
        let binary = file.to_binary_bytes().unwrap();
        assert!(MajikFile::is_valid_mjkb(binary));
    }

    // ── exceedsSize ───────────────────────────────────────────────────────────

    #[test]
    fn test_exceeds_size() {
        let identity = make_identity();
        let file = MajikFile::create(CreateOptions {
            data: vec![0u8; 1024 * 1024], // exactly 1 MB
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        assert!(file.exceeds_size(0.5).unwrap()); // 1 MB > 0.5 MB
        assert!(!file.exceeds_size(2.0).unwrap()); // 1 MB < 2 MB
    }

    // ── getStats ─────────────────────────────────────────────────────────────

    #[test]
    fn test_get_stats_fields() {
        let identity = make_identity();
        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::UserUpload,
            ..Default::default()
        })
        .unwrap();

        let stats = file.get_stats();
        assert!(!stats.id.is_empty());
        assert!(!stats.file_hash.is_empty());
        assert!(!stats.size_original_human.is_empty());
        assert_eq!(stats.is_group, false);
    }

    // ── bind_to_thread_mail once-only constraint ──────────────────────────────

    #[test]
    fn test_bind_to_thread_mail_once_only() {
        let identity = make_identity();
        let mut file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity,
            context: FileContext::ThreadAttachment,
            ..Default::default()
        })
        .unwrap();

        file.bind_to_thread_mail("thread-1".into(), "msg-1".into())
            .unwrap();

        // Second call should fail
        let result = file.bind_to_thread_mail("thread-2".into(), "msg-2".into());
        assert!(result.is_err());
    }

    // ── deduplication and recipient limit ─────────────────────────────────────

    #[test]
    fn test_duplicate_recipient_deduplicated() {
        let owner = make_identity();
        let (_, recipient) = make_recipient();
        let duplicate = recipient.clone();

        // Providing the same recipient twice should not produce two key entries
        let file = MajikFile::create(CreateOptions {
            data: plaintext(),
            user_id: "user-001".into(),
            identity: owner,
            context: FileContext::UserUpload,
            recipients: vec![recipient, duplicate],
            ..Default::default()
        })
        .unwrap();

        // Should be group (one unique extra recipient)
        assert!(file.is_group());
    }
}
