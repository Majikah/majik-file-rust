//! Port of test/majik-file.test.ts. Keys come from `generate_ml_kem_keypair()`;
//! signing uses the mock provider in helpers (see its doc comment).

mod helpers;

use std::sync::Arc;

use ::majik_file::core::crypto::crypto_provider::*;
use ::majik_file::*;
use helpers::*;

const TEXT: &[u8] =
    b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

fn code(e: MajikFileError) -> MajikFileErrorCode {
    e.code
}

// ── create() — input validation ────────────────────────────────────────────

#[test]
fn create_rejects_empty_data() {
    let id = test_identity("a");
    let err = MajikFile::create(opts(b"", &id)).unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::InvalidInput);
}

#[test]
fn create_rejects_blank_user_id() {
    let id = test_identity("a");
    let mut o = opts(TEXT, &id);
    o.user_id = "  ".into();
    assert_eq!(
        code(MajikFile::create(o).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
}

#[test]
fn create_rejects_bad_public_key_length() {
    let mut id = test_identity("a");
    id.ml_kem_public_key.truncate(100);
    assert_eq!(
        code(MajikFile::create(opts(TEXT, &id)).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
}

#[test]
fn create_rejects_oversize_unless_bypassed() {
    let id = test_identity("a");
    let big = vec![7u8; MAX_FILE_SIZE_BYTES + 1];
    let err = MajikFile::create(opts(&big, &id)).unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::SizeExceeded);
}

#[test]
fn create_rejects_too_many_recipients() {
    let owner = test_identity("owner");
    let mut o = opts(TEXT, &owner);
    // identical key material is fine; fingerprints must differ to survive dedup
    let base = test_identity("r");
    o.recipients = (0..MAX_GROUP_RECIPIENTS + 1)
        .map(|i| {
            let mut r = as_recipient(&base);
            r.fingerprint = format!("fp-{i}");
            r
        })
        .collect();
    assert_eq!(
        code(MajikFile::create(o).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
}

// ── Single recipient ───────────────────────────────────────────────────────

#[test]
fn single_roundtrip_and_metadata() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();

    assert!(f.is_single() && !f.is_group());
    assert_eq!(f.kind(), "file");
    assert_eq!(f.schema_version(), FILE_SCHEMA_VERSION);
    assert_eq!(f.kem_alg(), "ML-KEM-768");
    assert_eq!(f.cipher_alg(), "AES-256-GCM");
    assert_eq!(f.mime_type(), Some("text/plain")); // inferred from .txt
    assert_eq!(f.size_original(), TEXT.len() as u64);
    assert_eq!(f.file_hash(), sha256_hex(TEXT));
    assert_eq!(f.encryption_iv().len(), IV_LENGTH * 2);
    assert_eq!(f.participants(), std::slice::from_ref(&id.public_key));

    let out = f.decrypt_binary(&id, None).unwrap();
    assert_eq!(out, TEXT);
}

#[test]
fn single_wrong_key_fails_authentication() {
    let id = test_identity("a");
    let other = test_identity("b");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let err = f.decrypt_binary(&other, None).unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::DecryptionFailed);
}

#[test]
fn decrypt_rejects_bad_secret_key_length() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let short = [0u8; 10];
    let err = f
        .decrypt_binary(MajikFileDecryptIdentity::new(&id.fingerprint, &short), None)
        .unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::InvalidInput);
}

#[test]
fn decrypt_with_metadata_returns_name_mime() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let m = f.decrypt_with_metadata(&id, None).unwrap();
    assert_eq!(m.bytes, TEXT);
    assert_eq!(m.original_name.as_deref(), Some("hello.txt"));
    assert_eq!(m.mime_type.as_deref(), Some("text/plain"));
    assert!(m.signature.is_none());
}

#[test]
fn incompressible_mime_is_stored_uncompressed() {
    let id = test_identity("a");
    let mut o = opts(&vec![1u8; 4096], &id);
    o.original_name = Some("clip.mp4".into());
    let f = MajikFile::create(o).unwrap();
    let decoded = decode_mjkb(f.to_mjkb().unwrap()).unwrap();
    assert_eq!(decoded.payload.z(), Some(false));
    assert_eq!(f.decrypt_binary(&id, None).unwrap(), vec![1u8; 4096]);
}

// ── Group ──────────────────────────────────────────────────────────────────

#[test]
fn group_roundtrip_for_every_participant() {
    let owner = test_identity("owner");
    let r1 = test_identity("r1");
    let r2 = test_identity("r2");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&r1), as_recipient(&r2)];
    let f = MajikFile::create(o).unwrap();

    assert!(f.is_group());
    assert_eq!(f.participants().len(), 3);
    for who in [&owner, &r1, &r2] {
        assert_eq!(f.decrypt_binary(who, None).unwrap(), TEXT);
    }
}

#[test]
fn group_non_participant_is_rejected() {
    let owner = test_identity("owner");
    let r1 = test_identity("r1");
    let outsider = test_identity("x");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&r1)];
    let f = MajikFile::create(o).unwrap();
    assert_eq!(
        code(f.decrypt_binary(&outsider, None).unwrap_err()),
        MajikFileErrorCode::DecryptionFailed
    );
}

#[test]
fn recipients_are_deduplicated_and_owner_stripped() {
    let owner = test_identity("owner");
    let r1 = test_identity("r1");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&owner), as_recipient(&r1), as_recipient(&r1)];
    let f = MajikFile::create(o).unwrap();
    assert_eq!(f.participants().len(), 2);
}

#[test]
fn only_owner_in_recipients_stays_single() {
    let owner = test_identity("owner");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&owner)];
    assert!(MajikFile::create(o).unwrap().is_single());
}

// ── Binary format ──────────────────────────────────────────────────────────

#[test]
fn binary_header_layout_is_v2() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let b = f.to_mjkb().unwrap();
    assert_eq!(&b[..4], b"MJKB");
    assert_eq!(b[4], MJKB_VERSION);
    assert_eq!(hex::encode(&b[5..17]), f.encryption_iv());
    assert!(MajikFile::is_mjkb_candidate(b));
    assert!(MajikFile::is_valid_mjkb(b));
    assert!(!MajikFile::is_valid_mjkb(&b[..10]));
}

#[test]
fn default_payload_matches_ts_shape() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let d = decode_mjkb(f.to_mjkb().unwrap()).unwrap();
    let len = u32::from_be_bytes(f.to_mjkb().unwrap()[17..21].try_into().unwrap()) as usize;
    let json: serde_json::Value =
        serde_json::from_slice(&f.to_mjkb().unwrap()[21..21 + len]).unwrap();
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["m", "mlKemCipherText", "n", "z"]); // no `ca` for default zstd
    assert_eq!(d.payload.z(), Some(true));
    assert!(d.payload.ca().is_none());
}

#[test]
fn decode_rejects_malformed_input() {
    assert_eq!(
        code(decode_mjkb(&[0u8; 10]).unwrap_err()),
        MajikFileErrorCode::FormatError
    );
    let id = test_identity("a");
    let mut b = MajikFile::create(opts(TEXT, &id))
        .unwrap()
        .to_mjkb()
        .unwrap()
        .to_vec();
    b[0] = b'X';
    assert_eq!(
        code(decode_mjkb(&b).unwrap_err()),
        MajikFileErrorCode::FormatError
    );
    b[0] = b'M';
    b[4] = 9;
    assert_eq!(
        code(decode_mjkb(&b).unwrap_err()),
        MajikFileErrorCode::UnsupportedVersion
    );
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let id = test_identity("a");
    let mut b = MajikFile::create(opts(TEXT, &id))
        .unwrap()
        .to_mjkb()
        .unwrap()
        .to_vec();
    let last = b.len() - 1;
    b[last] ^= 0xff;
    assert_eq!(
        code(MajikFile::decrypt(&b, &id, None).unwrap_err()),
        MajikFileErrorCode::DecryptionFailed
    );
}

#[test]
fn legacy_v1_binary_is_still_decryptable() {
    // Hand-build a v1 binary: payload has `c` and no `z`; decompression is
    // inferred from the mime (text/plain → compressed).
    let id = test_identity("a");
    let enc = ml_kem_encapsulate(&id.ml_kem_public_key).unwrap();
    let iv = generate_random_bytes(IV_LENGTH).unwrap();
    let compressed = MajikCompressor::compress(TEXT, Some(3)).unwrap();
    let ct = aes_gcm_encrypt(&enc.shared_secret, &iv, &compressed).unwrap();
    let payload = serde_json::json!({
        "mlKemCipherText": array_to_base64(&enc.cipher_text),
        "n": "old.txt", "m": "text/plain", "c": "user_upload"
    });
    let pj = serde_json::to_vec(&payload).unwrap();
    let mut b = Vec::new();
    b.extend_from_slice(b"MJKB");
    b.push(MJKB_VERSION_LEGACY);
    b.extend_from_slice(&iv);
    b.extend_from_slice(&(pj.len() as u32).to_be_bytes());
    b.extend_from_slice(&pj);
    b.extend_from_slice(&ct);
    assert_eq!(MajikFile::decrypt(&b, &id, None).unwrap(), TEXT);
}

// ── Compression ────────────────────────────────────────────────────────────

#[test]
fn zstd_roundtrip_across_levels() {
    let data: Vec<u8> = TEXT.iter().cycle().take(50_000).copied().collect();
    for level in [1, 3, 9, 19] {
        let c = MajikCompressor::compress(&data, Some(level)).unwrap();
        assert!(c.len() < data.len());
        assert_eq!(MajikCompressor::decompress(&c).unwrap(), data);
    }
}

#[test]
fn level_helpers() {
    assert_eq!(MajikCompressor::clamp_level(0), 1);
    assert_eq!(MajikCompressor::clamp_level(99), 22);
    assert_eq!(MajikCompressor::adaptive_level(&[0u8; 16], 22), 22);
    assert_eq!(MajikCompressor::compression_ratio_pct(100.0, 30.0), 70.0);
    assert_eq!(MajikCompressor::compression_ratio_pct(10.0, 30.0), 0.0);
}

#[test]
fn compress_rejects_empty() {
    assert_eq!(
        code(MajikCompressor::compress(&[], None).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
    assert_eq!(
        code(MajikCompressor::decompress(&[]).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
}

/// Trivial "codec" for exercising the pluggable path (identity transform).
struct XorCodec;
impl CompressionCodec for XorCodec {
    fn alg(&self) -> &str {
        "xor-test"
    }
    fn compress(&self, b: &[u8], _l: Option<i32>) -> Result<Vec<u8>> {
        Ok(b.iter().map(|x| x ^ 0x5a).collect())
    }
    fn decompress(&self, b: &[u8]) -> Result<Vec<u8>> {
        Ok(b.iter().map(|x| x ^ 0x5a).collect())
    }
}

#[test]
fn custom_codec_is_stamped_and_required_on_decrypt() {
    let id = test_identity("a");
    let mut o = opts(TEXT, &id);
    o.compressor = Some(Arc::new(XorCodec));
    let f = MajikFile::create(o).unwrap();
    assert_eq!(f.compression_alg(), Some("xor-test"));
    assert_eq!(
        decode_mjkb(f.to_mjkb().unwrap()).unwrap().payload.ca(),
        Some("xor-test")
    );

    // Without the codec → UNSUPPORTED_COMPRESSION_ALG
    let err = f.decrypt_binary(&id, None).unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::UnsupportedCompressionAlg);

    let opts_with = DecryptCompressionOptions {
        compressors: vec![Arc::new(XorCodec)],
    };
    assert_eq!(f.decrypt_binary(&id, Some(&opts_with)).unwrap(), TEXT);
}

// ── Serialization ──────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_with_and_without_binary() {
    let owner = test_identity("o");
    let r = test_identity("r");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&r)];
    o.compression_level = Some(CompressionPreset::GOOD);
    let f = MajikFile::create(o).unwrap();

    let json = f.to_json().unwrap();
    let text = serde_json::to_string(&json).unwrap();
    assert!(!text.contains("decrypted_base64"));

    let parsed: MajikFileJson = serde_json::from_str(&text).unwrap();
    let with_bin =
        MajikFile::from_json(parsed.clone(), Some(f.to_mjkb().unwrap().to_vec())).unwrap();
    assert!(with_bin.is_group()); // detected from the binary
    assert_eq!(with_bin.compression_level(), Some(9));
    assert_eq!(with_bin.decrypt_binary(&r, None).unwrap(), TEXT);

    let no_bin = MajikFile::from_json(parsed, None).unwrap();
    assert!(!no_bin.has_binary());
    assert_eq!(
        code(no_bin.decrypt_binary(&r, None).unwrap_err()),
        MajikFileErrorCode::MissingBinary
    );
}

#[test]
fn from_json_rejects_newer_schema_and_accepts_legacy_zero() {
    let id = test_identity("a");
    let f = MajikFile::create(opts(TEXT, &id)).unwrap();
    let mut j = f.to_json().unwrap();
    j.schema_version = FILE_SCHEMA_VERSION + 1;
    assert_eq!(
        code(MajikFile::from_json(j.clone(), None).unwrap_err()),
        MajikFileErrorCode::UnsupportedSchemaVersion
    );
    j.schema_version = LEGACY_SCHEMA_VERSION;
    assert!(MajikFile::from_json(j, None).is_ok());
}

#[test]
fn from_json_validates_required_fields() {
    let id = test_identity("a");
    let mut j = MajikFile::create(opts(TEXT, &id))
        .unwrap()
        .to_json()
        .unwrap();
    j.id = String::new();
    j.file_hash = String::new();
    let err = MajikFile::from_json(j, None).unwrap_err();
    assert_eq!(code(err), MajikFileErrorCode::ValidationError);
}

#[test]
fn dangerous_json_includes_plaintext_only_after_hydrate() {
    let id = test_identity("a");
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    assert!(f.to_dangerous_json().unwrap().decrypted_base64.is_none());
    f.decrypt_hydrate(&id, None).unwrap();
    let d = f.to_dangerous_json().unwrap();
    assert_eq!(base64_to_array(&d.decrypted_base64.unwrap()).unwrap(), TEXT);
}

// ── Hydration, batch, secure lock ──────────────────────────────────────────

#[test]
fn hydrate_then_secure_lock() {
    let id = test_identity("a");
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    assert!(!f.has_decrypted_file());
    f.decrypt_hydrate(&id, None).unwrap();
    assert_eq!(f.decrypted_file(), Some(TEXT));
    f.secure_lock();
    assert!(!f.has_decrypted_file());
}

#[test]
fn batch_decrypt_collects_errors_and_batch_lock_counts() {
    let me = test_identity("me");
    let other = test_identity("other");
    let mut mine = MajikFile::create(opts(TEXT, &me)).unwrap();
    mine.attach_binary(mine.to_mjkb().unwrap().to_vec()); // no-op re-attach
    let theirs = MajikFile::create(opts(b"not for me", &other)).unwrap();
    let theirs_id = theirs.id().to_string();

    let mut files = vec![mine, theirs];
    let ident: MajikFileDecryptIdentity = (&me).into();
    let res = MajikFile::batch_decrypt(&mut files, &ident, None).unwrap();

    assert!(!res.success);
    assert_eq!(res.decrypted.len(), 1);
    assert_eq!(res.errors.len(), 1);
    assert_eq!(res.errors[0].id, theirs_id);

    let lock = MajikFile::batch_lock(&mut files);
    assert_eq!((lock.locked, lock.skipped), (1, 1));
    assert!(!files[0].has_decrypted_file());
}

// ── Signatures ─────────────────────────────────────────────────────────────

#[test]
fn sign_attach_verify_remove() {
    let id = test_identity("a");
    let p = MockSignatures;
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    assert!(!f.is_signed());

    let sig = f
        .sign(&p, &"signer-A".to_string(), &SignOptions::default())
        .unwrap();
    assert!(f.is_signed());
    assert_eq!(f.signature_raw(), Some(sig.as_str()));

    let info = f.get_signature_info(&p).unwrap();
    assert_eq!(info.signer_id, "signer-A");
    assert_eq!(info.content_type.as_deref(), Some("text/plain")); // defaults to file mime

    assert_eq!(f.verify(&p, &"signer-A".to_string()).unwrap(), Some(true));
    assert_eq!(f.verify(&p, &"signer-B".to_string()).unwrap(), Some(false));
    assert!(f
        .verify_binary(&id, &p, &"signer-A".to_string(), None)
        .unwrap());

    f.remove_signature();
    assert!(!f.is_signed());
    assert_eq!(f.verify(&p, &"signer-A".to_string()).unwrap(), None);
}

#[test]
fn sign_requires_binary_and_attach_rejects_garbage() {
    let id = test_identity("a");
    let p = MockSignatures;
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    assert_eq!(
        code(f.attach_signature(&p, "").unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
    assert_eq!(
        code(f.attach_signature(&p, "%%%not-base64%%%").unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
    f.clear_binary();
    assert_eq!(
        code(
            f.sign(&p, &"s".to_string(), &SignOptions::default())
                .unwrap_err()
        ),
        MajikFileErrorCode::MissingBinary
    );
}

#[test]
fn create_and_sign_works() {
    let id = test_identity("a");
    let f = MajikFile::create_and_sign(
        opts(TEXT, &id),
        &MockSignatures,
        &"s".to_string(),
        &SignOptions::default(),
    )
    .unwrap();
    assert!(f.is_signed());
}

#[test]
fn signed_mjkb_trailer_roundtrip() {
    let id = test_identity("a");
    let p = MockSignatures;
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    assert_eq!(
        code(f.to_signed_mjkb(&p).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );

    f.sign(&p, &"signer-A".to_string(), &SignOptions::default())
        .unwrap();
    let signed = f.to_signed_mjkb(&p).unwrap();

    assert!(MajikFile::has_mjks_trailer(&signed));
    assert!(!MajikFile::has_mjks_trailer(f.to_mjkb().unwrap()));
    assert_eq!(MajikFile::strip_mjks_trailer(&signed), f.to_mjkb().unwrap());
    assert!(MajikFile::extract_mjks_signature(&signed, &p).is_some());

    assert!(MajikFile::verify_signed_mjkb(&signed, &p, &"signer-A".to_string()).unwrap());
    assert!(!MajikFile::verify_signed_mjkb(&signed, &p, &"signer-B".to_string()).unwrap());
    // Trailer-wrapped binaries still decrypt directly.
    assert_eq!(MajikFile::decrypt(&signed, &id, None).unwrap(), TEXT);
    // Unsigned input is rejected.
    assert_eq!(
        code(
            MajikFile::verify_signed_mjkb(f.to_mjkb().unwrap(), &p, &"x".to_string()).unwrap_err()
        ),
        MajikFileErrorCode::InvalidInput
    );
}

#[test]
fn tampered_signed_binary_fails_verification() {
    let id = test_identity("a");
    let p = MockSignatures;
    let mut f = MajikFile::create(opts(TEXT, &id)).unwrap();
    f.sign(&p, &"signer-A".to_string(), &SignOptions::default())
        .unwrap();
    let mut signed = f.to_signed_mjkb(&p).unwrap();
    signed[30] ^= 0xff; // inside the .mjkb body
    assert!(!MajikFile::verify_signed_mjkb(&signed, &p, &"signer-A".to_string()).unwrap());
}

// ── Ownership / participants / canDecrypt ──────────────────────────────────

#[test]
fn ownership_and_participant_checks() {
    let owner = test_identity("o");
    let r = test_identity("r");
    let stranger = test_identity("s");
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&r)];
    let f = MajikFile::create(o).unwrap();

    assert!(f.user_is_owner("user-1"));
    assert!(!f.user_is_owner("user-2"));
    assert!(!f.user_is_owner(" "));
    assert!(f.has_participant_access(&r.public_key));
    assert!(!f.has_participant_access(&stranger.public_key));
    assert!(f.can_decrypt(&(&r).into()));
    assert!(!f.can_decrypt(&(&stranger).into()));
    assert!(
        MajikFile::has_public_key_access(&owner.ml_kem_public_key, &owner.fingerprint).unwrap()
    );
    assert!(!MajikFile::has_public_key_access(&owner.ml_kem_public_key, &r.fingerprint).unwrap());
}

#[test]
fn can_decrypt_mjkb_paths() {
    let owner = test_identity("o");
    let r = test_identity("r");
    let stranger = test_identity("s");
    let default = CanDecryptMjkbOptions::default();
    let strict = CanDecryptMjkbOptions {
        strict: true,
        ..Default::default()
    };

    // group: fingerprint fast path
    let mut o = opts(TEXT, &owner);
    o.recipients = vec![as_recipient(&r)];
    let g = MajikFile::create(o).unwrap();
    let gb = g.to_mjkb().unwrap();
    assert!(MajikFile::can_decrypt_mjkb(
        gb,
        &r.fingerprint,
        None,
        &default
    ));
    assert!(!MajikFile::can_decrypt_mjkb(
        gb,
        &stranger.fingerprint,
        None,
        &default
    ));
    assert!(MajikFile::can_decrypt_mjkb(
        gb,
        &r.fingerprint,
        Some(&r.ml_kem_secret_key),
        &strict
    ));
    assert!(!MajikFile::can_decrypt_mjkb(
        gb,
        &r.fingerprint,
        Some(&stranger.ml_kem_secret_key),
        &strict
    ));

    // single: needs the secret key
    let s = MajikFile::create(opts(TEXT, &owner)).unwrap();
    let sb = s.to_mjkb().unwrap();
    assert!(!MajikFile::can_decrypt_mjkb(
        sb,
        &owner.fingerprint,
        None,
        &default
    ));
    assert!(MajikFile::can_decrypt_mjkb(
        sb,
        &owner.fingerprint,
        Some(&owner.ml_kem_secret_key),
        &default
    ));
    assert!(!MajikFile::can_decrypt_mjkb(
        sb,
        &stranger.fingerprint,
        Some(&stranger.ml_kem_secret_key),
        &default
    ));
    assert!(!MajikFile::can_decrypt_mjkb(
        b"garbage",
        &owner.fingerprint,
        None,
        &default
    ));
}

// ── Duplicates, stats, helpers ─────────────────────────────────────────────

#[test]
fn duplicate_detection() {
    let id = test_identity("a");
    let a = MajikFile::create(opts(TEXT, &id)).unwrap();
    let b = MajikFile::create(opts(TEXT, &id)).unwrap();
    let c = MajikFile::create(opts(b"different", &id)).unwrap();
    assert!(a.is_duplicate_of(&b));
    assert!(!a.is_duplicate_of(&c));
    assert!(MajikFile::would_be_duplicate(TEXT, a.file_hash()));
    assert_ne!(a.encryption_iv(), b.encryption_iv()); // fresh IV per encryption
}

#[test]
fn stats_and_size_helpers() {
    let id = test_identity("a");
    let data = vec![b'a'; 10_000];
    let f = MajikFile::create(opts(&data, &id)).unwrap();
    let s = f.get_stats();
    assert_eq!(s.size_original_human, "9.77 KB");
    assert!(s.compression_ratio_pct > 0.0);
    assert!(!s.is_signed && !s.is_group);
    assert!(f.exceeds_size(0.001).unwrap());
    assert!(!f.exceeds_size(1.0).unwrap());
    assert_eq!(
        code(f.exceeds_size(0.0).unwrap_err()),
        MajikFileErrorCode::InvalidInput
    );
    assert!(f.to_string().starts_with("MajikFile { id: "));
}

#[test]
fn util_helpers() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.00 KB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
    assert_eq!(
        infer_mime_type_from_filename("A.PNG").as_deref(),
        Some("image/png")
    );
    assert_eq!(infer_mime_type_from_filename("noext"), None);
    assert_eq!(infer_mime_type_from_filename("x.unknown"), None);
    assert!(should_compress_mime(None));
    assert!(should_compress_mime(Some("text/plain")));
    assert!(!should_compress_mime(Some("video/mp4")));
    assert!(!should_compress_mime(Some("image/jpeg")));
    assert!(is_mime_type_inline_viewable(Some("application/pdf")));
    assert!(!is_mime_type_inline_viewable(Some("application/zip")));
    assert_eq!(
        derive_filename("0123456789abcdef0123", Some("a.tar.gz")),
        "0123456789abcdef.gz"
    );
    assert_eq!(derive_filename("abc", None), "abc");
    assert_eq!(
        base64_to_array(&array_to_base64(&[1, 2, 3])).unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn ml_kem_primitives_roundtrip_and_sizes() {
    let kp = generate_ml_kem_keypair();
    assert_eq!(kp.public_key.len(), ML_KEM_PK_LEN);
    assert_eq!(kp.secret_key.len(), ML_KEM_SK_LEN);
    let enc = ml_kem_encapsulate(&kp.public_key).unwrap();
    assert_eq!(enc.cipher_text.len(), ML_KEM_CT_LEN);
    assert_eq!(enc.shared_secret.len(), AES_KEY_LEN);
    let ss = ml_kem_decapsulate(&enc.cipher_text, &kp.secret_key).unwrap();
    assert_eq!(*ss, *enc.shared_secret);
}

#[test]
fn aes_gcm_rejects_bad_lengths_and_auth_failure() {
    let key = vec![1u8; AES_KEY_LEN];
    let iv = vec![2u8; IV_LENGTH];
    assert!(aes_gcm_encrypt(&key[..16], &iv, b"x").is_err());
    assert!(aes_gcm_encrypt(&key, &iv[..8], b"x").is_err());
    let ct = aes_gcm_encrypt(&key, &iv, b"hello").unwrap();
    assert_eq!(
        aes_gcm_decrypt(&key, &iv, &ct).unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    let bad_key = vec![9u8; AES_KEY_LEN];
    assert!(aes_gcm_decrypt(&bad_key, &iv, &ct).unwrap().is_none());
}

#[test]
fn error_display_and_codes() {
    let e = MajikFileError::invalid_input("nope");
    assert_eq!(e.to_string(), "[INVALID_INPUT] nope");
    assert_eq!(
        MajikFileError::validation_failed(&["a".into(), "b".into()]).code,
        MajikFileErrorCode::ValidationError
    );
}
