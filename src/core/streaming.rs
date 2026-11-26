//! Bounded-memory MJKB v3 streaming encryption and decryption.
//!
//! v1/v2 remain handled by the legacy buffer APIs. V3 is a separate,
//! append-only chunk-record format: each record has its own AES-256-GCM tag,
//! and an authenticated final manifest binds the stream length and plaintext
//! SHA-256. The final manifest is mandatory; truncated streams are rejected.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};
use structured_zstd::decoding::StreamingDecoder;
use structured_zstd::encoding::{CompressionLevel as ZstdLevel, StreamingEncoder};
use zeroize::Zeroize;

use crate::core::crypto::constants::{
    AES_KEY_LEN, IV_LENGTH, MAX_GROUP_RECIPIENTS, MJKB_VERSION_STREAMING,
};
use crate::core::crypto::crypto_provider::{
    aes_gcm_decrypt_with_aad, aes_gcm_encrypt_with_aad, generate_random_bytes,
    ml_kem_encapsulate,
};
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::error::{MajikFileError, Result};
use crate::core::mjkb_codec::{
    resolve_aes_key_from_payload, MJKB_HEADER_LEN, MJKB_MAGIC,
};
use crate::core::types::{
    AnyMjkbPayload, MajikFileGroupKey, MajikFileRecipient, MajikFileEncryptionIdentity,
    MajikFileDecryptIdentity, MjkbGroupPayloadV3, MjkbPayloadV3, MjkbSinglePayloadV3,
};
use crate::core::utils::{
    array_to_base64, deduplicate_recipients, should_compress_mime,
};

pub const STREAM_SUITE_V3: &str = "AES-256-GCM-CHUNKED-1";
pub const DEFAULT_STREAM_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_STREAM_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_STREAM_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const MANIFEST_LEN: usize = 8 + 8 + 8 + 32;
const GCM_TAG_LEN: usize = 16;
const CHUNK_AAD_DOMAIN: &[u8] = b"MJKB3-CHUNK";
const MANIFEST_AAD_DOMAIN: &[u8] = b"MJKB3-MANIFEST";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingProgress {
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
}

/// Per-operation policy and callbacks. A None max_bytes means no file-size cap.
pub struct StreamingOptions<'a> {
    pub chunk_size: usize,
    /// None uses the existing MIME-based compression policy.
    pub compression: Option<bool>,
    pub compression_level: Option<i32>,
    pub total_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub cancellation: Option<&'a AtomicBool>,
    pub on_progress: Option<&'a mut dyn FnMut(StreamingProgress)>,
}

impl Default for StreamingOptions<'_> {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_STREAM_CHUNK_SIZE,
            compression: None,
            compression_level: Some(6),
            total_bytes: None,
            max_bytes: None,
            cancellation: None,
            on_progress: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingEncryptResult {
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub chunks: u64,
    pub file_hash: String,
    pub encryption_iv: String,
    pub participants: Vec<String>,
    pub is_group: bool,
    pub compression_alg: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamingDecryptResult {
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub chunks: u64,
    pub file_hash: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub payload: MjkbPayloadV3,
}

/// Encrypt any reader to a writer using the MJKB v3 chunked format.
/// The input and output are consumed incrementally; memory usage is bounded
/// by the configured chunk size and the Zstandard streaming window.
pub fn encrypt_reader_to_writer<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identity: &MajikFileEncryptionIdentity,
    recipients: &[MajikFileRecipient],
    original_name: Option<&str>,
    mime_type: Option<&str>,
    options: &mut StreamingOptions<'_>,
) -> Result<StreamingEncryptResult> {
    validate_chunk_size(options.chunk_size)?;
    if identity.fingerprint.trim().is_empty() {
        return Err(MajikFileError::invalid_input("identity.fingerprint is required"));
    }
    crate::core::validator::MajikFileValidator::assert_ml_kem_public_key(
        Some(&identity.ml_kem_public_key),
        "identity.mlKemPublicKey",
    )?;
    for (index, recipient) in recipients.iter().enumerate() {
        if recipient.fingerprint.trim().is_empty() {
            return Err(MajikFileError::invalid_input(format!(
                "recipients[{index}].fingerprint is required"
            )));
        }
        crate::core::validator::MajikFileValidator::assert_ml_kem_public_key(
            Some(&recipient.ml_kem_public_key),
            &format!("recipients[{index}].mlKemPublicKey"),
        )?;
    }

    let cleaned = deduplicate_recipients(recipients, &identity.fingerprint);
    crate::core::validator::MajikFileValidator::assert_recipient_limit(
        cleaned.len(),
        MAX_GROUP_RECIPIENTS,
    )?;

    let mut all = Vec::with_capacity(cleaned.len() + 1);
    all.push(MajikFileRecipient {
        fingerprint: identity.fingerprint.clone(),
        ml_kem_public_key: identity.ml_kem_public_key.clone(),
        public_key: identity.public_key.clone(),
    });
    all.extend(cleaned);
    let participants = all.iter().map(|item| item.public_key.clone()).collect::<Vec<_>>();
    let is_group = all.len() > 1;

    let compress = options.compression.unwrap_or_else(|| should_compress_mime(mime_type));
    let mut nonce_base = [0u8; IV_LENGTH];
    nonce_base.copy_from_slice(&generate_random_bytes(IV_LENGTH)?);

    let (aes_key, payload) = if !is_group {
        let encapsulation = ml_kem_encapsulate(&identity.ml_kem_public_key)?;
        (
            encapsulation.shared_secret,
            MjkbPayloadV3::Single(MjkbSinglePayloadV3 {
                ml_kem_cipher_text: array_to_base64(&encapsulation.cipher_text),
                n: original_name.map(str::to_string),
                m: mime_type.map(str::to_string),
                z: compress,
                ca: None,
                chunk_size: options.chunk_size as u32,
                stream_suite: STREAM_SUITE_V3.to_string(),
            }),
        )
    } else {
        let aes_key = Zeroizing::new(generate_random_bytes(AES_KEY_LEN)?);
        let mut keys = Vec::with_capacity(all.len());
        for recipient in &all {
            let encapsulation = ml_kem_encapsulate(&recipient.ml_kem_public_key)?;
            let mut wrapped = [0u8; AES_KEY_LEN];
            for index in 0..AES_KEY_LEN {
                wrapped[index] = aes_key[index] ^ encapsulation.shared_secret[index];
            }
            keys.push(MajikFileGroupKey {
                fingerprint: recipient.fingerprint.clone(),
                ml_kem_cipher_text: array_to_base64(&encapsulation.cipher_text),
                encrypted_aes_key: array_to_base64(&wrapped),
            });
        }
        (
            aes_key,
            MjkbPayloadV3::Group(MjkbGroupPayloadV3 {
                keys,
                n: original_name.map(str::to_string),
                m: mime_type.map(str::to_string),
                z: compress,
                ca: None,
                chunk_size: options.chunk_size as u32,
                stream_suite: STREAM_SUITE_V3.to_string(),
            }),
        )
    };

    let payload_json = serde_json::to_vec(&payload)
        .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
    let payload_len = u32::try_from(payload_json.len())
        .map_err(|_| MajikFileError::format_error("MJKB v3 payload is too large"))?;
    let payload_hash: [u8; 32] = Sha256::digest(&payload_json).into();

    write_encrypt(writer, &MJKB_MAGIC)?;
    write_encrypt(writer, &[MJKB_VERSION_STREAMING])?;
    write_encrypt(writer, &nonce_base)?;
    write_encrypt(writer, &payload_len.to_be_bytes())?;
    write_encrypt(writer, &payload_json)?;

    let mut chunk_writer = ChunkEncryptWriter::new(
        writer,
        &aes_key,
        nonce_base,
        payload_hash,
        options.chunk_size,
    );

    let mut hashing_reader = HashingReader::new(reader, options);
    if compress {
        let level = options.compression_level.unwrap_or(6).clamp(1, 22);
        let mut encoder = StreamingEncoder::new(
            &mut chunk_writer,
            ZstdLevel::from_level(level),
        );
        io::copy(&mut hashing_reader, &mut encoder)
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
        encoder
            .finish()
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
    } else {
        io::copy(&mut hashing_reader, &mut chunk_writer)
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
    }

    let (original_bytes, file_hash) = hashing_reader.finish()?;
    if original_bytes == 0 {
        return Err(MajikFileError::invalid_input("Cannot encrypt an empty stream"));
    }
    let (chunks, compressed_bytes) =
        chunk_writer.finish(original_bytes, file_hash)?;

    Ok(StreamingEncryptResult {
        original_bytes,
        compressed_bytes,
        chunks,
        file_hash: hex::encode(file_hash),
        encryption_iv: hex::encode(nonce_base),
        participants,
        is_group,
        compression_alg: if compress { Some("zstd".to_string()) } else { None },
    })
}

/// Decrypt an MJKB v3 reader into a writer. V1/v2 remain available through the
/// existing buffer-based API; this path intentionally refuses those formats.
pub fn decrypt_reader_to_writer<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    identity: MajikFileDecryptIdentity<'_>,
    options: &mut StreamingOptions<'_>,
) -> Result<StreamingDecryptResult> {
    let (nonce_base, payload_json, payload) = read_v3_header(reader)?;
    let chunk_size = payload.chunk_size() as usize;
    validate_chunk_size(chunk_size)?;
    if payload.stream_suite() != STREAM_SUITE_V3 {
        return Err(MajikFileError::format_error("Unsupported MJKB v3 stream suite"));
    }
    if payload.ca().is_some_and(|alg| alg != "zstd") {
        return Err(MajikFileError::unsupported_compression_alg(
            payload.ca().unwrap_or_default(),
        ));
    }

    let payload_hash: [u8; 32] = Sha256::digest(&payload_json).into();
    let any_payload = AnyMjkbPayload::V3(payload.clone());
    let aes_key = resolve_aes_key_from_payload(
        &any_payload,
        identity.fingerprint,
        identity.ml_kem_secret_key,
    )?;

    let mut chunk_reader = ChunkDecryptReader::new(
        reader,
        &aes_key,
        nonce_base,
        payload_hash,
        chunk_size,
        None,
    );
    let mut hashing_writer = HashingWriter::new(writer, options);

    if payload.z() {
        let mut decoder = StreamingDecoder::new(&mut chunk_reader);
        io::copy(&mut decoder, &mut hashing_writer)
            .map_err(|error| MajikFileError::decompression_failed(Some(Box::new(error))))?;
    } else {
        io::copy(&mut chunk_reader, &mut hashing_writer)
            .map_err(|error| MajikFileError::decryption_failed(
                "Failed while reading authenticated MJKB v3 chunks",
                Some(Box::new(error)),
            ))?;
    }

    let (original_bytes, file_hash) = hashing_writer.finish()?;
    let manifest = chunk_reader.manifest.as_ref().ok_or_else(|| {
        MajikFileError::format_error("MJKB v3 stream ended without an authenticated manifest")
    })?;
    if manifest.original_bytes != original_bytes || manifest.file_hash != file_hash {
        return Err(MajikFileError::decryption_failed(
            "MJKB v3 plaintext length or SHA-256 does not match its authenticated manifest",
            None,
        ));
    }

    Ok(StreamingDecryptResult {
        original_bytes,
        compressed_bytes: manifest.compressed_bytes,
        chunks: manifest.chunk_count,
        file_hash: hex::encode(file_hash),
        original_name: payload.n().map(str::to_string),
        mime_type: payload.m().map(str::to_string),
        payload,
    })
}

fn read_v3_header<R: Read>(reader: &mut R) -> Result<([u8; IV_LENGTH], Vec<u8>, MjkbPayloadV3)> {
    let mut header = [0u8; MJKB_HEADER_LEN];
    reader.read_exact(&mut header).map_err(|error| {
        MajikFileError::format_error(format!("Truncated MJKB header: {error}"))
    })?;
    if header[..4] != MJKB_MAGIC {
        return Err(MajikFileError::format_error("Missing MJKB magic bytes"));
    }
    if header[4] != MJKB_VERSION_STREAMING {
        return Err(MajikFileError::unsupported_version(header[4], MJKB_VERSION_STREAMING));
    }

    let mut nonce_base = [0u8; IV_LENGTH];
    nonce_base.copy_from_slice(&header[5..5 + IV_LENGTH]);
    let length_offset = 5 + IV_LENGTH;
    let payload_len = u32::from_be_bytes([
        header[length_offset],
        header[length_offset + 1],
        header[length_offset + 2],
        header[length_offset + 3],
    ]);
    if payload_len == 0 || payload_len > 1024 * 1024 {
        return Err(MajikFileError::format_error("Invalid MJKB v3 payload length"));
    }

    let mut payload_json = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload_json).map_err(|error| {
        MajikFileError::format_error(format!("Truncated MJKB v3 payload: {error}"))
    })?;
    let payload = serde_json::from_slice::<MjkbPayloadV3>(&payload_json)
        .map_err(|_| MajikFileError::format_error("Malformed MJKB v3 payload JSON"))?;
    Ok((nonce_base, payload_json, payload))
}

fn validate_chunk_size(chunk_size: usize) -> Result<()> {
    if !(MIN_STREAM_CHUNK_SIZE..=MAX_STREAM_CHUNK_SIZE).contains(&chunk_size) {
        return Err(MajikFileError::invalid_input(format!(
            "chunk_size must be between {MIN_STREAM_CHUNK_SIZE} and {MAX_STREAM_CHUNK_SIZE} bytes"
        )));
    }
    Ok(())
}

fn nonce_for(base: &[u8; IV_LENGTH], index: u64) -> [u8; IV_LENGTH] {
    let mut nonce = *base;
    for (target, counter) in nonce[4..].iter_mut().zip(index.to_be_bytes()) {
        *target ^= counter;
    }
    nonce
}

fn chunk_aad(payload_hash: &[u8; 32], index: u64, plaintext_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 32 + 8 + 4);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(payload_hash);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

fn manifest_aad(payload_hash: &[u8; 32], manifest: &[u8; MANIFEST_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MANIFEST_AAD_DOMAIN.len() + 32 + MANIFEST_LEN);
    aad.extend_from_slice(MANIFEST_AAD_DOMAIN);
    aad.extend_from_slice(payload_hash);
    aad.extend_from_slice(manifest);
    aad
}

fn write_encrypt<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes).map_err(|error| {
        MajikFileError::encryption_failed(Some(Box::new(error)))
    })
}

fn as_io_error(error: MajikFileError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

struct ChunkEncryptWriter<'a, W: Write> {
    writer: &'a mut W,
    key: &'a [u8],
    nonce_base: [u8; IV_LENGTH],
    payload_hash: [u8; 32],
    chunk_size: usize,
    buffer: Vec<u8>,
    chunk_count: u64,
    compressed_bytes: u64,
}

impl<'a, W: Write> ChunkEncryptWriter<'a, W> {
    fn new(
        writer: &'a mut W,
        key: &'a [u8],
        nonce_base: [u8; IV_LENGTH],
        payload_hash: [u8; 32],
        chunk_size: usize,
    ) -> Self {
        Self {
            writer,
            key,
            nonce_base,
            payload_hash,
            chunk_size,
            buffer: Vec::with_capacity(chunk_size),
            chunk_count: 0,
            compressed_bytes: 0,
        }
    }

    fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let plaintext_len = u32::try_from(self.buffer.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MJKB chunk is too large"))?;
        let nonce = nonce_for(&self.nonce_base, self.chunk_count);
        let aad = chunk_aad(&self.payload_hash, self.chunk_count, plaintext_len);
        let encrypted = aes_gcm_encrypt_with_aad(self.key, &nonce, &self.buffer, &aad)
            .map_err(as_io_error)?;
        let encrypted_len = u32::try_from(encrypted.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MJKB ciphertext chunk is too large"))?;
        self.writer.write_all(&encrypted_len.to_be_bytes())?;
        self.writer.write_all(&encrypted)?;
        self.chunk_count = self.chunk_count.checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MJKB chunk counter overflow"))?;
        self.compressed_bytes = self.compressed_bytes.checked_add(plaintext_len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MJKB stream length overflow"))?;
        self.buffer.zeroize();
        self.buffer.clear();
        Ok(())
    }

    fn finish(mut self, original_bytes: u64, file_hash: [u8; 32]) -> Result<(u64, u64)> {
        self.flush_chunk().map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;

        let mut manifest = [0u8; MANIFEST_LEN];
        manifest[0..8].copy_from_slice(&self.chunk_count.to_be_bytes());
        manifest[8..16].copy_from_slice(&self.compressed_bytes.to_be_bytes());
        manifest[16..24].copy_from_slice(&original_bytes.to_be_bytes());
        manifest[24..56].copy_from_slice(&file_hash);

        self.writer.write_all(&0u32.to_be_bytes())
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
        self.writer.write_all(&manifest)
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;

        let nonce = nonce_for(&self.nonce_base, self.chunk_count);
        let aad = manifest_aad(&self.payload_hash, &manifest);
        let tag = aes_gcm_encrypt_with_aad(self.key, &nonce, &[], &aad)?;
        self.writer.write_all(&tag)
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;
        self.writer.flush()
            .map_err(|error| MajikFileError::encryption_failed(Some(Box::new(error))))?;

        Ok((self.chunk_count, self.compressed_bytes))
    }
}

impl<W: Write> Write for ChunkEncryptWriter<'_, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let available = self.chunk_size - self.buffer.len();
        let accepted = available.min(input.len());
        self.buffer.extend_from_slice(&input[..accepted]);
        if self.buffer.len() == self.chunk_size {
            self.flush_chunk()?;
        }
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_chunk()?;
        self.writer.flush()
    }
}

#[derive(Debug, Clone)]
struct StreamManifest {
    chunk_count: u64,
    compressed_bytes: u64,
    original_bytes: u64,
    file_hash: [u8; 32],
}

struct ChunkDecryptReader<'a, R: Read> {
    reader: &'a mut R,
    key: &'a [u8],
    nonce_base: [u8; IV_LENGTH],
    payload_hash: [u8; 32],
    chunk_size: usize,
    chunk_count: u64,
    compressed_bytes: u64,
    buffer: Vec<u8>,
    offset: usize,
    manifest: Option<StreamManifest>,
    finished: bool,
    cancellation: Option<&'a AtomicBool>,
}

impl<'a, R: Read> ChunkDecryptReader<'a, R> {
    fn new(
        reader: &'a mut R,
        key: &'a [u8],
        nonce_base: [u8; IV_LENGTH],
        payload_hash: [u8; 32],
        chunk_size: usize,
        cancellation: Option<&'a AtomicBool>,
    ) -> Self {
        Self {
            reader,
            key,
            nonce_base,
            payload_hash,
            chunk_size,
            chunk_count: 0,
            compressed_bytes: 0,
            buffer: Vec::new(),
            offset: 0,
            manifest: None,
            finished: false,
            cancellation,
        }
    }

    fn read_next_record(&mut self) -> io::Result<()> {
        if self.cancellation.map(|flag| flag.load(Ordering::Acquire)).unwrap_or(false) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "MJKB decryption cancelled"));
        }
        let mut length_bytes = [0u8; 4];
        self.reader.read_exact(&mut length_bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(io::ErrorKind::UnexpectedEof, "MJKB v3 stream is missing its final manifest")
            } else {
                error
            }
        })?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length == 0 {
            let mut manifest_bytes = [0u8; MANIFEST_LEN];
            self.reader.read_exact(&mut manifest_bytes)?;
            let mut tag = [0u8; GCM_TAG_LEN];
            self.reader.read_exact(&mut tag)?;
            let aad = manifest_aad(&self.payload_hash, &manifest_bytes);
            let nonce = nonce_for(&self.nonce_base, self.chunk_count);
            let authenticated = aes_gcm_decrypt_with_aad(self.key, &nonce, &tag, &aad)
                .map_err(as_io_error)?;
            if authenticated.as_deref() != Some(&[][..]) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "MJKB v3 manifest authentication failed"));
            }

            let manifest = StreamManifest {
                chunk_count: u64::from_be_bytes(manifest_bytes[0..8].try_into().unwrap()),
                compressed_bytes: u64::from_be_bytes(manifest_bytes[8..16].try_into().unwrap()),
                original_bytes: u64::from_be_bytes(manifest_bytes[16..24].try_into().unwrap()),
                file_hash: manifest_bytes[24..56].try_into().unwrap(),
            };
            if manifest.chunk_count != self.chunk_count
                || manifest.compressed_bytes != self.compressed_bytes
            {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "MJKB v3 manifest does not match the chunk stream"));
            }

            let mut trailing = [0u8; 1];
            if self.reader.read(&mut trailing)? != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Unexpected trailing bytes after MJKB v3 manifest"));
            }
            self.manifest = Some(manifest);
            self.finished = true;
            return Ok(());
        }

        if length <= GCM_TAG_LEN || length > self.chunk_size + GCM_TAG_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid MJKB v3 chunk length"));
        }
        let mut ciphertext = vec![0u8; length];
        self.reader.read_exact(&mut ciphertext)?;
        let plaintext_len = u32::try_from(length - GCM_TAG_LEN)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "MJKB chunk length overflow"))?;
        let nonce = nonce_for(&self.nonce_base, self.chunk_count);
        let aad = chunk_aad(&self.payload_hash, self.chunk_count, plaintext_len);
        let plaintext = aes_gcm_decrypt_with_aad(self.key, &nonce, &ciphertext, &aad)
            .map_err(as_io_error)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MJKB v3 chunk authentication failed"))?;
        if plaintext.is_empty() || plaintext.len() > self.chunk_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid MJKB v3 plaintext chunk size"));
        }

        self.buffer.zeroize();
        self.buffer = plaintext;
        self.offset = 0;
        self.chunk_count = self.chunk_count.checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MJKB chunk counter overflow"))?;
        self.compressed_bytes = self.compressed_bytes.checked_add(plaintext_len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MJKB stream length overflow"))?;
        Ok(())
    }
}

impl<R: Read> Read for ChunkDecryptReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.offset < self.buffer.len() {
                let count = (self.buffer.len() - self.offset).min(output.len());
                output[..count].copy_from_slice(&self.buffer[self.offset..self.offset + count]);
                self.offset += count;
                return Ok(count);
            }
            if self.finished {
                return Ok(0);
            }
            self.read_next_record()?;
        }
    }
}

struct HashingReader<'r, 'o, R: Read> {
    reader: &'r mut R,
    options: &'r mut StreamingOptions<'o>,
    hasher: Sha256,
    bytes: u64,
}

impl<'r, 'o, R: Read> HashingReader<'r, 'o, R> {
    fn new(reader: &'r mut R, options: &'r mut StreamingOptions<'o>) -> Self {
        Self { reader, options, hasher: Sha256::new(), bytes: 0 }
    }

    fn finish(self) -> Result<(u64, [u8; 32])> {
        if let Some(expected) = self.options.total_bytes {
            if expected != self.bytes {
                return Err(MajikFileError::invalid_input(format!(
                    "Input stream length mismatch: expected {expected} bytes, read {}",
                    self.bytes
                )));
            }
        }
        if let Some(maximum) = self.options.max_bytes {
            if self.bytes > maximum {
                return Err(MajikFileError::size_exceeded(
                    usize::try_from(self.bytes).unwrap_or(usize::MAX),
                    usize::try_from(maximum).unwrap_or(usize::MAX),
                ));
            }
        }
        Ok((self.bytes, self.hasher.finalize().into()))
    }
}

impl<R: Read> Read for HashingReader<'_, '_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.options.cancellation.map(|flag| flag.load(Ordering::Acquire)).unwrap_or(false) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "MJKB encryption cancelled"));
        }
        let count = self.reader.read(output)?;
        if count == 0 {
            return Ok(0);
        }
        let next = self.bytes.checked_add(count as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Input byte count overflow"))?;
        if self.options.max_bytes.is_some_and(|maximum| next > maximum) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Input exceeds configured maximum"));
        }
        self.hasher.update(&output[..count]);
        self.bytes = next;
        if let Some(callback) = self.options.on_progress.as_deref_mut() {
            callback(StreamingProgress {
                bytes_processed: self.bytes,
                total_bytes: self.options.total_bytes,
            });
        }
        Ok(count)
    }
}

struct HashingWriter<'w, 'o, W: Write> {
    writer: &'w mut W,
    options: &'w mut StreamingOptions<'o>,
    hasher: Sha256,
    bytes: u64,
}

impl<'w, 'o, W: Write> HashingWriter<'w, 'o, W> {
    fn new(writer: &'w mut W, options: &'w mut StreamingOptions<'o>) -> Self {
        Self { writer, options, hasher: Sha256::new(), bytes: 0 }
    }

    fn finish(self) -> Result<(u64, [u8; 32])> {
        Ok((self.bytes, self.hasher.finalize().into()))
    }
}

impl<W: Write> Write for HashingWriter<'_, '_, W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.options.cancellation.map(|flag| flag.load(Ordering::Acquire)).unwrap_or(false) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "MJKB decryption cancelled"));
        }
        let next = self.bytes.checked_add(input.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Output byte count overflow"))?;
        if self.options.max_bytes.is_some_and(|maximum| next > maximum) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Decrypted output exceeds configured maximum"));
        }
        let count = self.writer.write(input)?;
        self.hasher.update(&input[..count]);
        self.bytes += count as u64;
        if let Some(callback) = self.options.on_progress.as_deref_mut() {
            callback(StreamingProgress {
                bytes_processed: self.bytes,
                total_bytes: self.options.total_bytes,
            });
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
