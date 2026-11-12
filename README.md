
# majik-file

[![Crates.io](https://img.shields.io/crates/v/majik-file.svg?logo=rust&color=D34516)](https://crates.io/crates/majik-file)
[![Documentation](https://docs.rs/majik-file/badge.svg)](https://docs.rs/majik-file)
[![License](https://img.shields.io/badge/License-Apache_2.0-D34516.svg)](https://opensource.org/licenses/Apache-2.0)

**Platform-agnostic post-quantum file encryption** for the Majikah ecosystem. This crate is the Rust port of [`@majikah/majik-file`](https://github.com/Majikah/majik-file). The TypeScript implementation is the behavioral and wire-format source of truth.

It creates self-contained `.mjkb` files using **ML-KEM-768 (FIPS 203) + AES-256-GCM**, with optional Zstandard compression. Encryption and decryption are offline.

## Compatibility contract

- New files use **MJKB v2** (format byte `0x02`).
- Existing **MJKB v1** files (format byte `0x01`) remain readable.
- The JSON record schema is independent of the binary version. Current records use `schema_version: 1`; an absent schema-version field is interpreted as legacy schema `0`.
- Legacy JSON records may omit `kem_alg` and `cipher_alg`. All pre-existing records used `ML-KEM-768` and `AES-256-GCM`, so Rust deserialization restores these historical defaults before file or nested stamp-row hydration.
- The binary is authoritative for the IV and compression flag/algorithm. The JSON record contains metadata, not the encrypted binary.
- TypeScript `MajikFile.toJSON()` omits `compression_alg`. Rust follows that serializer behavior; a custom codec identifier remains in the v2 binary payload's `ca` field.

The MJKB format version and JSON record schema version are separate axes. A v2 binary may be stored alongside a legacy schema-v0 JSON record.

## How encryption works

1. Hash the original plaintext with SHA-256 for stable deduplication.
2. Optionally preprocess through `MajikFileHooks`, then apply MIME-based Zstandard compression.
3. For a single recipient, use the ML-KEM shared secret directly as the AES-256-GCM key.
4. For group files, encrypt once with a random AES-256 key and wrap that key for each recipient using ML-KEM shared secrets.
5. Write the IV, payload JSON, and authenticated ciphertext into the `.mjkb` container.

The owner is always included as the first recipient. Duplicate recipient fingerprints and the owner's own fingerprint are removed while preserving first-occurrence order. The maximum is **32 additional recipients**, excluding the owner.

## MJKB binary format

The fixed header is 21 bytes:

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `MJKB` |
| 4 | 1 | Format version (`0x02` current; `0x01` legacy) |
| 5 | 12 | AES-GCM IV |
| 17 | 4 | Payload JSON byte length, big-endian uint32 |
| 21 | N | UTF-8 payload JSON |
| 21 + N | M | AES-GCM ciphertext, including the 16-byte authentication tag |

**Current v2 single-recipient payload:**

~~~json
{
  "mlKemCipherText": "<base64 ML-KEM-768 ciphertext>",
  "n": "report.pdf",
  "m": "application/pdf",
  "z": true
}
~~~

**Current v2 group payload:**

~~~json
{
  "keys": [
    {
      "fingerprint": "<base64 SHA-256 fingerprint>",
      "mlKemCipherText": "<base64 ML-KEM-768 ciphertext>",
      "encryptedAesKey": "<base64 32-byte wrapped AES key>"
    }
  ],
  "n": "report.pdf",
  "m": "application/pdf",
  "z": true
}
~~~

The optional v2 `ca` field identifies a non-default compression codec. An absent `ca` means `zstd`. Legacy v1 payloads used `c` instead of `z`; for those files, decompression is inferred from MIME type.

## Compression

The built-in codec is Zstandard, levels 1–22. When no level is supplied, level 22 is requested and capped using the same adaptive thresholds as TypeScript.

Compression is skipped for already-compressed MIME types: all `video/*` and `audio/*`; JPEG, WebP, AVIF, GIF, HEIC and HEIF images; and the archive MIME types listed by the TypeScript policy (including ZIP, 7z, RAR, gzip and Zstandard). Unknown or absent MIME types are compressed by default.

Custom codecs implement `CompressionCodec`. Their identifier is embedded in the v2 binary's `ca` field and must be supplied again when decrypting. The built-in `zstd` codec is always available.

## Installation

~~~toml
[dependencies]
majik-file = "1"
~~~

## Quick start

Use key material from your application's established Majik Key identity flow. Do not use placeholder key material in production.

~~~rust
use majik_file::{MajikFile, MajikFileCreateOptions};

let mut options =
    MajikFileCreateOptions::new(file_bytes, user_id, identity.clone());
options.original_name = Some("report.pdf".to_string());
options.mime_type = Some("application/pdf".to_string());

let file = MajikFile::create(options)?;
let encrypted_bytes = file.to_mjkb()?.to_vec();
let metadata = file.to_json()?;

// Store encrypted_bytes and metadata separately.
let recovered = file.decrypt_binary(&identity, None)?;
~~~

For a group file, populate `options.recipients` with `MajikFileRecipient` values before calling `MajikFile::create()`.

## Restoring metadata and legacy records

`MajikFile::from_json()` restores metadata and optionally attaches the separately stored binary:

~~~rust
let restored = MajikFile::from_json(metadata, Some(encrypted_bytes))?;
let plaintext = restored.decrypt_binary(&identity, None)?;
~~~

When deserializing a legacy JSON row, missing `schema_version` becomes the internal legacy marker `0`; missing crypto-suite identifiers become `ML-KEM-768` and `AES-256-GCM`. This includes nested `fileJson` objects in persisted signature-stamp records because they use the same `MajikFileJson` model.

A schema version newer than this crate supports returns `UnsupportedSchemaVersion`. Metadata can be restored without a binary, but binary-dependent methods return `MissingBinary` until one is attached.

## Main API

| API | Purpose |
| --- | --- |
| `MajikFile::create(options)` | Encrypt bytes and create a file instance |
| `MajikFile::decrypt(source, identity, options)` | Decrypt raw `.mjkb` bytes |
| `MajikFile::decrypt_with_metadata_from(...)` | Decrypt and return embedded name, MIME type and optional serialized signature |
| `MajikFile::from_json(json, binary)` | Restore metadata and optionally attach binary bytes |
| `file.to_json()` | Return metadata only; excludes binary and decrypted plaintext |
| `file.to_mjkb()` / `file.to_binary_bytes()` | Access the encrypted binary |
| `file.decrypt_hydrate(identity, options)` | Decrypt and cache plaintext |
| `file.secure_lock()` | Zeroize and clear cached plaintext |
| `MajikFile::batch_decrypt(...)` / `batch_lock(...)` | Hydrate or lock multiple instances |
| `file.get_stats()` | Return size, compression, group and signature metadata |
| `MajikFile::is_valid_mjkb(bytes)` | Check container structure without decrypting |

The crate also exposes validation, duplicate detection, MIME helpers, `can_decrypt_mjkb()` and signed-binary trailer helpers.

## Signature integration

TypeScript uses the concrete `MajikSignature` type. Rust keeps this crate independent of a specific signing implementation through the `SignatureProvider` trait. A provider supplies signing, verification, signature validation, metadata inspection and JSON conversion.

The file instance stores a serialized signature. `decrypt_with_metadata_from()` returns the serialized signature when one is supplied; it does not verify it. The `MJKS` trailer helpers allow a signed `.mjkb` binary to carry a serialized signature alongside the encrypted payload.

## Tauri integration

Enable the optional feature:

~~~toml
[dependencies]
majik-file = { version = "1", features = ["tauri"] }
tauri = "2"
~~~

The `tauri_commands` module exposes commands for encryption, decryption, test keypair generation, MIME inference, byte formatting, hashing and basic MJKB validation. See [src/tauri_commands.rs](src/tauri_commands.rs) for the request/result DTOs and registration example. The keypair-generation command is intended for testing; production identities should be managed by the application's key layer.

## Rust and TypeScript implementation differences

The persisted metadata contract and `.mjkb` wire format are kept compatible. Host-language and platform integration differ:

| TypeScript | Rust |
| --- | --- |
| `Blob`, `Uint8Array` or `ArrayBuffer` inputs | `&[u8]` / `Vec<u8>` |
| Browser `Blob` output | Borrowed encrypted bytes; clone when ownership is needed |
| Async WASM Zstandard initialization | Synchronous native Zstandard |
| Browser Canvas image conversion | Frontend preprocessing or a `MajikFileHooks` implementation |
| Concrete `MajikKey` accepted for decryption | `MajikFileDecryptIdentity` or borrowed `MajikFileIdentity` |
| Concrete `MajikSignature` type | Generic `SignatureProvider` abstraction |

Rust batch decryption is sequential because the crypto work is CPU-bound. Applications can parallelize independent files at the call site when appropriate.

## Error handling

Errors use `MajikFileError` and the same stable error-code vocabulary as TypeScript:

`INVALID_INPUT`, `VALIDATION_ERROR`, `ENCRYPTION_FAILED`, `DECRYPTION_FAILED`, `COMPRESSION_FAILED`, `DECOMPRESSION_FAILED`, `FORMAT_ERROR`, `SIZE_EXCEEDED`, `MISSING_BINARY`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SCHEMA_VERSION`, `UNSUPPORTED_COMPRESSION_ALG`, `LEGACY_MIGRATION_FAILED` and `STORAGE_KEY_MISMATCH`.

A wrong ML-KEM secret key normally produces a different shared secret rather than an ML-KEM error. AES-GCM authentication detects the mismatch and returns `DECRYPTION_FAILED`.

## Cryptographic parameters

| Primitive | Parameters |
| --- | --- |
| ML-KEM-768 (FIPS 203) | 1184-byte public key, 2400-byte expanded secret key, 1088-byte ciphertext |
| AES-256-GCM | 32-byte key, 12-byte IV, 16-byte authentication tag |
| SHA-256 | Original-file hash and public-key fingerprints |
| Zstandard | Levels 1–22; adaptive caps for large inputs |
| Randomness | Operating-system CSPRNG |

## Related projects

- [TypeScript source: Majikah/majik-file](https://github.com/Majikah/majik-file)
- [Majik Key](https://github.com/Majikah/majik-key)
- [Majik Signature](https://github.com/Majikah/majik-signature)

## License

Apache-2.0. See [LICENSE](LICENSE).
