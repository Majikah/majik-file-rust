# majik-file

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)



Post-quantum file encryption for the Majik Message platform. Produces self-contained `.mjkb` binary files — sealed with **ML-KEM-768 + AES-256-GCM**, optionally Zstd-compressed, readable without any network access.

This is the **Rust port** of the [`@majikah/majik-file`](https://www.npmjs.com/package/@majikah/majik-file) TypeScript library. The `.mjkb` binary format is fully compatible — files encrypted by the TypeScript library can be decrypted by this crate and vice versa.

Designed for use in **Tauri desktop applications** and other native Rust environments where the TypeScript library cannot run.

[![Crates.io](https://img.shields.io/crates/v/majik-file)](https://crates.io/crates/majik-file) ![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/majik-file) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Rust](https://img.shields.io/badge/Rust-1.75+-orange)

---

## Contents

- [majik-file](#majik-file)
  - [Contents](#contents)
  - [How it works](#how-it-works)
  - [The .mjkb binary format](#the-mjkb-binary-format)
  - [Encryption modes](#encryption-modes)
    - [Single-recipient](#single-recipient)
    - [Group](#group)
  - [Compression behaviour](#compression-behaviour)
  - [Crate vs npm dependency mapping](#crate-vs-npm-dependency-mapping)
  - [Installation](#installation)
  - [Quick start](#quick-start)
    - [Encrypt a file (single recipient / self)](#encrypt-a-file-single-recipient--self)
    - [Decrypt a file](#decrypt-a-file)
    - [Encrypt for multiple recipients (group)](#encrypt-for-multiple-recipients-group)
    - [Temporary files](#temporary-files)
  - [Tauri integration](#tauri-integration)
  - [API reference](#api-reference)
    - [`MajikFile::create(options)`](#majikfilecreateoptions)
      - [`CreateOptions`](#createoptions)
    - [`MajikFile::decrypt`](#majikfiledecrypt)
    - [`MajikFile::decrypt_with_metadata`](#majikfiledecrypt_with_metadata)
    - [`MajikFile::from_json`](#majikfilefrom_json)
    - [Instance methods](#instance-methods)
    - [Instance getters](#instance-getters)
    - [Static helpers](#static-helpers)
  - [Type reference](#type-reference)
    - [`MajikFileIdentity`](#majikfileidentity)
    - [`MajikFileRecipient`](#majikfilerecipient)
    - [`FileContext`](#filecontext)
    - [`StorageType`](#storagetype)
    - [`TempFileDuration`](#tempfileduration)
    - [`MajikFileJson`](#majikfilejson)
    - [`MajikFileStats`](#majikfilestats)
  - [Error handling](#error-handling)
    - [Error codes](#error-codes)
  - [Differences from the TypeScript library](#differences-from-the-typescript-library)
  - [Storage model](#storage-model)
  - [Cryptographic parameters](#cryptographic-parameters)
  - [Related projects](#related-projects)
    - [majik-file (TypeScript / npm)](#majik-file-typescript--npm)
    - [Majik Message](#majik-message)
    - [Majik Key](#majik-key)
    - [Majik Envelope](#majik-envelope)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)

---

## How it works

```
raw bytes
  │
  ├─ SHA-256 hash (pre-compression — used for dedup)
  │
  ├─ Zstd compress at level 22
  │   Skipped for pre-compressed formats (JPEG, WebP, AVIF, video, audio, archives, Office XML)
  │   Note: WebP conversion is intentionally omitted (browser Canvas API only).
  │         Convert images to WebP on the frontend before passing to this library.
  │
  ├─ [single recipient]
  │   ML-KEM-768 encapsulate(ownerPublicKey)
  │   → sharedSecret (32 bytes) used directly as AES-256-GCM key
  │
  ├─ [group — 2+ recipients]
  │   Random 32-byte AES key encrypts the file once
  │   Per recipient: ML-KEM-768 encapsulate(recipientPublicKey)
  │   → encryptedAesKey = aesKey XOR sharedSecret
  │
  └─ AES-256-GCM encrypt (12-byte random IV, 16-byte auth tag)
       → .mjkb binary
```

The encrypted binary is self-contained: the IV, all key material, original filename, and MIME type are embedded inside the file. No sidecar files or database records are required to decrypt.

---

## The .mjkb binary format

Version: `0x01`

```
┌────────────────────────────────────────────────────────────────────┐
│  4 bytes  │  Magic: ASCII "MJKB"  (0x4D 0x4A 0x4B 0x42)           │
│  1 byte   │  Version (currently 0x01)                               │
│ 12 bytes  │  AES-GCM IV (random per file)                           │
│  4 bytes  │  Payload JSON length (big-endian uint32)                │
│  N bytes  │  Payload JSON (UTF-8)                                   │
│  M bytes  │  AES-GCM ciphertext (compressed plaintext + 16-byte tag)│
└────────────────────────────────────────────────────────────────────┘

Fixed header: 21 bytes (before variable payload JSON)
```

**Single-recipient payload JSON:**
```json
{
  "mlKemCipherText": "<base64, 1088 bytes>",
  "n": "photo.png",
  "m": "image/png",
  "c": "user_upload"
}
```

**Group payload JSON:**
```json
{
  "keys": [
    {
      "fingerprint": "<base64 SHA-256 of public key>",
      "mlKemCipherText": "<base64, 1088 bytes>",
      "encryptedAesKey": "<base64, 32 bytes>"
    }
  ],
  "n": "photo.png",
  "m": "image/png",
  "c": "user_upload"
}
```

`n`, `m`, and `c` use short keys to minimise binary overhead. All fields are `Option<String>` — `None` when encryption was called without providing `original_name` / `mime_type`.

---

## Encryption modes

### Single-recipient

Used when `recipients` is empty after deduplication. The ML-KEM shared secret is used directly as the AES-256-GCM key. The owner is the only entity who can decrypt.

### Group

Used when one or more `recipients` are supplied. The file is encrypted once with a random 32-byte AES key. Each recipient — including the owner, who is always prepended automatically — gets their own ML-KEM encapsulation entry:

```
encryptedAesKey = groupAesKey XOR mlKemSharedSecret
```

This is safe because ML-KEM shared secrets are 32 uniformly random bytes, making the XOR a one-time pad for the group key. Each recipient can independently recover `groupAesKey` using only their own secret key.

**Recipient deduplication:** If the owner's own fingerprint appears in `recipients`, it is silently removed. Duplicate fingerprints are also deduplicated — first occurrence wins.

**Limit:** Maximum 100 recipients (excluding the owner). Exceeding this returns `MajikFileError::invalid_input(...)`.

---

## Compression behaviour

Zstd compression at level 22 is applied selectively:

| Skipped (already compressed)         | Compressed with Zstd lv.22 |
| ------------------------------------ | -------------------------- |
| JPEG, WebP, AVIF, HEIC, HEIF, JXL    | PNG, BMP, TIFF, SVG, GIF   |
| All video (mp4, webm, mkv, mov, …)   | WAV, FLAC, AIFF            |
| Lossy audio (mp3, aac, ogg, opus, …) | PDF, JSON, XML, CSV        |
| ZIP, gzip, 7z, rar, bzip2, xz, zstd  | Plain text, source code    |
| .docx, .xlsx, .pptx, .epub           | SQLite databases           |

If `mime_type` is `None` or unknown, compression is applied (safer default).

---

## Crate vs npm dependency mapping

| TypeScript (npm)                    | Rust (crate)       | Notes                                 |
| ----------------------------------- | ------------------ | ------------------------------------- |
| `@noble/post-quantum` ml_kem768     | `ml-kem 0.2.1`     | Identical 2400-byte secret key format |
| `@stablelib/aes` + `@stablelib/gcm` | `aes-gcm 0.10`     | Identical ciphertext-then-tag output  |
| `@stablelib/sha256`                 | `sha2 0.10`        | Same SHA-256 output                   |
| `@bokuweb/zstd-wasm`                | `zstd 0.13`        | Same Zstd algorithm, same levels 1–22 |
| `crypto.getRandomValues()`          | `rand_core::OsRng` | OS CSPRNG, same security              |
| `crypto.randomUUID()`               | `uuid 1` (v4)      | Same UUID v4 format                   |
| `btoa` / `atob`                     | `base64 0.22`      | Standard base64, identical encoding   |

> **Key format compatibility:** `ml-kem 0.2.x` uses the **2400-byte expanded decapsulation key** format — the same format as `@noble/post-quantum`. Files encrypted by either library are fully interchangeable.

---

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
majik-file = "0.0.1"
```

For Tauri projects, add to `src-tauri/Cargo.toml`.

---

## Quick start

### Encrypt a file (single recipient / self)

```rust
use majik_file::{MajikFile, CreateOptions, FileContext, MajikFileIdentity};

// Identity comes from your key store — this library does not generate or persist keys.
// In production, derive keys from a BIP-39 mnemonic using Majik Key.
let identity = MajikFileIdentity {
    public_key: "base64-pubkey-string".to_string(),
    fingerprint: "base64-sha256-of-ml-kem-public-key".to_string(),
    ml_kem_public_key: vec![0u8; 1184], // 1184-byte ML-KEM-768 public key
    ml_kem_secret_key: vec![0u8; 2400], // 2400-byte ML-KEM-768 secret key
};

let file_bytes: Vec<u8> = std::fs::read("photo.png")?;

let majik_file = MajikFile::create(CreateOptions {
    data: file_bytes,
    user_id: "user-uuid".to_string(),
    identity,
    context: FileContext::UserUpload,
    original_name: Some("photo.png".to_string()),
    mime_type: Some("image/png".to_string()),
    ..Default::default()
})?;

// Export the encrypted binary — upload this to R2
let mjkb_bytes: Vec<u8> = majik_file.to_mjkb()?;

// Export metadata — insert this into Supabase
let metadata = majik_file.to_json()?;
let json_string = serde_json::to_string(&metadata)?;
```

### Decrypt a file

```rust
use majik_file::MajikFile;

let mjkb_bytes: Vec<u8> = fetch_from_r2(&r2_key).await?;

let (bytes, original_name, mime_type) = MajikFile::decrypt_with_metadata(
    &mjkb_bytes,
    &identity.fingerprint,
    &identity.ml_kem_secret_key,
)?;

println!("Decrypted {} bytes", bytes.len());
println!("File: {:?}, MIME: {:?}", original_name, mime_type);
```

### Encrypt for multiple recipients (group)

```rust
use majik_file::{MajikFile, CreateOptions, FileContext, MajikFileRecipient};

let majik_file = MajikFile::create(CreateOptions {
    data: file_bytes,
    user_id: "owner-uuid".to_string(),
    identity: sender_identity,
    context: FileContext::ChatAttachment,
    original_name: Some("report.pdf".to_string()),
    mime_type: Some("application/pdf".to_string()),
    recipients: vec![
        MajikFileRecipient {
            fingerprint: "recipient-a-fingerprint".to_string(),
            public_key: "recipient-a-pubkey".to_string(),
            ml_kem_public_key: recipient_a_key,
        },
        MajikFileRecipient {
            fingerprint: "recipient-b-fingerprint".to_string(),
            public_key: "recipient-b-pubkey".to_string(),
            ml_kem_public_key: recipient_b_key,
        },
    ],
    ..Default::default()
})?;
```

Any of the three principals (sender, recipient A, recipient B) can decrypt using only their own `ml_kem_secret_key`.

### Temporary files

```rust
use majik_file::{MajikFile, CreateOptions, FileContext, TempFileDuration};

let majik_file = MajikFile::create(CreateOptions {
    data: file_bytes,
    user_id: "user-uuid".to_string(),
    identity,
    context: FileContext::UserUpload,
    is_temporary: true,
    expires_at: TempFileDuration::Seven, // 7 days
    ..Default::default()
})?;
```

---

## Tauri integration

Register the Tauri commands in your `src-tauri/src/main.rs`:

```rust
use majik_file::{MajikFile, CreateOptions, FileContext, MajikFileIdentity};

#[tauri::command]
fn encrypt_file(
    data: Vec<u8>,
    user_id: String,
    fingerprint: String,
    public_key: String,
    ml_kem_public_key: Vec<u8>,
    ml_kem_secret_key: Vec<u8>,
    original_name: Option<String>,
    mime_type: Option<String>,
) -> Result<(Vec<u8>, serde_json::Value), String> {
    let identity = MajikFileIdentity {
        public_key,
        fingerprint,
        ml_kem_public_key,
        ml_kem_secret_key,
    };

    let file = MajikFile::create(CreateOptions {
        data,
        user_id,
        identity,
        context: FileContext::UserUpload,
        original_name,
        mime_type,
        ..Default::default()
    })
    .map_err(|e| e.to_string())?;

    let mjkb = file.to_mjkb().map_err(|e| e.to_string())?;
    let meta = file.to_json().map_err(|e| e.to_string())?;
    let meta_json = serde_json::to_value(&meta).map_err(|e| e.to_string())?;

    Ok((mjkb, meta_json))
}

#[tauri::command]
fn decrypt_file(
    mjkb_bytes: Vec<u8>,
    fingerprint: String,
    ml_kem_secret_key: Vec<u8>,
) -> Result<(Vec<u8>, Option<String>, Option<String>), String> {
    MajikFile::decrypt_with_metadata(&mjkb_bytes, &fingerprint, &ml_kem_secret_key)
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![encrypt_file, decrypt_file])
        .run(tauri::generate_context!())
        .unwrap();
}
```

**TypeScript frontend:**

```typescript
import { invoke } from '@tauri-apps/api/core';

// Encrypt
const [mjkbBytes, metadata] = await invoke<[number[], object]>('encrypt_file', {
  data: Array.from(fileBytes),
  userId: currentUser.id,
  fingerprint: identity.fingerprint,
  publicKey: identity.publicKey,
  mlKemPublicKey: Array.from(identity.mlKemPublicKey),
  mlKemSecretKey: Array.from(identity.mlKemSecretKey),
  originalName: file.name,
  mimeType: file.type,
});

// Decrypt
const [bytes, originalName, mimeType] = await invoke<[number[], string | null, string | null]>(
  'decrypt_file',
  {
    mjkbBytes: Array.from(await fetchFromR2(r2Key)),
    fingerprint: identity.fingerprint,
    mlKemSecretKey: Array.from(identity.mlKemSecretKey),
  }
);
```

> **Note on WebP conversion:** The TypeScript library converts chat images to WebP using the browser's Canvas API before encryption. This Rust library does not perform image conversion — it operates on raw bytes only. If you need WebP normalisation for `chat_image` / `chat_attachment` contexts, perform the conversion on the frontend before calling the Tauri command.

---

## API reference

### `MajikFile::create(options)`

```rust
pub fn create(options: CreateOptions) -> Result<MajikFile, MajikFileError>
```

Encrypts raw bytes and returns a `MajikFile` instance with the `.mjkb` binary and all metadata populated.

#### `CreateOptions`

| Field               | Type                      | Required | Description                                                           |
| ------------------- | ------------------------- | -------- | --------------------------------------------------------------------- |
| `data`              | `Vec<u8>`                 | ✓        | Raw file bytes to encrypt                                             |
| `user_id`           | `String`                  | ✓        | Owner's auth UUID                                                     |
| `identity`          | `MajikFileIdentity`       | ✓        | Owner's full identity (both keys)                                     |
| `context`           | `FileContext`             | ✓        | `UserUpload` \| `ChatAttachment` \| `ChatImage` \| `ThreadAttachment` |
| `recipients`        | `Vec<MajikFileRecipient>` | —        | Additional recipients. Empty → single-recipient mode                  |
| `original_name`     | `Option<String>`          | —        | Original filename. Embedded in `.mjkb` payload                        |
| `mime_type`         | `Option<String>`          | —        | MIME type. Inferred from `original_name` extension if omitted         |
| `is_temporary`      | `bool`                    | —        | Default `false`. Routes to `files/public/` R2 prefix                  |
| `is_shared`         | `bool`                    | —        | Default `false`                                                       |
| `id`                | `Option<String>`          | —        | Pre-computed UUID. Auto-generated if `None`                           |
| `bypass_size_limit` | `bool`                    | —        | Default `false`. Bypasses the 100 MB cap                              |
| `expires_at`        | `TempFileDuration`        | —        | Required when `is_temporary = true`                                   |
| `chat_message_id`   | `Option<String>`          | —        | Mutually exclusive with `thread_message_id`                           |
| `thread_message_id` | `Option<String>`          | —        | Mutually exclusive with `chat_message_id`                             |
| `thread_id`         | `Option<String>`          | —        |                                                                       |
| `conversation_id`   | `Option<String>`          | —        | Required when `context = ChatImage`                                   |
| `compression_level` | `Option<i32>`             | —        | Zstd level 1–22. `None` = adaptive default                            |

### `MajikFile::decrypt`

```rust
pub fn decrypt(
    source: &[u8],
    fingerprint: &str,
    ml_kem_secret_key: &[u8],
) -> Result<Vec<u8>, MajikFileError>
```

Decrypts a `.mjkb` binary and returns the raw plaintext bytes. Does not return filename or MIME type — use `decrypt_with_metadata` if you need those.

**Note on wrong keys:** ML-KEM decapsulation never errors on a wrong key — it silently returns a garbage shared secret. AES-GCM authentication detects this and causes `MajikFileError` with code `DecryptionFailed`.

### `MajikFile::decrypt_with_metadata`

```rust
pub fn decrypt_with_metadata(
    source: &[u8],
    fingerprint: &str,
    ml_kem_secret_key: &[u8],
) -> Result<(Vec<u8>, Option<String>, Option<String>), MajikFileError>
```

Returns `(bytes, original_name, mime_type)`. Preferred for UI use — no second parse of the binary required.

`original_name` and `mime_type` will be `None` for files encrypted without those fields. Implement fallbacks accordingly.

### `MajikFile::from_json`

```rust
pub fn from_json(
    json: MajikFileJson,
    binary: Option<Vec<u8>>,
) -> Result<MajikFile, MajikFileError>
```

Restores a `MajikFile` from a Supabase row. Binary is optional — if `None`, calling `to_mjkb()` or `decrypt_binary()` will return `MajikFileError::missing_binary()`. R2 prefix validation is intentionally skipped to tolerate rows from older schema versions.

### Instance methods

| Method                                       | Returns                                  | Description                                           |
| -------------------------------------------- | ---------------------------------------- | ----------------------------------------------------- |
| `to_json()`                                  | `Result<MajikFileJson, MajikFileError>`  | Serialise metadata for Supabase. Binary excluded      |
| `to_mjkb()`                                  | `Result<Vec<u8>, MajikFileError>`        | Export encrypted binary as owned bytes for R2 upload  |
| `to_binary_bytes()`                          | `Result<&[u8], MajikFileError>`          | Borrow encrypted binary bytes                         |
| `decrypt_binary(fp, sk)`                     | `Result<Vec<u8>, MajikFileError>`        | Decrypt in-memory binary. Errors if binary not loaded |
| `validate()`                                 | `Result<(), MajikFileError>`             | Validate all metadata invariants. Collects all errors |
| `attach_binary(binary)`                      | `()`                                     | Load or replace the encrypted binary                  |
| `clear_binary()`                             | `()`                                     | Free the in-memory binary after upload                |
| `toggle_sharing(token)`                      | `Result<Option<String>, MajikFileError>` | Toggle share token on/off                             |
| `user_is_owner(user_id)`                     | `bool`                                   | Check if `user_id` matches this file's owner          |
| `exceeds_size(limit_mb)`                     | `Result<bool, MajikFileError>`           | True if original size exceeds the given MB limit      |
| `is_duplicate_of(other)`                     | `bool`                                   | Compare by SHA-256 `file_hash`                        |
| `get_stats()`                                | `MajikFileStats`                         | Human-readable stats snapshot                         |
| `bind_to_thread_mail(thread_id, msg_id)`     | `Result<(), MajikFileError>`             | Bind once-only — errors if already bound              |
| `bind_to_chat_conversation(conv_id, msg_id)` | `Result<(), MajikFileError>`             | Bind once-only — errors if already bound              |
| `set_permanent()`                            | `Result<(), MajikFileError>`             | Switch to permanent storage, rebuild R2 key           |
| `set_temporary(duration)`                    | `Result<(), MajikFileError>`             | Switch to temporary storage, rebuild R2 key           |

### Instance getters

| Getter                                                | Type                   | Description                                     |
| ----------------------------------------------------- | ---------------------- | ----------------------------------------------- |
| `id()`                                                | `&str`                 | UUID primary key                                |
| `user_id()`                                           | `&str`                 | Owner's auth UUID                               |
| `r2_key()`                                            | `&str`                 | Full R2 object key                              |
| `original_name()`                                     | `Option<&str>`         | Original filename                               |
| `mime_type()`                                         | `Option<&str>`         | Resolved MIME type                              |
| `size_original()`                                     | `u64`                  | Plaintext byte length                           |
| `size_stored()`                                       | `u64`                  | `.mjkb` byte length                             |
| `size_kb()` / `size_mb()` / `size_gb()` / `size_tb()` | `f64`                  | Original size in various units (3 dp)           |
| `file_hash()`                                         | `&str`                 | SHA-256 hex of original bytes (pre-compression) |
| `encryption_iv()`                                     | `&str`                 | Hex-encoded IV (audit record)                   |
| `storage_type()`                                      | `&StorageType`         | `Permanent` or `Temporary`                      |
| `is_shared()`                                         | `bool`                 | Whether sharing is enabled                      |
| `share_token()`                                       | `Option<&str>`         | Active share token                              |
| `has_share_token()`                                   | `bool`                 | `share_token().is_some()`                       |
| `context()`                                           | `Option<&FileContext>` | File context                                    |
| `is_group()`                                          | `bool`                 | Multiple recipient key entries                  |
| `is_single()`                                         | `bool`                 | `!is_group()`                                   |
| `is_expired()`                                        | `bool`                 | Whether `expires_at` is in the past             |
| `is_temporary()`                                      | `bool`                 | `storage_type == Temporary`                     |
| `is_inline_viewable()`                                | `bool`                 | Whether MIME type renders inline in a browser   |
| `safe_filename()`                                     | `String`               | `<file_hash><ext>` — safe download name         |
| `has_binary()`                                        | `bool`                 | Whether encrypted binary is loaded in memory    |

### Static helpers

| Method                                       | Returns                        | Description                                        |
| -------------------------------------------- | ------------------------------ | -------------------------------------------------- |
| `MajikFile::build_expiry_date(days)`         | `String`                       | ISO-8601 expiry from a `TempFileDuration`          |
| `MajikFile::format_bytes(bytes)`             | `String`                       | Human-readable size (e.g. `"4.2 MB"`)              |
| `MajikFile::infer_mime_type(filename)`       | `Option<&'static str>`         | MIME from file extension                           |
| `MajikFile::is_mjkb_candidate(data)`         | `bool`                         | Magic byte check — does not fully parse            |
| `MajikFile::is_valid_mjkb(data)`             | `bool`                         | Full structural validation without decrypting      |
| `MajikFile::has_public_key_access(pk, fp)`   | `Result<bool, MajikFileError>` | SHA-256 fingerprint match — not a decryption proof |
| `MajikFile::would_be_duplicate(bytes, hash)` | `bool`                         | Pre-flight dedup check by SHA-256                  |
| `MajikFile::get_raw_file_size(data)`         | `usize`                        | Byte length of a slice                             |

---

## Type reference

### `MajikFileIdentity`

```rust
pub struct MajikFileIdentity {
    pub public_key: String,           // base64-encoded message public key string
    pub fingerprint: String,          // base64 SHA-256 of ml_kem_public_key
    pub ml_kem_public_key: Vec<u8>,   // 1184 bytes — used during encryption
    pub ml_kem_secret_key: Vec<u8>,   // 2400 bytes — used during decryption
}
```

### `MajikFileRecipient`

```rust
pub struct MajikFileRecipient {
    pub fingerprint: String,          // base64 SHA-256 of ml_kem_public_key
    pub public_key: String,           // base64-encoded message public key string
    pub ml_kem_public_key: Vec<u8>,   // 1184 bytes — secret key never leaves the device
}
```

### `FileContext`

```rust
pub enum FileContext {
    UserUpload,        // general file vault
    ChatAttachment,    // message attachment
    ChatImage,         // inline chat image — requires conversation_id
    ThreadAttachment,  // thread attachment
}
```

### `StorageType`

```rust
pub enum StorageType {
    Permanent,   // files/user/<userId>/<hash>.mjkb
    Temporary,   // files/public/<duration>/<userId>_<hash>.mjkb
}
```

### `TempFileDuration`

```rust
pub enum TempFileDuration {
    One = 1,
    Two = 2,
    Three = 3,
    Five = 5,
    Seven = 7,
    Fifteen = 15,  // default
}
```

### `MajikFileJson`

Serialises to a struct matching the `majikah.majik_files` Supabase table. Derives `serde::Serialize` and `serde::Deserialize`. The encrypted binary is intentionally absent — it lives in R2.

### `MajikFileStats`

```rust
pub struct MajikFileStats {
    pub id: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_original_human: String,    // e.g. "4.2 MB"
    pub size_stored_human: String,      // e.g. "1.1 MB"
    pub compression_ratio_pct: f64,     // percentage reduction, clamped to 0
    pub file_hash: String,
    pub storage_type: StorageType,
    pub is_group: bool,
    pub context: Option<FileContext>,
    pub is_shared: bool,
    pub is_expired: bool,
    pub expires_at: Option<String>,
    pub timestamp: Option<String>,
    pub r2_key: String,
}
```

---

## Error handling

All errors are instances of `MajikFileError`:

```rust
use majik_file::{MajikFile, MajikFileError, MajikFileErrorCode};

match MajikFile::create(options) {
    Ok(file) => { /* ... */ }
    Err(e) => {
        eprintln!("code:    {}", e.code);
        eprintln!("message: {}", e.message);
        if let Some(cause) = &e.cause {
            eprintln!("cause:   {cause}");
        }
    }
}
```

### Error codes

| Code                  | When returned                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `InvalidInput`        | Missing required fields, wrong key sizes, incompatible options, recipient limit exceeded   |
| `ValidationError`     | `validate()` found inconsistent state (all violations collected before returning)          |
| `EncryptionFailed`    | Unexpected error during the crypto or compression pipeline                                 |
| `DecryptionFailed`    | Wrong key (AES-GCM auth tag mismatch), missing fingerprint in group key list, corrupt data |
| `CompressionFailed`   | Zstd compression error                                                                     |
| `DecompressionFailed` | Zstd decompression error                                                                   |
| `FormatError`         | Magic byte mismatch, truncated binary, malformed payload JSON                              |
| `SizeExceeded`        | `data.len() > 100 MB` and `bypass_size_limit` is false                                     |
| `MissingBinary`       | `to_mjkb()`, `to_binary_bytes()`, or `decrypt_binary()` called when binary is `None`       |
| `UnsupportedVersion`  | `.mjkb` version byte is not `0x01`                                                         |

**Important:** A wrong decryption key does not return `InvalidInput` — it surfaces as `DecryptionFailed` via AES-GCM authentication failure. This is by design: ML-KEM decapsulation is deterministic and never errors on bad input.

---

## Differences from the TypeScript library

This Rust port is intentionally faithful to the TypeScript original. The `.mjkb` binary format is identical and files are fully interchangeable. However, a small number of browser-specific features are not applicable in a native context:

| Feature               | TypeScript                          | Rust                              |
| --------------------- | ----------------------------------- | --------------------------------- |
| WebP image conversion | ✓ via Canvas API                    | Not ported — browser only         |
| `Blob` input type     | ✓                                   | Not applicable — use `&[u8]`      |
| `fromJSONWithBlob()`  | ✓                                   | Not ported — no `Blob` type       |
| `toMJKB()` returns    | `Blob`                              | `Vec<u8>`                         |
| `decrypt()` accepts   | `Blob \| Uint8Array \| ArrayBuffer` | `&[u8]`                           |
| `async` / `await`     | All methods async                   | Synchronous (no `async` required) |

**WebP conversion:** The TypeScript library re-encodes chat images to WebP before encryption. If you want equivalent behaviour in a Tauri app, perform the WebP conversion on the frontend (using the existing TypeScript library or the browser Canvas API) before passing bytes to the Tauri command.

---

## Storage model

This library produces two artefacts that must be stored separately:

| Artefact                      | What it is       | Where it goes                        |
| ----------------------------- | ---------------- | ------------------------------------ |
| `to_mjkb()` → `Vec<u8>`       | Encrypted binary | Cloudflare R2 at `r2_key()`          |
| `to_json()` → `MajikFileJson` | Metadata record  | Supabase `majikah.majik_files` table |

The library does **not** perform R2 uploads or Supabase inserts itself.

**R2 key structure:**

```
Permanent:  files/user/<userId>/<fileHash>.mjkb
Temporary:  files/public/<duration>/<userId>_<fileHash>.mjkb
Chat image: images/chats/<conversationId>/<userId>_<fileHash>.mjkb
```

**File immutability:** `.mjkb` files are write-once. There is no update or patch operation. To replace a file, delete the R2 object and Supabase row, then call `MajikFile::create()` again.

---

## Cryptographic parameters

| Primitive             | Parameters                                | Role                                             |
| --------------------- | ----------------------------------------- | ------------------------------------------------ |
| ML-KEM-768 (FIPS 203) | PK: 1184 B, SK: 2400 B, CT: 1088 B        | Key encapsulation — post-quantum                 |
| AES-256-GCM           | 32-byte key, 12-byte IV, 16-byte auth tag | Symmetric authenticated encryption               |
| Zstd                  | Level 22 (maximum, adaptive)              | Pre-encryption compression                       |
| SHA-256               | —                                         | File deduplication hash, public key fingerprints |
| CSPRNG                | `rand_core::OsRng`                        | IV generation, group AES key generation          |

ML-KEM-768 provides NIST security category 3. The hybrid construction (ML-KEM for key encapsulation + AES-256-GCM for bulk encryption) means security is bounded by both primitives.

---

## Related projects

### [majik-file (TypeScript / npm)](https://www.npmjs.com/package/@majikah/majik-file)
The original TypeScript library this crate ports. Produces compatible `.mjkb` files.

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys and Majik File.

### [Majik Key](https://majikah.solutions/sdk/majik-key)
BIP-39 seed phrase account library for ML-KEM-768 + X25519 key derivation.

### [Majik Envelope](https://majikah.solutions/sdk/majik-envelope)
Post-quantum message encryption (text/string payloads — the message equivalent of this library).

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome.

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

**Developer:** Josef Elijah Fabian  
**GitHub:** [https://github.com/jedlsf](https://github.com/jedlsf)  
**Business Email:** [business@thezelijah.world](mailto:business@thezelijah.world)  
**Website:** [https://www.thezelijah.world](https://www.thezelijah.world)