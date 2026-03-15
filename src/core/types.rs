use serde::{Deserialize, Serialize};

/// String alias for a Majik Message public key (base64-encoded string).
pub type MajikMessagePublicKey = String;

// ─── Domain enums ─────────────────────────────────────────────────────────────

/// File usage context — mirrors `FileContext` in TypeScript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContext {
    UserUpload,
    ChatAttachment,
    /// Rasterised WebP image sent in a chat conversation.
    ChatImage,
    ThreadAttachment,
}

impl FileContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserUpload => "user_upload",
            Self::ChatAttachment => "chat_attachment",
            Self::ChatImage => "chat_image",
            Self::ThreadAttachment => "thread_attachment",
        }
    }
}

impl std::fmt::Display for FileContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Storage lifecycle — mirrors `StorageType` in TypeScript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    Permanent,
    Temporary,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent => write!(f, "permanent"),
            Self::Temporary => write!(f, "temporary"),
        }
    }
}

/// Allowed TTLs for temporary files in days — mirrors `TempFileDuration` in TypeScript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempFileDuration {
    One = 1,
    Two = 2,
    Three = 3,
    Five = 5,
    Seven = 7,
    Fifteen = 15,
}

impl TempFileDuration {
    pub fn days(self) -> i64 {
        self as i64
    }
}

impl Default for TempFileDuration {
    fn default() -> Self {
        Self::Fifteen
    }
}

// ─── Identities & Recipients ──────────────────────────────────────────────────

/// The file owner's full identity — carries both keys.
/// Mirrors `MajikFileIdentity` in TypeScript.
#[derive(Debug, Clone)]
pub struct MajikFileIdentity {
    /// Base64-encoded message public key string.
    pub public_key: MajikMessagePublicKey,
    /// Base64 SHA-256 of the ML-KEM public key.
    pub fingerprint: String,
    /// ML-KEM-768 public key (1184 bytes).
    pub ml_kem_public_key: Vec<u8>,
    /// ML-KEM-768 secret key (2400 bytes).
    pub ml_kem_secret_key: Vec<u8>,
}

/// A recipient who can decrypt the file.
/// Mirrors `MajikFileRecipient` in TypeScript.
#[derive(Debug, Clone)]
pub struct MajikFileRecipient {
    /// Base64 SHA-256 of the ML-KEM public key.
    pub fingerprint: String,
    pub public_key: MajikMessagePublicKey,
    /// ML-KEM-768 public key (1184 bytes).
    pub ml_kem_public_key: Vec<u8>,
}

// ─── Per-recipient key entry (group .mjkb) ────────────────────────────────────

/// Per-recipient encrypted key entry stored inside a group .mjkb binary.
/// Mirrors `MajikFileGroupKey` in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MajikFileGroupKey {
    /// Base64 SHA-256 fingerprint.
    pub fingerprint: String,
    /// Base64-encoded ML-KEM-768 ciphertext (1088 bytes).
    #[serde(rename = "mlKemCipherText")]
    pub ml_kem_cipher_text: String,
    /// Base64-encoded 32-byte encrypted AES key (groupAesKey XOR sharedSecret).
    #[serde(rename = "encryptedAesKey")]
    pub encrypted_aes_key: String,
}

// ─── .mjkb Payload Types ─────────────────────────────────────────────────────

/// JSON payload for a single-recipient .mjkb binary.
/// Mirrors `MjkbSinglePayload` in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MjkbSinglePayload {
    /// Base64-encoded ML-KEM-768 ciphertext (1088 bytes).
    #[serde(rename = "mlKemCipherText")]
    pub ml_kem_cipher_text: String,
    /// Original filename — short key `n` keeps the binary compact.
    pub n: Option<String>,
    /// Original MIME type — short key `m` keeps the binary compact.
    pub m: Option<String>,
    /// Usage context — short key `c`.
    pub c: Option<String>,
}

/// JSON payload for a group .mjkb binary.
/// Mirrors `MjkbGroupPayload` in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MjkbGroupPayload {
    /// Per-recipient key entries.
    pub keys: Vec<MajikFileGroupKey>,
    /// Original filename.
    pub n: Option<String>,
    /// Original MIME type.
    pub m: Option<String>,
    /// Usage context.
    pub c: Option<String>,
}

/// Discriminated union of the two payload types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MjkbPayload {
    Group(MjkbGroupPayload),
    Single(MjkbSinglePayload),
}

impl MjkbPayload {
    pub fn is_group(&self) -> bool {
        matches!(self, Self::Group(_))
    }

    pub fn is_single(&self) -> bool {
        matches!(self, Self::Single(_))
    }

    pub fn original_name(&self) -> Option<&str> {
        match self {
            Self::Single(p) => p.n.as_deref(),
            Self::Group(p) => p.n.as_deref(),
        }
    }

    pub fn mime_type(&self) -> Option<&str> {
        match self {
            Self::Single(p) => p.m.as_deref(),
            Self::Group(p) => p.m.as_deref(),
        }
    }

    pub fn context_str(&self) -> Option<&str> {
        match self {
            Self::Single(p) => p.c.as_deref(),
            Self::Group(p) => p.c.as_deref(),
        }
    }
}

// ─── MajikFileJSON ────────────────────────────────────────────────────────────

/// Serialised representation of a MajikFile — maps to the Supabase table.
/// Mirrors `MajikFileJSON` in TypeScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MajikFileJson {
    pub id: String,
    pub user_id: String,
    pub r2_key: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_original: u64,
    pub size_stored: u64,
    pub file_hash: String,
    /// Hex-encoded 12-byte AES-GCM IV.
    pub encryption_iv: String,
    pub storage_type: StorageType,
    pub is_shared: bool,
    pub share_token: Option<String>,
    pub context: Option<FileContext>,
    pub chat_message_id: Option<String>,
    pub thread_message_id: Option<String>,
    pub thread_id: Option<String>,
    pub participants: Vec<MajikMessagePublicKey>,
    pub conversation_id: Option<String>,
    pub expires_at: Option<String>,
    pub timestamp: Option<String>,
    pub last_update: Option<String>,
}

// ─── CreateOptions ────────────────────────────────────────────────────────────

/// Options for `MajikFile::create()`.
/// Mirrors `CreateOptions` in TypeScript.
pub struct CreateOptions {
    /// Raw binary content of the file to encrypt.
    pub data: Vec<u8>,
    /// UUID from auth.users — used for R2 key construction.
    pub user_id: String,
    /// Identity of the file owner.
    pub identity: MajikFileIdentity,
    /// Additional recipients beyond the owner (empty = single-recipient).
    pub recipients: Vec<MajikFileRecipient>,
    /// File context.
    pub context: FileContext,
    /// Original filename.
    pub original_name: Option<String>,
    /// MIME type string.
    pub mime_type: Option<String>,
    /// If true, stored under files/public/ and auto-deleted after TTL.
    pub is_temporary: bool,
    /// If true, a share_token can be generated.
    pub is_shared: bool,
    /// Pre-computed UUID for the record. None = auto-generate.
    pub id: Option<String>,
    /// Bypass the MAX_FILE_SIZE_BYTES (100 MB) limit.
    pub bypass_size_limit: bool,
    /// Temporary file duration. Required when is_temporary = true.
    pub expires_at: TempFileDuration,
    pub chat_message_id: Option<String>,
    pub thread_message_id: Option<String>,
    pub thread_id: Option<String>,
    /// Required when context is ChatImage.
    pub conversation_id: Option<String>,
    /// Zstd compression level 1–22. None = adaptive default (22, clamped).
    pub compression_level: Option<i32>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            user_id: String::new(),
            identity: MajikFileIdentity {
                public_key: String::new(),
                fingerprint: String::new(),
                ml_kem_public_key: Vec::new(),
                ml_kem_secret_key: Vec::new(),
            },
            recipients: Vec::new(),
            context: FileContext::UserUpload,
            original_name: None,
            mime_type: None,
            is_temporary: false,
            is_shared: false,
            id: None,
            bypass_size_limit: false,
            expires_at: TempFileDuration::Fifteen,
            chat_message_id: None,
            thread_message_id: None,
            thread_id: None,
            conversation_id: None,
            compression_level: None,
        }
    }
}

// ─── Decoded .mjkb Binary ─────────────────────────────────────────────────────

/// Internal representation of a fully parsed .mjkb binary.
pub struct DecodedMjkb {
    pub version: u8,
    /// IV extracted from the binary header.
    pub iv: Vec<u8>,
    /// AES-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// Parsed payload.
    pub payload: MjkbPayload,
}

// ─── File Stats ───────────────────────────────────────────────────────────────

/// Human-readable stats — mirrors `MajikFileStats` in TypeScript.
#[derive(Debug, Clone, Serialize)]
pub struct MajikFileStats {
    pub id: String,
    pub original_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_original_human: String,
    pub size_stored_human: String,
    pub compression_ratio_pct: f64,
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
