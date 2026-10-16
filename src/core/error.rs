//! error.rs — mirrors `MajikFileError` / `MajikFileErrorCode` from error.ts.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MajikFileError>;
pub type ErrorCause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MajikFileErrorCode {
    InvalidInput,
    ValidationError,
    EncryptionFailed,
    DecryptionFailed,
    CompressionFailed,
    DecompressionFailed,
    FormatError,
    SizeExceeded,
    MissingBinary,
    UnsupportedVersion,
    UnsupportedSchemaVersion,
    UnsupportedCompressionAlg,
    LegacyMigrationFailed,
    StorageKeyMismatch,
}

impl MajikFileErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::ValidationError => "VALIDATION_ERROR",
            Self::EncryptionFailed => "ENCRYPTION_FAILED",
            Self::DecryptionFailed => "DECRYPTION_FAILED",
            Self::CompressionFailed => "COMPRESSION_FAILED",
            Self::DecompressionFailed => "DECOMPRESSION_FAILED",
            Self::FormatError => "FORMAT_ERROR",
            Self::SizeExceeded => "SIZE_EXCEEDED",
            Self::MissingBinary => "MISSING_BINARY",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::UnsupportedSchemaVersion => "UNSUPPORTED_SCHEMA_VERSION",
            Self::UnsupportedCompressionAlg => "UNSUPPORTED_COMPRESSION_ALG",
            Self::LegacyMigrationFailed => "LEGACY_MIGRATION_FAILED",
            Self::StorageKeyMismatch => "STORAGE_KEY_MISMATCH",
        }
    }
}

impl std::fmt::Display for MajikFileErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("[{code}] {message}")]
pub struct MajikFileError {
    pub code: MajikFileErrorCode,
    pub message: String,
    #[source]
    pub cause: Option<ErrorCause>,
}

impl MajikFileError {
    pub fn new(
        code: MajikFileErrorCode,
        message: impl Into<String>,
        cause: Option<ErrorCause>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            cause,
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(MajikFileErrorCode::InvalidInput, message, None)
    }

    pub fn validation_failed(errors: &[String]) -> Self {
        Self::new(
            MajikFileErrorCode::ValidationError,
            format!(
                "MajikFile validation failed:\n  • {}",
                errors.join("\n  • ")
            ),
            None,
        )
    }

    pub fn encryption_failed(cause: Option<ErrorCause>) -> Self {
        Self::new(
            MajikFileErrorCode::EncryptionFailed,
            "File encryption failed",
            cause,
        )
    }

    pub fn decryption_failed(message: impl Into<String>, cause: Option<ErrorCause>) -> Self {
        Self::new(MajikFileErrorCode::DecryptionFailed, message, cause)
    }

    pub fn compression_failed(cause: Option<ErrorCause>) -> Self {
        Self::new(
            MajikFileErrorCode::CompressionFailed,
            "File compression failed",
            cause,
        )
    }

    pub fn decompression_failed(cause: Option<ErrorCause>) -> Self {
        Self::new(
            MajikFileErrorCode::DecompressionFailed,
            "File decompression failed",
            cause,
        )
    }

    pub fn format_error(message: impl Into<String>) -> Self {
        Self::new(MajikFileErrorCode::FormatError, message, None)
    }

    pub fn size_exceeded(actual: usize, limit: usize) -> Self {
        Self::new(
            MajikFileErrorCode::SizeExceeded,
            format!(
                "File size {actual} bytes exceeds the {limit}-byte limit ({} MB). Set bypass_size_limit: true to override.",
                (limit as f64 / 1024.0 / 1024.0).round()
            ),
            None,
        )
    }

    pub fn missing_binary() -> Self {
        Self::new(
            MajikFileErrorCode::MissingBinary,
            "No encrypted binary available. Either create() the file or supply the binary to from_json() / attach_binary().",
            None,
        )
    }

    pub fn unsupported_version(version: u8, supported: u8) -> Self {
        Self::new(
            MajikFileErrorCode::UnsupportedVersion,
            format!("Unsupported .mjkb binary version: {version}. Only v{supported} (plus documented legacy versions) is supported."),
            None,
        )
    }

    pub fn unsupported_schema_version(version: u32, supported_max: u32) -> Self {
        Self::new(
            MajikFileErrorCode::UnsupportedSchemaVersion,
            format!(
                "Unsupported MajikFile record schema version: {version}. This SDK supports up to schema v{supported_max}. Upgrade the SDK, or this may be a legacy record — try from_legacy_json()."
            ),
            None,
        )
    }

    pub fn unsupported_compression_alg(alg: &str) -> Self {
        Self::new(
            MajikFileErrorCode::UnsupportedCompressionAlg,
            format!(
                "Unsupported compression algorithm: \"{alg}\". No matching CompressionCodec was found in the \"compressors\" option passed to this decrypt call."
            ),
            None,
        )
    }

    pub fn legacy_migration_failed(cause: Option<ErrorCause>) -> Self {
        Self::new(
            MajikFileErrorCode::LegacyMigrationFailed,
            "Failed to migrate a legacy MajikFile record to the current schema",
            cause,
        )
    }

    pub fn storage_key_mismatch(message: impl Into<String>) -> Self {
        Self::new(MajikFileErrorCode::StorageKeyMismatch, message, None)
    }
}
