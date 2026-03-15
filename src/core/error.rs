use thiserror::Error;

/// Error codes mirroring the TypeScript MajikFileErrorCode union.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl std::fmt::Display for MajikFileErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
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
        };
        write!(f, "{s}")
    }
}

/// Main error type — mirrors `MajikFileError` from TypeScript.
#[derive(Debug, Error)]
#[error("[{code}] {message}")]
pub struct MajikFileError {
    pub code: MajikFileErrorCode,
    pub message: String,
    #[source]
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl MajikFileError {
    fn new(
        code: MajikFileErrorCode,
        message: impl Into<String>,
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
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

    pub fn validation_failed(errors: Vec<String>) -> Self {
        let msg = format!(
            "MajikFile validation failed:\n  • {}",
            errors.join("\n  • ")
        );
        Self::new(MajikFileErrorCode::ValidationError, msg, None)
    }

    pub fn encryption_failed(cause: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::new(
            MajikFileErrorCode::EncryptionFailed,
            "File encryption failed",
            cause,
        )
    }

    pub fn decryption_failed(
        message: impl Into<String>,
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::new(MajikFileErrorCode::DecryptionFailed, message, cause)
    }

    pub fn compression_failed(cause: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::new(
            MajikFileErrorCode::CompressionFailed,
            "File compression failed",
            cause,
        )
    }

    pub fn decompression_failed(cause: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self {
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
        let msg = format!(
            "File size {} bytes exceeds the {}-byte limit ({} MB). \
             Set bypass_size_limit: true to override.",
            actual,
            limit,
            limit / 1024 / 1024
        );
        Self::new(MajikFileErrorCode::SizeExceeded, msg, None)
    }

    pub fn missing_binary() -> Self {
        Self::new(
            MajikFileErrorCode::MissingBinary,
            "No encrypted binary available. \
             Either create() the file or supply the binary to from_json() / attach_binary().",
            None,
        )
    }

    pub fn unsupported_version(version: u8, supported: u8) -> Self {
        let msg = format!("Unsupported .mjkb version: {version}. Only v{supported} is supported.");
        Self::new(MajikFileErrorCode::UnsupportedVersion, msg, None)
    }
}
