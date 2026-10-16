//! validator.rs — each rule is written once as `check_*` (returns the error
//! message) with an `assert_*` wrapper that fails fast.

use crate::core::crypto::constants::{FILE_SCHEMA_VERSION, ML_KEM_PK_LEN, ML_KEM_SK_LEN};
use crate::core::error::{MajikFileError, Result};

pub struct MajikFileValidator;

impl MajikFileValidator {
    /// Single VALIDATION_ERROR if `errors` is non-empty.
    pub fn assert_all(errors: &[String]) -> Result<()> {
        if errors.is_empty() {
            Ok(())
        } else {
            Err(MajikFileError::validation_failed(errors))
        }
    }

    fn required(v: Option<&str>, msg: &str) -> Option<String> {
        if v.map(|s| s.trim().is_empty()).unwrap_or(true) {
            Some(msg.to_string())
        } else {
            None
        }
    }

    pub fn check_id(id: Option<&str>) -> Option<String> {
        Self::required(id, "id is required")
    }
    pub fn assert_id(id: Option<&str>) -> Result<()> {
        Self::check_id(id).map_or(Ok(()), |e| Err(MajikFileError::invalid_input(e)))
    }
    pub fn check_user_id(user_id: Option<&str>) -> Option<String> {
        Self::required(user_id, "userId is required")
    }
    pub fn assert_user_id(user_id: Option<&str>) -> Result<()> {
        Self::check_user_id(user_id).map_or(Ok(()), |e| Err(MajikFileError::invalid_input(e)))
    }
    pub fn check_file_hash(hash: Option<&str>) -> Option<String> {
        Self::required(hash, "file_hash is required")
    }
    pub fn check_encryption_iv(iv: Option<&str>) -> Option<String> {
        Self::required(iv, "encryption_iv is required")
    }

    pub fn check_non_negative_size(size: f64, field_name: &str) -> Option<String> {
        if size >= 0.0 {
            None
        } else {
            Some(format!("{field_name} must be a non-negative number"))
        }
    }

    pub fn check_size_within_limit(
        byte_length: usize,
        limit: usize,
        bypass: bool,
    ) -> Option<String> {
        if bypass || byte_length <= limit {
            None
        } else {
            Some(format!(
                "size {byte_length} bytes exceeds the {limit}-byte limit"
            ))
        }
    }
    pub fn assert_size_within_limit(byte_length: usize, limit: usize, bypass: bool) -> Result<()> {
        if bypass || byte_length <= limit {
            Ok(())
        } else {
            Err(MajikFileError::size_exceeded(byte_length, limit))
        }
    }
    pub fn assert_non_empty_data(byte_length: usize) -> Result<()> {
        if byte_length == 0 {
            Err(MajikFileError::invalid_input("data must not be empty"))
        } else {
            Ok(())
        }
    }

    pub fn check_ml_kem_public_key(pk: Option<&[u8]>, field_name: &str) -> Option<String> {
        match pk {
            Some(p) if p.len() == ML_KEM_PK_LEN => None,
            Some(p) => Some(format!(
                "{field_name} must be a {ML_KEM_PK_LEN}-byte Uint8Array (got {})",
                p.len()
            )),
            None => Some(format!(
                "{field_name} must be a {ML_KEM_PK_LEN}-byte Uint8Array (got undefined)"
            )),
        }
    }
    pub fn assert_ml_kem_public_key(pk: Option<&[u8]>, field_name: &str) -> Result<()> {
        Self::check_ml_kem_public_key(pk, field_name)
            .map_or(Ok(()), |e| Err(MajikFileError::invalid_input(e)))
    }

    pub fn check_ml_kem_secret_key(sk: Option<&[u8]>, field_name: &str) -> Option<String> {
        match sk {
            Some(s) if s.len() == ML_KEM_SK_LEN => None,
            Some(s) => Some(format!(
                "{field_name} must be {ML_KEM_SK_LEN} bytes (got {})",
                s.len()
            )),
            None => Some(format!(
                "{field_name} must be {ML_KEM_SK_LEN} bytes (got undefined)"
            )),
        }
    }
    pub fn assert_ml_kem_secret_key(sk: Option<&[u8]>, field_name: &str) -> Result<()> {
        Self::check_ml_kem_secret_key(sk, field_name)
            .map_or(Ok(()), |e| Err(MajikFileError::invalid_input(e)))
    }

    pub fn check_recipient_limit(count: usize, max: usize) -> Option<String> {
        if count > max {
            Some(format!(
                "recipient count {count} exceeds the maximum of {max}"
            ))
        } else {
            None
        }
    }
    pub fn assert_recipient_limit(count: usize, max: usize) -> Result<()> {
        Self::check_recipient_limit(count, max)
            .map_or(Ok(()), |e| Err(MajikFileError::invalid_input(e)))
    }

    /// Version 0 = legacy (absent in JSON) — a migration concern, not a failure.
    pub fn check_schema_version(version: u32, supported_max: u32) -> Option<String> {
        if version > supported_max {
            Some(format!(
                "schema_version {version} is newer than this SDK supports (max {supported_max})"
            ))
        } else {
            None
        }
    }
    pub fn assert_schema_version(version: u32, supported_max: u32) -> Result<()> {
        if version > supported_max {
            Err(MajikFileError::unsupported_schema_version(
                version,
                supported_max,
            ))
        } else {
            Ok(())
        }
    }
    pub fn check_current_schema_version(version: u32) -> Option<String> {
        Self::check_schema_version(version, FILE_SCHEMA_VERSION)
    }

    /// Shared primitive reused by MajikMessageFileValidator.
    pub fn check_mutually_exclusive(
        a: bool,
        b: bool,
        label_a: &str,
        label_b: &str,
    ) -> Option<String> {
        if a && b {
            Some(format!("{label_a} and {label_b} cannot both be set"))
        } else {
            None
        }
    }
}
