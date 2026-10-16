//! Test helpers: key factory + a MOCK signature provider (the real
//! majik-signature has no Rust port yet). The mock is NOT cryptographically
//! secure — it only binds (signer, content hash) so MajikFile's plumbing
//! (attach / trailer / verify) can be exercised.

#![allow(dead_code)]

use ::majik_file::core::crypto::crypto_provider::*;
use ::majik_file::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};

pub fn test_identity(label: &str) -> MajikFileIdentity {
    let kp = generate_ml_kem_keypair();
    MajikFileIdentity {
        public_key: format!("pub-{label}-{}", generate_uuid()),
        fingerprint: sha256_base64(&kp.public_key),
        ml_kem_public_key: kp.public_key,
        ml_kem_secret_key: kp.secret_key,
    }
}

pub fn as_recipient(i: &MajikFileIdentity) -> MajikFileRecipient {
    MajikFileRecipient {
        fingerprint: i.fingerprint.clone(),
        public_key: i.public_key.clone(),
        ml_kem_public_key: i.ml_kem_public_key.clone(),
    }
}

pub fn opts(data: &[u8], identity: &MajikFileIdentity) -> MajikFileCreateOptions {
    let mut o = MajikFileCreateOptions::new(data.to_vec(), "user-1", identity.clone());
    o.original_name = Some("hello.txt".to_string());
    o
}

/// A signer is just a string id in the mock.
pub struct MockSignatures;

impl SignatureProvider for MockSignatures {
    type SigningKey = String;
    type Verifier = String; // expected signer id
    type Verification = bool;

    fn sign(&self, data: &[u8], key: &String, o: &SignOptions) -> Result<String> {
        let json = serde_json::json!({
            "signerId": key,
            "timestamp": o.timestamp.clone().unwrap_or_else(|| "2026-01-01T00:00:00.000Z".into()),
            "contentType": o.content_type,
            "contentHash": sha256_hex(data),
        });
        Ok(B64.encode(serde_json::to_vec(&json).unwrap()))
    }

    fn verify(&self, data: &[u8], serialized: &str, verifier: &String) -> Result<bool> {
        let info = self.info(serialized)?;
        Ok(info.signer_id == *verifier && info.content_hash == sha256_hex(data))
    }

    fn validate(&self, serialized: &str) -> Result<()> {
        self.info(serialized).map(|_| ())
    }

    fn info(&self, serialized: &str) -> Result<FileSignature> {
        let bytes = B64
            .decode(serialized)
            .map_err(|e| MajikFileError::invalid_input(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| MajikFileError::invalid_input(e.to_string()))
    }

    fn to_json(&self, serialized: &str) -> Result<serde_json::Value> {
        serde_json::to_value(self.info(serialized)?)
            .map_err(|e| MajikFileError::invalid_input(e.to_string()))
    }

    fn from_json(&self, json: &serde_json::Value) -> Result<String> {
        let info: FileSignature = serde_json::from_value(json.clone())
            .map_err(|e| MajikFileError::invalid_input(e.to_string()))?;
        Ok(B64.encode(serde_json::to_vec(&info).unwrap()))
    }
}
