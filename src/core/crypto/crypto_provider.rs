//! crypto_provider.rs
//!
//! Encryption engine for MajikFile.
//! Provides AES-256-GCM and ML-KEM-768 (FIPS-203) primitives.
//!
//! Crate mapping vs TypeScript:
//!   @stablelib/aes + @stablelib/gcm  →  aes-gcm 0.10
//!   @noble/post-quantum ml_kem768    →  ml-kem 0.2.x  (2400-byte secret key, 1:1 compatible)
//!   crypto.getRandomValues()         →  OsRng via rand_core 0.6
//!
//! Method reference for ml-kem 0.2.x types:
//!   EncapsulationKey  / DecapsulationKey  →  EncodedSizeUser types  →  .as_bytes() / from_bytes()
//!   Ciphertext<P>     / SharedKey<P>      →  hybrid_array::Array    →  .as_slice()  / TryFrom

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::{OsRng, RngCore};

use crate::core::constants::{AES_KEY_LEN, IV_LENGTH, ML_KEM_CT_LEN, ML_KEM_PK_LEN, ML_KEM_SK_LEN};
use crate::core::error::MajikFileError;

// ─── Type aliases ─────────────────────────────────────────────────────────────

type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;
type Dk768 = <MlKem768 as KemCore>::DecapsulationKey;
type Ct768 = Ciphertext<MlKem768>;

// ─── Random bytes ─────────────────────────────────────────────────────────────

/// Generate cryptographically random bytes.
/// Mirrors `generateRandomBytes()` in TypeScript.
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, MajikFileError> {
    if len == 0 {
        return Err(MajikFileError::invalid_input(
            "generate_random_bytes: len must be > 0",
        ));
    }
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

/// Encrypt plaintext bytes with AES-256-GCM.
/// Output: ciphertext || 16-byte GCM auth tag — identical to @stablelib/gcm seal().
/// Mirrors `aesGcmEncrypt()` in TypeScript.
pub fn aes_gcm_encrypt(
    key_bytes: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, MajikFileError> {
    if key_bytes.len() != AES_KEY_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "aes_gcm_encrypt: key must be {AES_KEY_LEN} bytes (got {})",
            key_bytes.len()
        )));
    }
    if iv.len() != IV_LENGTH {
        return Err(MajikFileError::invalid_input(format!(
            "aes_gcm_encrypt: iv must be {IV_LENGTH} bytes (got {})",
            iv.len()
        )));
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, plaintext).map_err(|e| {
        MajikFileError::encryption_failed(Some(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))))
    })
}

/// Decrypt AES-256-GCM ciphertext.
/// Returns Ok(Some(plaintext)) on success, Ok(None) on auth failure.
/// Mirrors @stablelib/gcm `open()` returning null.
/// Mirrors `aesGcmDecrypt()` in TypeScript.
pub fn aes_gcm_decrypt(
    key_bytes: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>, MajikFileError> {
    if key_bytes.len() != AES_KEY_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "aes_gcm_decrypt: key must be {AES_KEY_LEN} bytes (got {})",
            key_bytes.len()
        )));
    }
    if iv.len() != IV_LENGTH {
        return Err(MajikFileError::invalid_input(format!(
            "aes_gcm_decrypt: iv must be {IV_LENGTH} bytes (got {})",
            iv.len()
        )));
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => Ok(Some(plaintext)),
        Err(_) => Ok(None),
    }
}

// ─── ML-KEM-768 ───────────────────────────────────────────────────────────────

/// ML-KEM-768 key encapsulation.
///
/// Accepts the recipient's 1184-byte public key.
/// Returns (shared_secret: 32 bytes, ciphertext: 1088 bytes).
/// Mirrors `mlKemEncapsulate()` in TypeScript.
pub fn ml_kem_encapsulate(
    recipient_public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), MajikFileError> {
    if recipient_public_key.len() != ML_KEM_PK_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_encapsulate: public key must be {ML_KEM_PK_LEN} bytes (got {})",
            recipient_public_key.len()
        )));
    }

    // Ek768 implements EncodedSizeUser → from_bytes() takes &[u8; 1184].into()
    let ek_bytes: &[u8; ML_KEM_PK_LEN] = recipient_public_key
        .try_into()
        .expect("length already validated");
    let ek = Ek768::from_bytes(ek_bytes.into());

    // encapsulate() returns (Ciphertext<MlKem768>, SharedKey<MlKem768>).
    // Both Ct768 and SharedKey are hybrid_array::Array<u8, N> — NOT EncodedSizeUser types.
    // Use .as_slice() to get &[u8] from them.
    let (ct, shared_secret): (Ct768, _) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| MajikFileError::encryption_failed(None))?;

    Ok((
        shared_secret.as_slice().to_vec(), // SharedKey  = Array<u8, U32>    → 32 bytes
        ct.as_slice().to_vec(),            // Ciphertext = Array<u8, U1088>  → 1088 bytes
    ))
}

/// ML-KEM-768 key decapsulation.
///
/// Accepts the 1088-byte ciphertext and the 2400-byte secret key.
/// The 2400-byte format is identical to @noble/post-quantum ml_kem768.
///
/// IMPORTANT: ML-KEM decapsulation NEVER fails on a wrong key — it returns
/// garbage bytes. The AES-GCM auth tag catches this (aes_gcm_decrypt → None).
/// Mirrors `mlKemDecapsulate()` in TypeScript.
pub fn ml_kem_decapsulate(
    cipher_text: &[u8],
    recipient_secret_key: &[u8],
) -> Result<Vec<u8>, MajikFileError> {
    if cipher_text.len() != ML_KEM_CT_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_decapsulate: ciphertext must be {ML_KEM_CT_LEN} bytes (got {})",
            cipher_text.len()
        )));
    }
    if recipient_secret_key.len() != ML_KEM_SK_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_decapsulate: secret key must be {ML_KEM_SK_LEN} bytes (got {})",
            recipient_secret_key.len()
        )));
    }

    // Dk768 implements EncodedSizeUser → from_bytes() takes &[u8; 2400].into()
    let dk_bytes: &[u8; ML_KEM_SK_LEN] = recipient_secret_key
        .try_into()
        .expect("length already validated");
    let dk = Dk768::from_bytes(dk_bytes.into());

    // Ct768 = Array<u8, CiphertextSize> — NOT an EncodedSizeUser type.
    // TryFrom<&[u8]> is the correct (non-deprecated) constructor.
    let ct_bytes: &[u8; ML_KEM_CT_LEN] = cipher_text.try_into().expect("length already validated");
    let ct = Ct768::try_from(ct_bytes.as_ref())
        .expect("ct_bytes is ML_KEM_CT_LEN bytes; validated above");

    // decapsulate() returns SharedKey<MlKem768> = Array<u8, U32>.
    // Use .as_slice() — it is an Array, NOT an EncodedSizeUser type.
    let shared_secret: ml_kem::SharedKey<MlKem768> = dk
        .decapsulate(&ct)
        .map_err(|_| MajikFileError::decryption_failed("ML-KEM decapsulation failed", None))?;

    Ok(shared_secret.as_slice().to_vec()) // SharedKey = Array<u8, U32> → 32 bytes
}

/// Generate a random ML-KEM-768 keypair.
///
/// Returns (public_key: Vec<u8>, secret_key: Vec<u8>) where:
///   public_key  = 1184 bytes  (EncapsulationKey — share with recipients)
///   secret_key  = 2400 bytes  (DecapsulationKey — keep private)
///
/// Sizes match @noble/post-quantum ml_kem768.keygen() exactly:
///   { publicKey: Uint8Array(1184), secretKey: Uint8Array(2400) }
///
/// Mirrors `generateMlKemKeypair()` in TypeScript.
pub fn generate_ml_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    // MlKem768::generate() → (DecapsulationKey, EncapsulationKey) — dk FIRST, ek SECOND.
    let (dk, ek): (Dk768, Ek768) = MlKem768::generate(&mut OsRng);

    // Both Dk768 and Ek768 implement EncodedSizeUser → .as_bytes() returns &Encoded<Self>
    // which derefs to &[u8]. Return (public_key, secret_key) to match TypeScript convention.
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}
