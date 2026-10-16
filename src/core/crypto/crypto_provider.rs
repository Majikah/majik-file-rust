//! crypto_provider.rs — AES-256-GCM + ML-KEM-768 primitives.
//!
//! @stablelib/aes+gcm → aes-gcm 0.10 · @noble/post-quantum → ml-kem 0.2.x
//! (2400-byte expanded secret key) · crypto.getRandomValues → OsRng.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::{OsRng, RngCore};

use crate::core::crypto::constants::{
    AES_KEY_LEN, IV_LENGTH, ML_KEM_CT_LEN, ML_KEM_PK_LEN, ML_KEM_SK_LEN,
};
use crate::core::crypto::zeroize::Zeroizing;
use crate::core::error::{MajikFileError, Result};

type Ek768 = <MlKem768 as KemCore>::EncapsulationKey;
type Dk768 = <MlKem768 as KemCore>::DecapsulationKey;
type Ct768 = Ciphertext<MlKem768>;

/// Result of an ML-KEM encapsulation. Named fields (not a tuple) so the
/// ciphertext/secret order can never be swapped at a call site.
pub struct MlKemEncapsulation {
    pub shared_secret: Zeroizing<Vec<u8>>,
    pub cipher_text: Vec<u8>,
}

/// Rust-side addition (keygen lives in `@majikah/majik-key` in TS).
pub struct MlKemKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Zeroizing<Vec<u8>>,
}

// ─── Random ─────────────────────────────────────────────────────────────────

pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Err(MajikFileError::invalid_input(
            "generate_random_bytes: len must be a positive integer (got 0)",
        ));
    }
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

// ─── AES-256-GCM ────────────────────────────────────────────────────────────

fn check_key_iv(fn_name: &str, key: &[u8], iv: &[u8]) -> Result<()> {
    if key.len() != AES_KEY_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "{fn_name}: key must be {AES_KEY_LEN} bytes (got {})",
            key.len()
        )));
    }
    if iv.len() != IV_LENGTH {
        return Err(MajikFileError::invalid_input(format!(
            "{fn_name}: iv must be {IV_LENGTH} bytes (got {})",
            iv.len()
        )));
    }
    Ok(())
}

/// Output: ciphertext || 16-byte GCM tag (same as stablelib `seal`).
pub fn aes_gcm_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    check_key_iv("aes_gcm_encrypt", key, iv)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(iv), plaintext)
        .map_err(|e| {
            MajikFileError::encryption_failed(Some(Box::new(std::io::Error::other(e.to_string()))))
        })
}

/// `Ok(None)` on authentication failure (stablelib `open` returning null).
pub fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
    check_key_iv("aes_gcm_decrypt", key, iv)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    Ok(cipher.decrypt(Nonce::from_slice(iv), ciphertext).ok())
}

// ─── ML-KEM-768 ─────────────────────────────────────────────────────────────

pub fn ml_kem_encapsulate(recipient_public_key: &[u8]) -> Result<MlKemEncapsulation> {
    if recipient_public_key.len() != ML_KEM_PK_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_encapsulate: public key must be {ML_KEM_PK_LEN} bytes (got {})",
            recipient_public_key.len()
        )));
    }
    let ek_bytes: &[u8; ML_KEM_PK_LEN] = recipient_public_key.try_into().expect("length validated");
    let ek = Ek768::from_bytes(ek_bytes.into());

    // encapsulate() returns (Ciphertext, SharedKey) — ciphertext FIRST.
    let (ct, shared): (Ct768, _) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| MajikFileError::encryption_failed(None))?;

    Ok(MlKemEncapsulation {
        shared_secret: Zeroizing::new(shared.as_slice().to_vec()),
        cipher_text: ct.as_slice().to_vec(),
    })
}

/// NEVER fails on a wrong key (returns a garbage secret) — AES-GCM auth
/// catches it downstream.
pub fn ml_kem_decapsulate(
    cipher_text: &[u8],
    recipient_secret_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if cipher_text.len() != ML_KEM_CT_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_decapsulate: cipherText must be {ML_KEM_CT_LEN} bytes (got {})",
            cipher_text.len()
        )));
    }
    if recipient_secret_key.len() != ML_KEM_SK_LEN {
        return Err(MajikFileError::invalid_input(format!(
            "ml_kem_decapsulate: secret key must be {ML_KEM_SK_LEN} bytes (got {})",
            recipient_secret_key.len()
        )));
    }
    let dk_bytes: &[u8; ML_KEM_SK_LEN] = recipient_secret_key.try_into().expect("length validated");
    let dk = Dk768::from_bytes(dk_bytes.into());
    let ct = Ct768::try_from(cipher_text).expect("length validated");

    let shared = dk
        .decapsulate(&ct)
        .map_err(|_| MajikFileError::decryption_failed("ML-KEM decapsulation failed", None))?;
    Ok(Zeroizing::new(shared.as_slice().to_vec()))
}

/// Generate a random ML-KEM-768 keypair (1184-byte pk, 2400-byte sk).
pub fn generate_ml_kem_keypair() -> MlKemKeypair {
    // generate() → (DecapsulationKey, EncapsulationKey) — dk FIRST.
    let (dk, ek): (Dk768, Ek768) = MlKem768::generate(&mut OsRng);
    MlKemKeypair {
        public_key: ek.as_bytes().to_vec(),
        secret_key: Zeroizing::new(dk.as_bytes().to_vec()),
    }
}
