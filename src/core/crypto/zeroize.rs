//! zeroize.rs
//!
//! In Rust, secret wiping is handled by the `zeroize` crate and the
//! ownership model: wrap secrets in [`Zeroizing`] and they are wiped on drop,
//! including on early return / error (this replaces TS `withZeroize`).
//!
//! Ownership rule (same as TS): only wrap buffers MajikFile itself allocates
//! (shared secrets, AES keys, the decrypted cache). Never zeroize a
//! caller-supplied secret key — decrypt identities borrow `&[u8]`.

pub use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Overwrite a buffer with zeros in place (TS `secureFill`).
pub fn secure_fill(buf: &mut [u8]) {
    buf.zeroize();
}

/// Zeroize several buffers (TS `secureFillMany`).
pub fn secure_fill_many(bufs: &mut [&mut [u8]]) {
    for b in bufs.iter_mut() {
        b.zeroize();
    }
}
