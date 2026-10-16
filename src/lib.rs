//! # majik-file
//!
//! Post-quantum file encryption for the Majikah ecosystem (ML-KEM-768 +
//! AES-256-GCM + Zstd) in the `.mjkb` binary format. Pure Rust port of the
//! `@majikah/majik-file` TypeScript SDK (v0.7.1).
//!
//! Layout mirrors the TypeScript `src/` tree 1:1:
//!
//! | TypeScript                          | Rust                                  |
//! |-------------------------------------|---------------------------------------|
//! | `index.ts`                          | `lib.rs`                              |
//! | `majik-file.ts`                     | `majik_file.rs`                       |
//! | `core/index` (barrel)               | `core/mod.rs`                         |
//! | `core/utils.ts`                     | `core/utils.rs`                       |
//! | `core/error.ts`                     | `core/error.rs`                       |
//! | `core/validator.ts`                 | `core/validator.rs`                   |
//! | `core/mjkb-codec.ts`                | `core/mjkb_codec.rs`                  |
//! | `core/types.ts`                     | `core/types.rs`                       |
//! | `core/crypto/*`                     | `core/crypto/{mod,constants,crypto_provider,zeroize}.rs` |
//! | `core/compressor/majik-compressor`  | `core/compressor/{mod,majik_compressor}.rs` |

pub mod core;
pub mod majik_file;
#[cfg(feature = "tauri")]
pub mod tauri_commands;

// Re-export the full public surface — mirrors `index.ts`.
pub use crate::core::compressor::majik_compressor::*;
pub use crate::core::crypto::constants::*;
pub use crate::core::error::*;
pub use crate::core::mjkb_codec::*;
pub use crate::core::types::*;
pub use crate::core::utils::*;
pub use crate::core::validator::*;
pub use crate::majik_file::*;
