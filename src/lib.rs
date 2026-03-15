pub mod core;
pub mod majik_file;
#[cfg(feature = "tauri")]
pub mod tauri_commands;

// Re-export the full public surface — mirrors index.ts
pub use core::error::*;
pub use core::types::*;
pub use majik_file::MajikFile;

#[cfg(test)]
mod tests;
