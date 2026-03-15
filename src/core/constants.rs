// ─── .mjkb Format Constants ───────────────────────────────────────────────────

/// Current .mjkb binary format version.
pub const MJKB_VERSION: u8 = 1;

/// .mjkb magic bytes: ASCII "MJKB" (0x4D 0x4A 0x4B 0x42).
pub const MJKB_MAGIC: [u8; 4] = [0x4d, 0x4a, 0x4b, 0x42];

/// Fixed header size (bytes): 4 magic + 1 version + 12 IV + 4 payload-len = 21.
pub const MJKB_HEADER_SIZE: usize = 4 + 1 + 12 + 4;

// utils.rs re-exports this under the internal name MJKB_FIXED_HEADER (same value)

// ─── ML-KEM-768 Key Sizes ─────────────────────────────────────────────────────

/// ML-KEM-768 public key length in bytes.
pub const ML_KEM_PK_LEN: usize = 1184;

/// ML-KEM-768 secret key length in bytes.
/// This is the 2400-byte *expanded* decapsulation key format,
/// matching @noble/post-quantum's ml_kem768 output exactly.
/// (ml-kem 0.2.x stores the full expanded key; 0.3.x uses a 64-byte seed instead)
pub const ML_KEM_SK_LEN: usize = 2400;

/// ML-KEM-768 ciphertext length in bytes.
pub const ML_KEM_CT_LEN: usize = 1088;

// ─── AES-GCM ─────────────────────────────────────────────────────────────────

/// AES-256-GCM key length in bytes.
pub const AES_KEY_LEN: usize = 32;

/// AES-GCM IV / nonce length in bytes.
pub const IV_LENGTH: usize = 12;

// ─── Compression ─────────────────────────────────────────────────────────────

/// Maximum Zstd compression level (highest ratio, slowest).
pub const ZSTD_MAX_LEVEL: i32 = 22;

// ─── File Size Limits ─────────────────────────────────────────────────────────

/// Default maximum file size: 100 MB in bytes. Bypassable via CreateOptions.
pub const MAX_FILE_SIZE_BYTES: usize = 100 * 1024 * 1024;

// ─── R2 Storage Prefixes ─────────────────────────────────────────────────────

pub struct R2Prefix;

impl R2Prefix {
    pub const PERMANENT: &'static str = "files/user";
    pub const TEMPORARY: &'static str = "files/public";
    pub const CHAT_IMAGE: &'static str = "images/chats";
}

// ─── File-level Constants ────────────────────────────────────────────────────

/// Maximum number of recipients for a group-encrypted file.
pub const MAX_RECIPIENTS: usize = 100;

// ─── MIME type sets ───────────────────────────────────────────────────────────

/// MIME types that are already compressed at the codec level.
/// Applying Zstd to these yields negligible savings.
pub fn incompressible_mime_types() -> std::collections::HashSet<&'static str> {
    [
        "image/jpeg",
        "image/jpg",
        "image/webp",
        "image/avif",
        "image/heic",
        "image/heif",
        "image/jxl",
        "video/mp4",
        "video/webm",
        "video/ogg",
        "video/quicktime",
        "video/x-msvideo",
        "video/x-matroska",
        "video/x-flv",
        "video/3gpp",
        "video/3gpp2",
        "video/mpeg",
        "video/x-ms-wmv",
        "video/mp2t",
        "video/x-m4v",
        "audio/mpeg",
        "audio/aac",
        "audio/ogg",
        "audio/opus",
        "audio/webm",
        "audio/x-m4a",
        "audio/mp4",
        "audio/amr",
        "application/zip",
        "application/gzip",
        "application/x-zip-compressed",
        "application/x-gzip",
        "application/x-rar-compressed",
        "application/x-rar",
        "application/vnd.rar",
        "application/x-7z-compressed",
        "application/x-bzip2",
        "application/x-xz",
        "application/x-lzip",
        "application/x-zstd",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/epub+zip",
    ]
    .into_iter()
    .collect()
}

/// MIME types that can be rendered inline in a browser.
pub fn inline_viewable_mime_types() -> std::collections::HashSet<&'static str> {
    [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/svg+xml",
        "image/bmp",
        "image/tiff",
        "image/x-icon",
        "application/pdf",
        "text/plain",
        "text/html",
        "text/css",
        "text/csv",
        "text/xml",
        "text/markdown",
        "video/mp4",
        "video/webm",
        "video/ogg",
        "video/quicktime",
        "audio/mpeg",
        "audio/ogg",
        "audio/wav",
        "audio/webm",
        "audio/aac",
        "audio/flac",
    ]
    .into_iter()
    .collect()
}

/// Map from file extension to canonical MIME type.
pub fn extension_to_mime(ext: &str) -> Option<&'static str> {
    match ext.to_lowercase().as_str() {
        // Images
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "svg" => Some("image/svg+xml"),
        "bmp" => Some("image/bmp"),
        "tiff" | "tif" => Some("image/tiff"),
        "ico" => Some("image/x-icon"),
        "heic" => Some("image/heic"),
        "heif" => Some("image/heif"),
        "jxl" => Some("image/jxl"),
        "psd" => Some("image/vnd.adobe.photoshop"),
        "xcf" => Some("image/x-xcf"),
        "cr2" => Some("image/x-canon-cr2"),
        "nef" => Some("image/x-nikon-nef"),
        "arw" => Some("image/x-sony-arw"),
        // Video
        "mp4" => Some("video/mp4"),
        "webm" => Some("video/webm"),
        "ogg" => Some("video/ogg"),
        "mov" => Some("video/quicktime"),
        "avi" => Some("video/x-msvideo"),
        "mkv" => Some("video/x-matroska"),
        "flv" => Some("video/x-flv"),
        "3gp" => Some("video/3gpp"),
        "mpeg" | "mpg" => Some("video/mpeg"),
        "wmv" => Some("video/x-ms-wmv"),
        "m4v" => Some("video/x-m4v"),
        // Audio
        "mp3" => Some("audio/mpeg"),
        "wav" => Some("audio/wav"),
        "aac" => Some("audio/aac"),
        "flac" => Some("audio/flac"),
        "m4a" => Some("audio/x-m4a"),
        "mid" | "midi" => Some("audio/midi"),
        "aiff" | "aif" => Some("audio/aiff"),
        "opus" => Some("audio/opus"),
        "amr" => Some("audio/amr"),
        // Documents
        "pdf" => Some("application/pdf"),
        "doc" => Some("application/msword"),
        "docx" => Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        "xls" => Some("application/vnd.ms-excel"),
        "xlsx" => Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        "ppt" => Some("application/vnd.ms-powerpoint"),
        "pptx" => Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        "odt" => Some("application/vnd.oasis.opendocument.text"),
        "ods" => Some("application/vnd.oasis.opendocument.spreadsheet"),
        "odp" => Some("application/vnd.oasis.opendocument.presentation"),
        "rtf" => Some("application/rtf"),
        // Text / Code
        "txt" => Some("text/plain"),
        "html" | "htm" => Some("text/html"),
        "css" => Some("text/css"),
        "csv" => Some("text/csv"),
        "xml" => Some("text/xml"),
        "md" | "markdown" => Some("text/markdown"),
        "js" | "mjs" => Some("text/javascript"),
        "ts" => Some("application/typescript"),
        "json" => Some("application/json"),
        "yaml" | "yml" => Some("text/yaml"),
        "toml" => Some("application/toml"),
        "graphql" | "gql" => Some("application/graphql"),
        "py" => Some("text/x-python"),
        "java" => Some("text/x-java-source"),
        "c" => Some("text/x-c"),
        "cpp" | "cxx" => Some("text/x-c++"),
        "cs" => Some("text/x-csharp"),
        "go" => Some("text/x-go"),
        "rs" => Some("text/x-rust"),
        "swift" => Some("text/x-swift"),
        "kt" => Some("text/x-kotlin"),
        "rb" => Some("text/x-ruby"),
        "php" => Some("text/x-php"),
        "sh" | "bash" => Some("text/x-sh"),
        "ps1" => Some("text/x-powershell"),
        "sql" => Some("application/x-sql"),
        "lua" => Some("text/x-lua"),
        // Archives
        "zip" => Some("application/zip"),
        "rar" => Some("application/x-rar-compressed"),
        "7z" => Some("application/x-7z-compressed"),
        "tar" => Some("application/x-tar"),
        "gz" => Some("application/gzip"),
        "bz2" => Some("application/x-bzip2"),
        "xz" => Some("application/x-xz"),
        "zst" => Some("application/x-zstd"),
        // Executables
        "exe" | "dll" => Some("application/x-msdownload"),
        "msi" => Some("application/x-msi"),
        "dmg" => Some("application/x-apple-diskimage"),
        "deb" => Some("application/x-debian-package"),
        "rpm" => Some("application/x-rpm"),
        // Fonts
        "ttf" => Some("font/ttf"),
        "otf" => Some("font/otf"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        "eot" => Some("application/vnd.ms-fontobject"),
        // 3D
        "gltf" => Some("model/gltf+json"),
        "glb" => Some("model/gltf-binary"),
        "obj" => Some("model/obj"),
        "stl" => Some("model/stl"),
        "blend" => Some("application/x-blender"),
        "fbx" => Some("application/x-fbx"),
        // Adobe
        "ai" | "eps" => Some("application/postscript"),
        "indd" => Some("application/x-indesign"),
        "xd" => Some("application/x-xd"),
        // Design
        "fig" => Some("application/x-figma"),
        "sketch" => Some("application/x-sketch"),
        // VS Code / IDE
        "vsix" => Some("application/x-vsix"),
        "ipynb" => Some("application/x-ipynb+json"),
        // Database
        "sqlite" | "db" => Some("application/x-sqlite3"),
        // eBook
        "epub" => Some("application/epub+zip"),
        "mobi" => Some("application/x-mobipocket-ebook"),
        // Apple
        "pages" => Some("application/x-iwork-pages-sffpages"),
        "numbers" => Some("application/x-iwork-numbers-sffnumbers"),
        "key" => Some("application/x-iwork-keynote-sffkey"),
        // Crypto / Certs
        "pem" => Some("application/x-pem-file"),
        "pfx" | "p12" => Some("application/x-pkcs12"),
        "cer" | "crt" => Some("application/pkix-cert"),
        _ => None,
    }
}
