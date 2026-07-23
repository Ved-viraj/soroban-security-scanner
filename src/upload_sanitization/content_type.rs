//! Content type checks for uploaded files.
//!
//! Verifies that uploaded files have the correct MIME type
//! and file extension for WASM binaries.

/// Result of content type verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentTypeResult {
    /// Content type is valid for a WASM binary
    Valid,
    /// Invalid file extension
    InvalidExtension { provided: String, expected: String },
    /// Invalid MIME type
    InvalidMimeType { provided: String, expected: String },
    /// MIME type does not match file content
    MimeContentMismatch { mime: String, detail: String },
}

/// Valid WASM file extensions
const VALID_EXTENSIONS: &[&str] = &["wasm", "wat"];

/// Valid MIME types for WASM binaries
const VALID_MIME_TYPES: &[&str] = &[
    "application/wasm",
    "application/octet-stream",
];

/// Validate that the file extension is valid for a WASM binary
pub fn validate_extension(filename: &str) -> ContentTypeResult {
    let path = std::path::Path::new(filename);
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if VALID_EXTENSIONS.contains(&ext) => ContentTypeResult::Valid,
        Some(ext) => ContentTypeResult::InvalidExtension {
            provided: ext.to_string(),
            expected: VALID_EXTENSIONS.join(", "),
        },
        None => ContentTypeResult::InvalidExtension {
            provided: "(no extension)".to_string(),
            expected: VALID_EXTENSIONS.join(", "),
        },
    }
}

/// Validate that the MIME type is valid for a WASM binary
pub fn validate_mime_type(mime_type: &str) -> ContentTypeResult {
    if VALID_MIME_TYPES.contains(&mime_type) {
        ContentTypeResult::Valid
    } else {
        ContentTypeResult::InvalidMimeType {
            provided: mime_type.to_string(),
            expected: "application/wasm".to_string(),
        }
    }
}

/// Validate that the file content matches the expected type
pub fn validate_content_type(filename: &str, bytes: &[u8]) -> ContentTypeResult {
    // Check extension first
    let ext_result = validate_extension(filename);
    if !matches!(ext_result, ContentTypeResult::Valid) {
        return ext_result;
    }

    // Verify WASM magic bytes
    if bytes.len() < 4 || bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
        return ContentTypeResult::MimeContentMismatch {
            mime: "application/wasm".to_string(),
            detail: "File content does not contain valid WASM magic bytes".to_string(),
        };
    }

    ContentTypeResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_wasm_extension() {
        assert_eq!(
            validate_extension("contract.wasm"),
            ContentTypeResult::Valid
        );
    }

    #[test]
    fn test_invalid_extension() {
        let result = validate_extension("contract.exe");
        assert!(matches!(result, ContentTypeResult::InvalidExtension { .. }));
    }

    #[test]
    fn test_valid_mime_type() {
        assert_eq!(
            validate_mime_type("application/wasm"),
            ContentTypeResult::Valid
        );
    }

    #[test]
    fn test_invalid_mime_type() {
        let result = validate_mime_type("text/html");
        assert!(matches!(result, ContentTypeResult::InvalidMimeType { .. }));
    }

    #[test]
    fn test_mime_content_mismatch() {
        let result = validate_content_type("contract.wasm", &[0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, ContentTypeResult::MimeContentMismatch { .. }));
    }

    #[test]
    fn test_valid_content_type() {
        let result = validate_content_type("contract.wasm", &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(result, ContentTypeResult::Valid);
    }
}
