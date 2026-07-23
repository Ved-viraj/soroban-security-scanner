//! Magic byte verification for WASM binaries.
//!
//! WASM modules start with the magic bytes `0x00 0x61 0x73 0x6D`
//! (the ASCII string "\0asm").

/// The expected WASM magic bytes: `\0asm`
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// The expected WASM version (1)
pub const WASM_VERSION: u32 = 1;

/// Result of magic byte verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MagicVerificationResult {
    /// The binary is a valid WASM module
    Valid,
    /// The binary does not start with WASM magic bytes
    InvalidMagic { expected: [u8; 4], found: [u8; 4] },
    /// The WASM version is not supported
    UnsupportedVersion { expected: u32, found: u32 },
    /// The binary is too small to be a valid WASM module
    TooSmall { size: usize },
}

/// Verify that the given bytes start with the WASM magic bytes
/// and have a supported version.
pub fn verify_magic(bytes: &[u8]) -> MagicVerificationResult {
    if bytes.len() < 8 {
        return MagicVerificationResult::TooSmall { size: bytes.len() };
    }

    let magic: [u8; 4] = match bytes[0..4].try_into() {
        Ok(m) => m,
        Err(_) => {
            let mut found = [0u8; 4];
            let copy_len = bytes.len().min(4);
            found[..copy_len].copy_from_slice(&bytes[..copy_len]);
            return MagicVerificationResult::InvalidMagic {
                expected: WASM_MAGIC,
                found,
            };
        }
    };

    if magic != WASM_MAGIC {
        return MagicVerificationResult::InvalidMagic {
            expected: WASM_MAGIC,
            found: magic,
        };
    }

    let version: u32 = u32::from_le_bytes(match bytes[4..8].try_into() {
        Ok(v) => v,
        Err(_) => {
            return MagicVerificationResult::UnsupportedVersion {
                expected: WASM_VERSION,
                found: 0,
            }
        }
    });

    if version != WASM_VERSION {
        return MagicVerificationResult::UnsupportedVersion {
            expected: WASM_VERSION,
            found: version,
        };
    }

    MagicVerificationResult::Valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_wasm_magic() {
        let valid_wasm = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(verify_magic(&valid_wasm), MagicVerificationResult::Valid);
    }

    #[test]
    fn test_invalid_magic() {
        let invalid = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let result = verify_magic(&invalid);
        assert!(matches!(
            result,
            MagicVerificationResult::InvalidMagic { .. }
        ));
    }

    #[test]
    fn test_unsupported_version() {
        let unsupported = [0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00];
        let result = verify_magic(&unsupported);
        assert!(matches!(
            result,
            MagicVerificationResult::UnsupportedVersion { .. }
        ));
    }

    #[test]
    fn test_too_small() {
        let too_small = [0x00, 0x61, 0x73];
        assert_eq!(
            verify_magic(&too_small),
            MagicVerificationResult::TooSmall { size: 3 }
        );
    }
}
