//! Sanitization pipeline for uploaded WASM binaries.
//!
//! Orchestrates the full validation pipeline:
//! 1. Magic byte verification
//! 2. Content type checks
//! 3. Malware signature scanning
//! 4. Deep inspection (including function signature validation)

use crate::upload_sanitization::content_type::{validate_content_type, ContentTypeResult};
use crate::upload_sanitization::deep_inspection::{
    validate_function_signatures, SignatureValidationResult, SorobanContractInterface,
};
use crate::upload_sanitization::magic::{verify_magic, MagicVerificationResult};
use crate::upload_sanitization::malware::{scan_for_malware, MalwareScanResult};
use crate::upload_sanitization::wasm::parse_wasm_module;

/// Result of the full sanitization pipeline
#[derive(Debug, Clone)]
pub struct SanitizationResult {
    /// Whether the binary passed all checks
    pub passed: bool,
    /// Magic byte verification result
    pub magic_check: MagicVerificationResult,
    /// Content type validation result
    pub content_type_check: ContentTypeResult,
    /// Malware scan results
    pub malware_scan: Vec<MalwareScanResult>,
    /// Deep inspection result
    pub deep_inspection: Option<SignatureValidationResult>,
    /// Whether the binary is clean
    pub is_clean: bool,
    /// List of all issues found
    pub issues: Vec<String>,
}

/// The sanitization pipeline
#[derive(Debug, Clone)]
pub struct SanitizationPipeline {
    /// The SEI interface to validate against
    pub sei_interface: SorobanContractInterface,
    /// Path to custom SEI interface file (optional)
    pub sei_interface_path: Option<String>,
}

impl Default for SanitizationPipeline {
    fn default() -> Self {
        Self {
            sei_interface: SorobanContractInterface::default(),
            sei_interface_path: None,
        }
    }
}

impl SanitizationPipeline {
    /// Create a new sanitization pipeline with the given configuration
    pub fn new(strict_signature_check: bool) -> Self {
        let mut interface = SorobanContractInterface::default();
        interface.config.strict = strict_signature_check;

        Self {
            sei_interface: interface,
            sei_interface_path: None,
        }
    }

    /// Whether strict signature checking is enabled
    pub fn strict_signature_check(&self) -> bool {
        self.sei_interface.config.strict
    }

    /// Create a new sanitization pipeline with a custom SEI interface file
    pub fn new_with_interface(
        strict_signature_check: bool,
        interface_path: &str,
    ) -> anyhow::Result<Self> {
        let mut interface = if std::path::Path::new(interface_path).exists() {
            SorobanContractInterface::load_from_file(interface_path)?
        } else {
            SorobanContractInterface::default()
        };
        interface.config.strict = strict_signature_check;

        Ok(Self {
            sei_interface: interface,
            sei_interface_path: Some(interface_path.to_string()),
        })
    }

    /// Run the full sanitization pipeline on the given bytes
    pub fn sanitize(&self, bytes: &[u8], filename: Option<&str>) -> SanitizationResult {
        let mut issues = Vec::new();
        let mut passed = true;

        // Stage 1: Magic byte verification
        let magic_check = verify_magic(bytes);
        if !matches!(magic_check, MagicVerificationResult::Valid) {
            passed = false;
            issues.push(format!("Magic byte check failed: {:?}", magic_check));
        }

        // Stage 2: Content type check (if filename provided)
        let content_type_check = match filename {
            Some(name) => validate_content_type(name, bytes),
            None => ContentTypeResult::Valid,
        };
        if !matches!(content_type_check, ContentTypeResult::Valid) {
            passed = false;
            issues.push(format!(
                "Content type check failed: {:?}",
                content_type_check
            ));
        }

        // Stage 3: Malware scan
        let malware_scan = scan_for_malware(bytes);
        let has_malware = malware_scan
            .iter()
            .any(|r| matches!(r, MalwareScanResult::MalwareDetected { .. }));
        if has_malware {
            passed = false;
            issues.push("Malware detected in binary".to_string());
        }

        // Stage 4: Deep inspection (only if basic checks pass or partial inspection desired)
        let strict_check = self.strict_signature_check();
        let deep_inspection = if matches!(magic_check, MagicVerificationResult::Valid) {
            match parse_wasm_module(bytes) {
                Ok(wasm) => {
                    let sig_result = validate_function_signatures(&wasm, &self.sei_interface);
                    if !sig_result.valid && strict_check {
                        passed = false;
                    }
                    if !sig_result.warnings.is_empty() {
                        for warning in &sig_result.warnings {
                            issues.push(format!("Signature validation: {}", warning));
                        }
                    }
                    Some(sig_result)
                }
                Err(e) => {
                    if strict_check {
                        passed = false;
                    }
                    issues.push(format!("WASM parsing failed: {}", e));
                    None
                }
            }
        } else {
            None
        };

        let is_clean = passed
            && matches!(magic_check, MagicVerificationResult::Valid)
            && matches!(content_type_check, ContentTypeResult::Valid)
            && !has_malware;

        SanitizationResult {
            passed,
            magic_check,
            content_type_check,
            malware_scan,
            deep_inspection,
            is_clean,
            issues,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_simple_wasm() -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

        // Type section with 1 type: (i32) -> (i64) (balance-like)
        wasm.push(1);
        let mut type_content = vec![
            0x01, // 1 type
            0x60, // functype
            0x01, 0x7F, // 1 param: i32
            0x01, 0x7E, // 1 result: i64
        ];
        let content_len = type_content.len() as u32;
        wasm.extend_from_slice(&content_len.to_le_bytes());
        wasm.extend_from_slice(&type_content);

        // Function section
        wasm.push(3);
        let func_content = vec![0x01, 0x00];
        let func_len = func_content.len() as u32;
        wasm.extend_from_slice(&func_len.to_le_bytes());
        wasm.extend_from_slice(&func_content);

        // Export section: balance(Address) -> i128
        wasm.push(7);
        let mut export_content = vec![0x01]; // 1 export
        export_content.push(7); // len of "balance"
        export_content.extend_from_slice(b"balance");
        export_content.push(0x00); // func kind
        export_content.push(0x00); // func index 0
        let export_len = export_content.len() as u32;
        wasm.extend_from_slice(&export_len.to_le_bytes());
        wasm.extend_from_slice(&export_content);

        // Code section
        wasm.push(10);
        let code_content = vec![0x01, 0x00];
        let code_len = code_content.len() as u32;
        wasm.extend_from_slice(&code_len.to_le_bytes());
        wasm.extend_from_slice(&code_content);

        wasm
    }

    #[test]
    fn test_pipeline_with_valid_wasm() {
        let pipeline = SanitizationPipeline::new(false);
        let wasm = create_simple_wasm();
        let result = pipeline.sanitize(&wasm, Some("contract.wasm"));
        assert!(result.is_clean || result.passed);
    }

    #[test]
    fn test_pipeline_with_invalid_magic() {
        let pipeline = SanitizationPipeline::new(false);
        let invalid = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let result = pipeline.sanitize(&invalid, Some("contract.wasm"));
        assert!(!result.passed);
    }

    #[test]
    fn test_pipeline_with_no_filename() {
        let pipeline = SanitizationPipeline::new(false);
        let wasm = create_simple_wasm();
        // Without filename, content type check should be skipped
        let result = pipeline.sanitize(&wasm, None);
        assert!(result.passed);
    }
}
