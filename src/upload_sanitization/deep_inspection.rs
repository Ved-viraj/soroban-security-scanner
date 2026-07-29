//! Deep inspection module for WASM binaries.
//!
//! Validates WASM module structure and exported function signatures
//! against the expected Stellar Environment Interface (SEI).

#[cfg(test)]
use crate::upload_sanitization::wasm::parse_wasm_module;
use crate::upload_sanitization::wasm::{ExportKind, ValType, WasmModule};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Expected Soroban contract interface function signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SorobanContractInterface {
    /// Version of the SEI specification
    pub version: String,
    /// Expected function signatures
    pub functions: Vec<ExpectedFunction>,
    /// Configuration options
    #[serde(default)]
    pub config: InterfaceConfig,
}

/// Expected function signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFunction {
    /// Function name
    pub name: String,
    /// Expected parameter types as strings ("Address", "i128", "u64", etc.)
    pub params: Vec<String>,
    /// Expected return types as strings
    pub results: Vec<String>,
    /// Whether this function is required
    #[serde(default = "default_required")]
    pub required: bool,
    /// Description of what this function does
    #[serde(default)]
    pub description: String,
}

fn default_required() -> bool {
    false
}

/// Interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Whether to use strict signature checking
    #[serde(default)]
    pub strict: bool,
    /// Whether to emit warnings for unknown functions
    #[serde(default = "default_true")]
    pub warn_unknown: bool,
}

fn default_true() -> bool {
    true
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            strict: false,
            warn_unknown: true,
        }
    }
}

impl Default for SorobanContractInterface {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            functions: vec![
                ExpectedFunction {
                    name: "init".to_string(),
                    params: vec!["Admin".to_string()],
                    results: vec![],
                    required: true,
                    description: "Initialize the contract with an admin address".to_string(),
                },
                ExpectedFunction {
                    name: "transfer".to_string(),
                    params: vec![
                        "Address".to_string(),
                        "Address".to_string(),
                        "i128".to_string(),
                    ],
                    results: vec![],
                    required: true,
                    description: "Transfer tokens from sender to recipient".to_string(),
                },
                ExpectedFunction {
                    name: "allowance".to_string(),
                    params: vec!["Address".to_string(), "Address".to_string()],
                    results: vec!["i128".to_string()],
                    required: false,
                    description: "Get the allowance for a spender".to_string(),
                },
                ExpectedFunction {
                    name: "approve".to_string(),
                    params: vec![
                        "Address".to_string(),
                        "Address".to_string(),
                        "i128".to_string(),
                    ],
                    results: vec![],
                    required: false,
                    description: "Approve a spender to spend tokens".to_string(),
                },
                ExpectedFunction {
                    name: "balance".to_string(),
                    params: vec!["Address".to_string()],
                    results: vec!["i128".to_string()],
                    required: true,
                    description: "Get the balance of an account".to_string(),
                },
                ExpectedFunction {
                    name: "mint".to_string(),
                    params: vec!["Address".to_string(), "i128".to_string()],
                    results: vec![],
                    required: false,
                    description: "Mint new tokens (admin only)".to_string(),
                },
                ExpectedFunction {
                    name: "burn".to_string(),
                    params: vec!["Address".to_string(), "i128".to_string()],
                    results: vec![],
                    required: false,
                    description: "Burn tokens (admin only)".to_string(),
                },
                ExpectedFunction {
                    name: "upgrade".to_string(),
                    params: vec!["Bytes".to_string()],
                    results: vec![],
                    required: false,
                    description: "Upgrade contract WASM code".to_string(),
                },
                ExpectedFunction {
                    name: "name".to_string(),
                    params: vec![],
                    results: vec!["String".to_string()],
                    required: false,
                    description: "Get the token name".to_string(),
                },
                ExpectedFunction {
                    name: "symbol".to_string(),
                    params: vec![],
                    results: vec!["String".to_string()],
                    required: false,
                    description: "Get the token symbol".to_string(),
                },
                ExpectedFunction {
                    name: "decimals".to_string(),
                    params: vec![],
                    results: vec!["u32".to_string()],
                    required: false,
                    description: "Get the token decimals".to_string(),
                },
                ExpectedFunction {
                    name: "total_supply".to_string(),
                    params: vec![],
                    results: vec!["i128".to_string()],
                    required: false,
                    description: "Get the total supply".to_string(),
                },
            ],
            config: InterfaceConfig::default(),
        }
    }
}

impl SorobanContractInterface {
    /// Create the standard Soroban contract interface
    pub fn standard() -> Self {
        Self::default()
    }

    /// Load the interface from a JSON file
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let interface: SorobanContractInterface = serde_json::from_str(&content)?;
        Ok(interface)
    }

    /// Save the interface to a JSON file
    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Convert a WASM ValType to an interface type string for comparison
    fn valtype_to_interface_type(vt: &ValType) -> String {
        match vt {
            ValType::I32 => "i32".to_string(),
            ValType::I64 => "i64".to_string(),
            ValType::F32 => "f32".to_string(),
            ValType::F64 => "f64".to_string(),
            ValType::V128 => "v128".to_string(),
            ValType::FuncRef => "funcref".to_string(),
            ValType::ExternRef => "externref".to_string(),
            ValType::Unknown(b) => format!("unknown(0x{:02X})", b),
        }
    }

    /// Check if a WASM type matches an expected interface type string.
    /// In Soroban, types like Address, i128 are encoded as i32 pointers/externref
    /// and bytes, so we do a flexible mapping.
    fn type_matches(wasm_type: &ValType, interface_type: &str) -> bool {
        match (wasm_type, interface_type) {
            (ValType::I32, "i32") => true,
            (ValType::I32, "u32") => true,
            (ValType::I32, "Address") => true, // Address is 32 bytes, passed as pointer (i32)
            (ValType::I32, "Bytes") => true,   // Bytes passed as pointer (i32)
            (ValType::I32, "String") => true,  // String passed as pointer (i32)
            (ValType::I32, "Symbol") => true,  // Symbol passed as pointer (i32)
            (ValType::I32, "bool") => true,    // bool passed as i32
            (ValType::I64, "i64") => true,
            (ValType::I64, "u64") => true,
            (ValType::I64, "i128") => true, // i128 is often 2 x i64 or i64-based
            (ValType::I64, "u128") => true,
            (ValType::V128, "i128") => true, // v128 can hold i128
            (ValType::V128, "u128") => true,
            (ValType::F32, "f32") => true,
            (ValType::F64, "f64") => true,
            _ => false,
        }
    }
}

/// Core function to validate exported function signatures against the SEI.
///
/// Takes a parsed WASM module and an interface definition, and returns
/// a detailed validation result.
pub fn validate_function_signatures(
    wasm: &WasmModule,
    interface: &SorobanContractInterface,
) -> SignatureValidationResult {
    let mut function_results = Vec::new();
    let mut warnings = Vec::new();

    // Build a map from function name to expected signature
    let expected_map: HashMap<&str, &ExpectedFunction> = interface
        .functions
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    // Process exported functions
    for export in &wasm.exports {
        if export.kind != ExportKind::Func {
            continue;
        }

        let idx = export.index as usize;
        let func_name = export.name.clone();

        // Get the actual function type from the WASM module
        let actual_sig = if idx < wasm.function_bodies.len() {
            let type_idx = wasm.function_bodies[idx].type_index as usize;
            if type_idx < wasm.function_types.len() {
                let ft = &wasm.function_types[type_idx];
                Some(FunctionSignature {
                    params: ft
                        .params
                        .iter()
                        .map(SorobanContractInterface::valtype_to_interface_type)
                        .collect(),
                    results: ft
                        .results
                        .iter()
                        .map(SorobanContractInterface::valtype_to_interface_type)
                        .collect(),
                })
            } else {
                None
            }
        } else {
            None
        };

        // Check against expected interface
        let result = match expected_map.get(func_name.as_str()) {
            Some(expected) => {
                let actual = match &actual_sig {
                    Some(sig) => sig,
                    None => {
                        function_results.push(FunctionSignatureResult {
                            function_name: func_name.clone(),
                            matches: false,
                            status: SignatureStatus::Unknown,
                            expected: Some(FunctionSignature {
                                params: expected.params.clone(),
                                results: expected.results.clone(),
                            }),
                            actual: None,
                            warning: Some("Could not determine function type".to_string()),
                        });
                        continue;
                    }
                };

                check_function_match(func_name.clone(), expected, actual, &mut warnings)
            }
            None => {
                // Unknown function - emit warning
                let warning = format!(
                    "Function '{}' is not part of the known Soroban contract interface",
                    func_name
                );
                warnings.push(warning.clone());
                FunctionSignatureResult {
                    function_name: func_name.clone(),
                    matches: false,
                    status: SignatureStatus::Unknown,
                    expected: None,
                    actual: actual_sig.clone(),
                    warning: Some(warning),
                }
            }
        };

        function_results.push(result);
    }

    // Check for required functions that are missing
    let present_functions: Vec<&str> = wasm
        .exports
        .iter()
        .filter(|e| e.kind == ExportKind::Func)
        .map(|e| e.name.as_str())
        .collect();

    for expected_func in &interface.functions {
        if expected_func.required && !present_functions.contains(&expected_func.name.as_str()) {
            let warning = format!(
                "Required function '{}' is missing from the contract interface",
                expected_func.name
            );
            warnings.push(warning.clone());
            function_results.push(FunctionSignatureResult {
                function_name: expected_func.name.clone(),
                matches: false,
                status: SignatureStatus::Unknown,
                expected: Some(FunctionSignature {
                    params: expected_func.params.clone(),
                    results: expected_func.results.clone(),
                }),
                actual: None,
                warning: Some(warning),
            });
        }
    }

    // Count statistics
    let total_checked = function_results.len();
    let total_mismatches = function_results
        .iter()
        .filter(|r| !r.matches && r.status != SignatureStatus::Unknown)
        .count();
    let total_unknown = function_results
        .iter()
        .filter(|r| r.status == SignatureStatus::Unknown)
        .count();
    let valid = total_mismatches == 0;

    // If strict mode is enabled, also require no unknown functions
    let strict_valid = if interface.config.strict {
        valid && total_unknown == 0
    } else {
        valid
    };

    SignatureValidationResult {
        valid: strict_valid,
        function_results,
        total_checked,
        total_mismatches,
        total_unknown,
        warnings,
    }
}

/// Check a single function against the expected interface
fn check_function_match(
    func_name: String,
    expected: &ExpectedFunction,
    actual: &FunctionSignature,
    warnings: &mut Vec<String>,
) -> FunctionSignatureResult {
    // Verify parameter count
    if actual.params.len() != expected.params.len() {
        let warning = format!(
            "Function '{}': expected {} parameters, found {}",
            func_name,
            expected.params.len(),
            actual.params.len()
        );
        warnings.push(warning.clone());
        return FunctionSignatureResult {
            function_name: func_name,
            matches: false,
            status: SignatureStatus::ParamCountMismatch {
                expected: expected.params.len(),
                actual: actual.params.len(),
            },
            expected: Some(FunctionSignature {
                params: expected.params.clone(),
                results: expected.results.clone(),
            }),
            actual: Some(actual.clone()),
            warning: Some(warning),
        };
    }

    // Verify parameter types
    let mut param_mismatches = Vec::new();
    for (i, (actual_type_str, expected_type)) in
        actual.params.iter().zip(expected.params.iter()).enumerate()
    {
        // Parse the string back to ValType for matching
        let wasm_val_type = match actual_type_str.as_str() {
            "i32" => ValType::I32,
            "i64" => ValType::I64,
            "f32" => ValType::F32,
            "f64" => ValType::F64,
            "v128" => ValType::V128,
            "funcref" => ValType::FuncRef,
            "externref" => ValType::ExternRef,
            _ => ValType::Unknown(0),
        };

        if !SorobanContractInterface::type_matches(&wasm_val_type, expected_type) {
            param_mismatches.push(format!(
                "param[{}]: expected '{}', found WASM type '{}'",
                i, expected_type, actual_type_str
            ));
        }
    }

    if !param_mismatches.is_empty() {
        let warning = format!(
            "Function '{}' parameter type mismatch: {}",
            func_name,
            param_mismatches.join("; ")
        );
        warnings.push(warning.clone());
        return FunctionSignatureResult {
            function_name: func_name,
            matches: false,
            status: SignatureStatus::ParamMismatch {
                expected: expected.params.clone(),
                actual: actual.params.clone(),
            },
            expected: Some(FunctionSignature {
                params: expected.params.clone(),
                results: expected.results.clone(),
            }),
            actual: Some(actual.clone()),
            warning: Some(warning),
        };
    }

    // Verify result count
    if actual.results.len() != expected.results.len() {
        let warning = format!(
            "Function '{}': expected {} results, found {}",
            func_name,
            expected.results.len(),
            actual.results.len()
        );
        warnings.push(warning.clone());
        return FunctionSignatureResult {
            function_name: func_name,
            matches: false,
            status: SignatureStatus::ResultCountMismatch {
                expected: expected.results.len(),
                actual: actual.results.len(),
            },
            expected: Some(FunctionSignature {
                params: expected.params.clone(),
                results: expected.results.clone(),
            }),
            actual: Some(actual.clone()),
            warning: Some(warning),
        };
    }

    // All checks passed
    FunctionSignatureResult {
        function_name: func_name,
        matches: true,
        status: SignatureStatus::Matched,
        expected: Some(FunctionSignature {
            params: expected.params.clone(),
            results: expected.results.clone(),
        }),
        actual: Some(actual.clone()),
        warning: None,
    }
}

/// Result of function signature validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureValidationResult {
    /// Whether all signatures are valid
    pub valid: bool,
    /// Detailed validation results for each function
    pub function_results: Vec<FunctionSignatureResult>,
    /// Number of total functions checked
    pub total_checked: usize,
    /// Number of functions with mismatches
    pub total_mismatches: usize,
    /// Number of unknown functions (not in interface)
    pub total_unknown: usize,
    /// Warnings generated during validation
    pub warnings: Vec<String>,
}

/// Result of validating a single function's signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignatureResult {
    /// Function name
    pub function_name: String,
    /// Whether the signature matches
    pub matches: bool,
    /// The status of this function
    pub status: SignatureStatus,
    /// Expected signature (from interface)
    pub expected: Option<FunctionSignature>,
    /// Actual signature (from WASM)
    pub actual: Option<FunctionSignature>,
    /// Warning message if applicable
    pub warning: Option<String>,
}

/// A function signature (parameter and return types)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub params: Vec<String>,
    pub results: Vec<String>,
}

/// Status of a function signature check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Signature matches the expected interface
    Matched,
    /// Function not found in known interface
    Unknown,
    /// Parameter type mismatch
    ParamMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    /// Return type mismatch
    ResultMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    /// Parameter count mismatch
    ParamCountMismatch { expected: usize, actual: usize },
    /// Result count mismatch
    ResultCountMismatch { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a WASM module with a specific function signature for testing
    fn create_test_wasm_with_function(
        func_name: &str,
        param_types: &[u8],
        result_types: &[u8],
    ) -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

        // Type section
        wasm.push(1); // section id: type
        let mut type_content = vec![
            0x01, // 1 type
            0x60, // functype
        ];
        type_content.push(param_types.len() as u8);
        type_content.extend_from_slice(param_types);
        type_content.push(result_types.len() as u8);
        type_content.extend_from_slice(result_types);

        let content_len = type_content.len() as u32;
        wasm.extend_from_slice(&content_len.to_le_bytes());
        wasm.extend_from_slice(&type_content);

        // Function section (map type index 0 to function 0)
        wasm.push(3); // section id: function
        let func_content = vec![
            0x01, // 1 function
            0x00, // type index 0
        ];
        let func_len = func_content.len() as u32;
        wasm.extend_from_slice(&func_len.to_le_bytes());
        wasm.extend_from_slice(&func_content);

        // Export section
        wasm.push(7); // section id: export
        let name_bytes = func_name.as_bytes();
        let mut export_content = vec![
            0x01, // 1 export
        ];
        // name (length-prefixed)
        export_content.push(name_bytes.len() as u8);
        export_content.extend_from_slice(name_bytes);
        export_content.push(0x00); // func kind
        export_content.push(0x00); // func index 0

        let export_len = export_content.len() as u32;
        wasm.extend_from_slice(&export_len.to_le_bytes());
        wasm.extend_from_slice(&export_content);

        // Code section
        wasm.push(10); // section id: code
        let code_content = vec![
            0x01, // 1 body
            0x00, // body size = 0 (empty body)
        ];
        let code_len = code_content.len() as u32;
        wasm.extend_from_slice(&code_len.to_le_bytes());
        wasm.extend_from_slice(&code_content);

        wasm
    }

    #[test]
    fn test_default_interface_has_required_functions() {
        let interface = SorobanContractInterface::default();
        let required: Vec<&str> = interface
            .functions
            .iter()
            .filter(|f| f.required)
            .map(|f| f.name.as_str())
            .collect();
        assert!(required.contains(&"init"));
        assert!(required.contains(&"transfer"));
        assert!(required.contains(&"balance"));
    }

    #[test]
    fn test_validate_valid_transfer_signature() {
        // Create a WASM with transfer(Address, Address, i128) -> ()
        // In WASM, Address is passed as i32 pointer, i128 as i64 pair
        let wasm_bytes = create_test_wasm_with_function(
            "transfer",
            &[0x7F, 0x7F, 0x7E], // i32, i32, i64 (Address, Address, i128)
            &[],                 // no results
        );
        let wasm = parse_wasm_module(&wasm_bytes).unwrap();
        let interface = SorobanContractInterface::default();

        let result = validate_function_signatures(&wasm, &interface);
        let transfer_result = result
            .function_results
            .iter()
            .find(|r| r.function_name == "transfer")
            .unwrap();
        assert!(
            transfer_result.matches,
            "transfer function should have valid signature"
        );
    }

    #[test]
    fn test_detect_param_count_mismatch() {
        // Create a WASM with transfer(Address, i64) instead of (Address, Address, i128)
        let wasm_bytes = create_test_wasm_with_function(
            "transfer",
            &[0x7F, 0x7E], // i32, i64 (wrong: should be 3 params)
            &[],           // no results
        );
        let wasm = parse_wasm_module(&wasm_bytes).unwrap();
        let interface = SorobanContractInterface::default();

        let result = validate_function_signatures(&wasm, &interface);
        // Should detect param count mismatch
        assert!(
            result
                .function_results
                .iter()
                .any(|r| matches!(r.status, SignatureStatus::ParamCountMismatch { .. })),
            "Should detect param count mismatch for transfer"
        );
    }

    #[test]
    fn test_detect_missing_required_function() {
        // Create a WASM with only an unknown function, missing required ones
        let wasm_bytes = create_test_wasm_with_function(
            "unknown_func",
            &[], // no params
            &[], // no results
        );
        let wasm = parse_wasm_module(&wasm_bytes).unwrap();
        let interface = SorobanContractInterface::default();

        let result = validate_function_signatures(&wasm, &interface);
        // Should warn about missing required functions
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Required function")),
            "Should warn about missing required functions"
        );
    }

    #[test]
    fn test_unknown_function_warning() {
        let wasm_bytes = create_test_wasm_with_function(
            "unknown_func",
            &[], // no params
            &[], // no results
        );
        let wasm = parse_wasm_module(&wasm_bytes).unwrap();
        let interface = SorobanContractInterface::default();

        let result = validate_function_signatures(&wasm, &interface);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("not part of the known")),
            "Should warn about unknown functions"
        );
    }

    #[test]
    fn test_strict_mode_rejects_unknown_functions() {
        let mut strict_interface = SorobanContractInterface::default();
        strict_interface.config.strict = true;

        let wasm_bytes = create_test_wasm_with_function(
            "unknown_func",
            &[], // no params
            &[], // no results
        );
        let wasm = parse_wasm_module(&wasm_bytes).unwrap();

        let result = validate_function_signatures(&wasm, &strict_interface);
        // In strict mode, valid should be false due to unknown functions
        assert!(!result.valid, "Strict mode should reject unknown functions");
    }

    #[test]
    fn test_interface_load_and_save() {
        let interface = SorobanContractInterface::default();
        let path = "/tmp/test_interface.json";
        interface.save_to_file(path).unwrap();
        let loaded = SorobanContractInterface::load_from_file(path).unwrap();
        assert_eq!(interface.version, loaded.version);
        assert_eq!(interface.functions.len(), loaded.functions.len());
        let _ = std::fs::remove_file(path);
    }
}
