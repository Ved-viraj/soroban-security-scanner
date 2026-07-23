//! WASM binary parser for extracting structure information.
//!
//! Provides utilities to parse WASM binary format and extract
//! section information, export entries, and function signatures.

use std::collections::HashMap;

/// WASM module structure parsed from binary
#[derive(Debug, Clone, Default)]
pub struct WasmModule {
    /// Version of the WASM module
    pub version: u32,
    /// Sections found in the module
    pub sections: Vec<Section>,
    /// Exported functions with their indices
    pub exports: Vec<ExportEntry>,
    /// Function types (signatures) by index
    pub function_types: Vec<FuncType>,
    /// Function bodies with their type index
    pub function_bodies: Vec<FunctionBody>,
    /// Imported functions
    pub imports: Vec<ImportEntry>,
}

/// WASM section types
#[derive(Debug, Clone)]
pub struct Section {
    pub id: u8,
    pub name: String,
    pub size: usize,
    pub offset: usize,
}

/// WASM value types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
    Unknown(u8),
}

impl ValType {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x7F => ValType::I32,
            0x7E => ValType::I64,
            0x7D => ValType::F32,
            0x7C => ValType::F64,
            0x7B => ValType::V128,
            0x70 => ValType::FuncRef,
            0x6F => ValType::ExternRef,
            b => ValType::Unknown(b),
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            ValType::I32 => "i32",
            ValType::I64 => "i64",
            ValType::F32 => "f32",
            ValType::F64 => "f64",
            ValType::V128 => "v128",
            ValType::FuncRef => "funcref",
            ValType::ExternRef => "externref",
            ValType::Unknown(b) => {
                // static str can't hold dynamic, so fallback
                "unknown"
            }
        }
    }
}

/// Function type (signature)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// Export entry from the export section
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub kind: ExportKind,
    pub index: u32,
}

/// Kind of export
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    Func,
    Table,
    Memory,
    Global,
}

/// Function body (code section entry)
#[derive(Debug, Clone)]
pub struct FunctionBody {
    pub type_index: u32,
    pub locals: Vec<ValType>,
    pub code_size: usize,
}

/// Import entry
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub module: String,
    pub name: String,
    pub kind: ExportKind,
    pub type_index: u32,
}

/// Parse a WASM binary into its module structure
pub fn parse_wasm_module(bytes: &[u8]) -> Result<WasmModule, WasmParseError> {
    if bytes.len() < 8 {
        return Err(WasmParseError::TooShort(bytes.len()));
    }

    // Verify magic bytes
    if bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
        return Err(WasmParseError::InvalidMagic);
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != 1 {
        return Err(WasmParseError::UnsupportedVersion(version));
    }

    let mut module = WasmModule {
        version,
        ..Default::default()
    };

    let mut pos = 8;
    let mut type_section_indices: HashMap<u32, FuncType> = HashMap::new();
    let mut current_type_idx: u32 = 0;

    // Parse sections
    while pos < bytes.len() {
        if pos + 1 > bytes.len() {
            break;
        }
        let section_id = bytes[pos];
        pos += 1;

        if pos + 4 > bytes.len() {
            break;
        }
        let section_size = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        let section_start = pos;
        let section_end = (pos + section_size).min(bytes.len());

        module.sections.push(Section {
            id: section_id,
            name: section_name(section_id).to_string(),
            size: section_size,
            offset: section_start,
        });

        match section_id {
            1 => {
                // Type section
                if section_start < section_end {
                    let count = leb128_u32(&bytes[section_start..section_end]);
                    let (_consumed, count) = count;
                    let mut sec_pos = section_start + _consumed;

                    for _ in 0..count {
                        if sec_pos >= section_end {
                            break;
                        }
                        match parse_functype(&bytes[sec_pos..section_end]) {
                            Ok((consumed, ft)) => {
                                type_section_indices.insert(current_type_idx, ft);
                                current_type_idx += 1;
                                sec_pos += consumed;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            2 => {
                // Import section
                if section_start < section_end {
                    let count = leb128_u32(&bytes[section_start..section_end]);
                    let (_consumed, count) = count;
                    let mut sec_pos = section_start + _consumed;

                    for _ in 0..count {
                        if sec_pos + 8 >= section_end {
                            break;
                        }
                        // Parse module name
                        let (consumed, module_name) = parse_name(&bytes[sec_pos..section_end]);
                        sec_pos += consumed;
                        let (consumed2, import_name) = parse_name(&bytes[sec_pos..section_end]);
                        sec_pos += consumed2;

                        if sec_pos < section_end {
                            let import_kind = bytes[sec_pos];
                            sec_pos += 1;

                            let (type_idx, _) = if sec_pos + 4 <= section_end {
                                let idx = u32::from_le_bytes(
                                    bytes[sec_pos..sec_pos + 4].try_into().unwrap(),
                                );
                                (idx, 4)
                            } else {
                                (0, 0)
                            };
                            sec_pos += 4;

                            let kind = match import_kind {
                                0x00 => ExportKind::Func,
                                0x01 => ExportKind::Table,
                                0x02 => ExportKind::Memory,
                                0x03 => ExportKind::Global,
                                _ => ExportKind::Func,
                            };

                            module.imports.push(ImportEntry {
                                module: module_name,
                                name: import_name,
                                kind,
                                type_index: type_idx,
                            });
                        }
                    }
                }
            }
            3 => {
                // Function section (maps type indices to functions)
                if section_start < section_end {
                    let count = leb128_u32(&bytes[section_start..section_end]);
                    let (_consumed, count) = count;
                    let mut sec_pos = section_start + _consumed;

                    for _ in 0..count {
                        if sec_pos >= section_end {
                            break;
                        }
                        let (consumed, type_idx) = leb128_u32(&bytes[sec_pos..section_end]);
                        sec_pos += consumed;

                        // Store a placeholder; actual bodies in code section
                        module.function_bodies.push(FunctionBody {
                            type_index: type_idx,
                            locals: vec![],
                            code_size: 0,
                        });
                    }
                }
            }
            7 => {
                // Export section
                if section_start < section_end {
                    let count = leb128_u32(&bytes[section_start..section_end]);
                    let (_consumed, count) = count;
                    let mut sec_pos = section_start + _consumed;

                    for _ in 0..count {
                        let (consumed, name) = parse_name(&bytes[sec_pos..section_end]);
                        sec_pos += consumed;

                        if sec_pos < section_end {
                            let export_kind = bytes[sec_pos];
                            sec_pos += 1;

                            let (consumed2, index) = leb128_u32(&bytes[sec_pos..section_end]);
                            sec_pos += consumed2;

                            let kind = match export_kind {
                                0x00 => ExportKind::Func,
                                0x01 => ExportKind::Table,
                                0x02 => ExportKind::Memory,
                                0x03 => ExportKind::Global,
                                _ => ExportKind::Func,
                            };

                            module.exports.push(ExportEntry { name, kind, index });
                        }
                    }
                }
            }
            10 => {
                // Code section
                if section_start < section_end {
                    let count = leb128_u32(&bytes[section_start..section_end]);
                    let (_consumed, count) = count;
                    let mut sec_pos = section_start + _consumed;

                    for func_idx in 0..count as usize {
                        if sec_pos >= section_end {
                            break;
                        }
                        // Body size
                        let (consumed, body_size) = leb128_u32(&bytes[sec_pos..section_end]);
                        let body_start = sec_pos + consumed;
                        let body_end = (body_start + body_size as usize).min(section_end);
                        sec_pos = body_end;

                        if func_idx < module.function_bodies.len() {
                            module.function_bodies[func_idx].code_size = body_size as usize;
                        }
                    }
                }
            }
            _ => {
                // Skip other sections (memory, table, global, start, element, data, custom)
            }
        }

        pos = section_end;
    }

    // Build function types list from the map
    let max_idx = type_section_indices.keys().max().copied().unwrap_or(0) as usize;
    module.function_types = vec![
        FuncType {
            params: vec![],
            results: vec![],
        };
        max_idx + 1
    ];
    for (idx, ft) in type_section_indices {
        module.function_types[idx as usize] = ft;
    }

    Ok(module)
}

/// Parse a function type from bytes
fn parse_functype(bytes: &[u8]) -> Result<(usize, FuncType), WasmParseError> {
    if bytes.is_empty() || bytes[0] != 0x60 {
        return Err(WasmParseError::InvalidTypeSection);
    }
    let mut pos = 1;

    // Parse params
    let (consumed, param_count) = leb128_u32(&bytes[pos..]);
    pos += consumed;
    let mut params = Vec::with_capacity(param_count as usize);
    for _ in 0..param_count {
        if pos >= bytes.len() {
            return Err(WasmParseError::InvalidTypeSection);
        }
        params.push(ValType::from_byte(bytes[pos]));
        pos += 1;
    }

    // Parse results
    let (consumed2, result_count) = leb128_u32(&bytes[pos..]);
    pos += consumed2;
    let mut results = Vec::with_capacity(result_count as usize);
    for _ in 0..result_count {
        if pos >= bytes.len() {
            return Err(WasmParseError::InvalidTypeSection);
        }
        results.push(ValType::from_byte(bytes[pos]));
        pos += 1;
    }

    Ok((pos, FuncType { params, results }))
}

/// Parse a name (length-prefixed string) from bytes
fn parse_name(bytes: &[u8]) -> (usize, String) {
    if bytes.is_empty() {
        return (1, String::new());
    }
    let (consumed, len) = leb128_u32(bytes);
    let len = len as usize;
    if consumed + len > bytes.len() {
        return (consumed, String::new());
    }
    let name = String::from_utf8_lossy(&bytes[consumed..consumed + len]).to_string();
    (consumed + len, name)
}

/// Read a LEB128 unsigned integer from bytes
fn leb128_u32(bytes: &[u8]) -> (usize, u32) {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut consumed = 0;

    for &byte in bytes {
        consumed += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }

    (consumed, result)
}

/// Get the name of a section by its ID
fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        _ => "unknown",
    }
}

/// Error during WASM parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasmParseError {
    TooShort(usize),
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidTypeSection,
    ParseError(String),
}

impl std::fmt::Display for WasmParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmParseError::TooShort(len) => write!(f, "WASM binary too short: {} bytes", len),
            WasmParseError::InvalidMagic => write!(f, "Invalid WASM magic bytes"),
            WasmParseError::UnsupportedVersion(v) => write!(f, "Unsupported WASM version: {}", v),
            WasmParseError::InvalidTypeSection => write!(f, "Invalid type section"),
            WasmParseError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for WasmParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid WASM module binary
    fn minimal_wasm() -> Vec<u8> {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D]; // magic
        wasm.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version
        wasm
    }

    #[test]
    fn test_parse_minimal_wasm() {
        let wasm = minimal_wasm();
        let module = parse_wasm_module(&wasm).unwrap();
        assert_eq!(module.version, 1);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let invalid = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let result = parse_wasm_module(&invalid);
        assert_eq!(result, Err(WasmParseError::InvalidMagic));
    }

    #[test]
    fn test_parse_too_short() {
        let too_short = vec![0x00, 0x61];
        let result = parse_wasm_module(&too_short);
        assert!(matches!(result, Err(WasmParseError::TooShort(_))));
    }

    #[test]
    fn test_parse_with_type_section() {
        let mut wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

        // Type section: 1 function type () -> ()
        wasm.push(1); // section id: type
        let type_content = vec![
            0x01, // 1 type
            0x60, // functype
            0x00, // 0 params
            0x00, // 0 results
        ];
        let content_len = type_content.len() as u32;
        wasm.extend_from_slice(&content_len.to_le_bytes());
        wasm.extend_from_slice(&type_content);

        // Export section: 1 export
        wasm.push(7); // section id: export
        let export_content = vec![
            0x01, // 1 export
            0x04, b't', b'e', b's', b't', // name "test"
            0x00, // func kind
            0x00, // func index 0
        ];
        let export_len = export_content.len() as u32;
        wasm.extend_from_slice(&export_len.to_le_bytes());
        wasm.extend_from_slice(&export_content);

        let module = parse_wasm_module(&wasm).unwrap();
        assert_eq!(module.version, 1);
        assert!(!module.exports.is_empty());
        assert_eq!(module.exports[0].name, "test");
    }
}
