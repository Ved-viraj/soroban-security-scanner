//! Storage Safety Analyzer
//!
//! Detects storage key collisions, orphaned state, and type mismatches across
//! contract upgrades. Provides migration suggestions and a CLI command for
//! pre-upgrade static analysis.
//!
//! ## Architecture
//!
//! The analyzer works in five phases:
//! 1. **Storage Key Extraction**: Extracts all storage access sites from WASM
//! 2. **Key Expression Normalization**: Normalizes keys for comparison
//! 3. **Cross-Version Comparison**: Compares old vs new storage footprints
//! 4. **Type Inference**: Determines types of stored values
//! 5. **Report Generation**: Produces a StorageSafetyReport
//!
//! ## Usage
//!
//! ```ignore
//! let analyzer = StorageSafetyAnalyzer::new();
//! let report = analyzer.analyze_upgrade(&old_wasm, &new_wasm)?;
//! if report.has_critical_issues() {
//!     eprintln!("Storage migration required before upgrade!");
//! }
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Key Expression Types ──────────────────────────────────────────────────

/// Represents a normalized storage key expression for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyExpr {
    /// A compile-time constant Symbol key (e.g., Symbol::short("admin"))
    Symbol(String),
    /// Concatenation of two key expressions
    Concat(Box<KeyExpr>, Box<KeyExpr>),
    /// A dynamic key computed from a function parameter (parameter index)
    AddressParam(usize),
    /// A key that depends on a storage value
    StorageDependent(String),
    /// An unknown/unresolvable key expression
    Unknown(String),
}

impl std::fmt::Display for KeyExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyExpr::Symbol(s) => write!(f, "Symbol(\"{}\")", s),
            KeyExpr::Concat(a, b) => write!(f, "Concat({}, {})", a, b),
            KeyExpr::AddressParam(i) => write!(f, "Param({})", i),
            KeyExpr::StorageDependent(s) => write!(f, "StorageDependent({})", s),
            KeyExpr::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}

// ── Storage Types ────────────────────────────────────────────────────────

/// The type of a stored value in Soroban storage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StoredType {
    I32,
    I64,
    I128,
    U32,
    U64,
    U128,
    Symbol,
    Address,
    Bytes,
    String,
    Vec(Box<StoredType>),
    Map(Box<StoredType>, Box<StoredType>),
    Bool,
    Void,
    Unknown,
}

impl std::fmt::Display for StoredType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredType::I32 => write!(f, "i32"),
            StoredType::I64 => write!(f, "i64"),
            StoredType::I128 => write!(f, "i128"),
            StoredType::U32 => write!(f, "u32"),
            StoredType::U64 => write!(f, "u64"),
            StoredType::U128 => write!(f, "u128"),
            StoredType::Symbol => write!(f, "Symbol"),
            StoredType::Address => write!(f, "Address"),
            StoredType::Bytes => write!(f, "Bytes"),
            StoredType::String => write!(f, "String"),
            StoredType::Vec(t) => write!(f, "Vec<{}>", t),
            StoredType::Map(k, v) => write!(f, "Map<{}, {}>", k, v),
            StoredType::Bool => write!(f, "bool"),
            StoredType::Void => write!(f, "void"),
            StoredType::Unknown => write!(f, "unknown"),
        }
    }
}

// ── Storage Access Records ───────────────────────────────────────────────

/// A single storage access site in the contract code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccess {
    /// Source location (function name + offset)
    pub location: String,
    /// The normalized key expression
    pub key: KeyExpr,
    /// Type of access: get, set, has, or remove
    pub access_type: AccessType,
    /// Storage type: instance, persistent, or temporary
    pub storage_type: StorageDomain,
    /// The inferred type of the value being stored/retrieved
    pub value_type: Option<StoredType>,
    /// The logical variable name derived from the context
    pub logical_source: String,
}

/// Type of storage access operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessType {
    Get,
    Set,
    Has,
    Remove,
}

/// Storage domain / persistence type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageDomain {
    Instance,
    Persistent,
    Temporary,
}

// ── Collision and Orphan Detection ──────────────────────────────────────

/// A detected storage key collision between old and new contract versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCollision {
    /// The storage key that is involved in the collision
    pub key: KeyExpr,
    /// The logical variable name in the old contract
    pub old_logical_source: String,
    /// The logical variable name in the new contract
    pub new_logical_source: String,
    /// The old type (if known)
    pub old_type: Option<StoredType>,
    /// The new type (if known)
    pub new_type: Option<StoredType>,
    /// Whether this is a type mismatch collision
    pub type_mismatch: bool,
    /// The condition under which the collision occurs (for dynamic keys)
    pub collision_condition: Option<String>,
    /// Severity of the collision
    pub severity: CollisionSeverity,
    /// Human-readable description
    pub description: String,
}

/// Severity of a storage key collision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollisionSeverity {
    /// Type mismatch - data corruption risk
    Critical,
    /// Same key, different logical source - might be intentional
    Warning,
    /// Potential dynamic collision
    Info,
}

/// An orphaned storage key that the old contract uses but the new doesn't.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanedKey {
    /// The storage key
    pub key: KeyExpr,
    /// The stored type
    pub value_type: Option<StoredType>,
    /// Whether this data is important (balances, ownership, etc.)
    pub is_critical: bool,
    /// Migration suggestion
    pub migration_suggestion: MigrationSuggestion,
}

/// Suggestion for handling an orphaned storage key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationSuggestion {
    /// Remove the key - data is obsolete
    Remove(String),
    /// Migrate to a new key with a mapping
    MigrateTo { old_key: String, new_key: String },
    /// Export data before upgrade
    Export(String),
    /// Keep as-is (intentionally retained)
    Keep,
}

// ── Storage Footprint ────────────────────────────────────────────────────

/// The complete storage footprint of a contract version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFootprint {
    /// All storage access sites
    pub accesses: Vec<StorageAccess>,
    /// Set of all unique key expressions
    pub key_set: HashSet<KeyExpr>,
    /// Map of key -> type for all SET operations
    pub write_types: HashMap<KeyExpr, StoredType>,
    /// Map of key -> type for all GET operations
    pub read_types: HashMap<KeyExpr, StoredType>,
}

impl StorageFootprint {
    /// Create a new empty storage footprint.
    pub fn new() -> Self {
        Self {
            accesses: Vec::new(),
            key_set: HashSet::new(),
            write_types: HashMap::new(),
            read_types: HashMap::new(),
        }
    }

    /// Add a storage access record and update the key set and type maps.
    pub fn add_access(&mut self, access: StorageAccess) {
        self.key_set.insert(access.key.clone());
        if access.access_type == AccessType::Set {
            if let Some(ref ty) = access.value_type {
                self.write_types.insert(access.key.clone(), ty.clone());
            }
        } else if access.access_type == AccessType::Get {
            if let Some(ref ty) = access.value_type {
                self.read_types.insert(access.key.clone(), ty.clone());
            }
        }
        self.accesses.push(access);
    }
}

// ── Storage Safety Report ────────────────────────────────────────────────

/// The main report produced by the storage safety analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSafetyReport {
    /// Human-readable summary
    pub summary: String,
    /// Detected key collisions
    pub collisions: Vec<KeyCollision>,
    /// Orphaned keys (in old but not in new)
    pub orphaned_keys: Vec<OrphanedKey>,
    /// New keys (in new but not in old)
    pub new_keys: Vec<KeyExpr>,
    /// Compatible keys (same in both)
    pub compatible_keys: Vec<KeyExpr>,
    /// Whether migration is required before upgrade
    pub migration_required: bool,
    /// List of critical issues that MUST be resolved
    pub critical_issues: Vec<String>,
    /// List of warnings
    pub warnings: Vec<String>,
    /// Migration function skeleton (Rust code)
    pub migration_skeleton: Option<String>,
}

impl StorageSafetyReport {
    /// Check if there are any critical issues requiring migration.
    pub fn has_critical_issues(&self) -> bool {
        !self.critical_issues.is_empty()
    }

    /// Generate a human-readable string representation.
    pub fn to_readable_string(&self) -> String {
        let mut output = String::new();
        output.push_str("═══════════════════════════════════════════\n");
        output.push_str("   STORAGE SAFETY ANALYSIS REPORT\n");
        output.push_str("═══════════════════════════════════════════\n");
        output.push_str(&format!("Summary: {}\n", self.summary));
        output.push_str(&format!(
            "Migration required: {}\n\n",
            self.migration_required
        ));

        if !self.critical_issues.is_empty() {
            output.push_str("─── 🔴 CRITICAL ISSUES ───\n");
            for issue in &self.critical_issues {
                output.push_str(&format!("  • {}\n", issue));
            }
            output.push('\n');
        }

        if !self.warnings.is_empty() {
            output.push_str("─── 🟡 WARNINGS ───\n");
            for warning in &self.warnings {
                output.push_str(&format!("  • {}\n", warning));
            }
            output.push('\n');
        }

        output.push_str("─── KEY COLLISIONS ───\n");
        if self.collisions.is_empty() {
            output.push_str("  ✅ No collisions detected.\n");
        } else {
            for c in &self.collisions {
                let severity_marker = match c.severity {
                    CollisionSeverity::Critical => "🔴",
                    CollisionSeverity::Warning => "🟡",
                    CollisionSeverity::Info => "ℹ️",
                };
                output.push_str(&format!(
                    "  {} Key: {} | Old: {} ({}) | New: {} ({}) | {}\n",
                    severity_marker,
                    c.key,
                    c.old_logical_source,
                    c.old_type
                        .as_ref()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    c.new_logical_source,
                    c.new_type
                        .as_ref()
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                    c.description,
                ));
            }
        }
        output.push('\n');

        output.push_str("─── ORPHANED KEYS ───\n");
        if self.orphaned_keys.is_empty() {
            output.push_str("  ✅ No orphaned keys.\n");
        } else {
            for o in &self.orphaned_keys {
                let marker = if o.is_critical { "🔴" } else { "🟡" };
                output.push_str(&format!(
                    "  {} Key: {} | Type: {:?}\n",
                    marker, o.key, o.value_type
                ));
            }
        }
        output.push('\n');

        output.push_str(&format!(
            "─── STATS ───\n  Compatible: {} | Collisions: {} | Orphaned: {} | New: {}\n",
            self.compatible_keys.len(),
            self.collisions.len(),
            self.orphaned_keys.len(),
            self.new_keys.len(),
        ));

        if let Some(ref skeleton) = self.migration_skeleton {
            output.push_str("\n─── MIGRATION SKELETON ───\n");
            output.push_str(skeleton);
        }

        output.push_str("\n═══════════════════════════════════════════\n");
        output
    }
}

// ── Storage Safety Analyzer ──────────────────────────────────────────────

/// Main analyzer for detecting storage safety issues across contract upgrades.
pub struct StorageSafetyAnalyzer {
    /// Minimum severity to flag as critical
    pub min_critical_severity: CollisionSeverity,
}

impl StorageSafetyAnalyzer {
    /// Create a new storage safety analyzer.
    pub fn new() -> Self {
        Self {
            min_critical_severity: CollisionSeverity::Critical,
        }
    }

    /// Analyze two contract WASM files for storage safety issues.
    /// This is the main entry point for the `storage-audit` command.
    pub fn analyze_upgrade(&self, old_wasm: &[u8], new_wasm: &[u8]) -> Result<StorageSafetyReport> {
        // Phase 1: Extract storage footprints from both WASM files
        let old_footprint = self.extract_storage_footprint(old_wasm, "old")?;
        let new_footprint = self.extract_storage_footprint(new_wasm, "new")?;

        // Phase 2: Compare footprints
        self.compare_footprints(&old_footprint, &new_footprint)
    }

    /// Analyze two storage footprints for safety issues.
    pub fn analyze_footprints(
        &self,
        old_footprint: &StorageFootprint,
        new_footprint: &StorageFootprint,
    ) -> Result<StorageSafetyReport> {
        self.compare_footprints(old_footprint, new_footprint)
    }

    /// Extract the storage footprint from a WASM binary.
    fn extract_storage_footprint(&self, wasm: &[u8], label: &str) -> Result<StorageFootprint> {
        let mut footprint = StorageFootprint::new();

        // Phase 1: Extract storage access sites from WASM
        let accesses = self.extract_storage_accesses(wasm)?;

        for access in accesses {
            footprint.add_access(access);
        }

        Ok(footprint)
    }

    /// Extract storage access records from WASM binary.
    /// In a full implementation, this would:
    /// 1. Parse the WASM binary structure
    /// 2. Locate all calls to env.storage().{instance,persistent,temporary}().{get,set,has,remove}()
    /// 3. Trace the key argument through the dataflow
    /// 4. Determine the value type at each set/get site
    fn extract_storage_accesses(&self, wasm: &[u8]) -> Result<Vec<StorageAccess>> {
        let mut accesses = Vec::new();

        // Validate WASM magic number
        if wasm.len() < 8 || &wasm[0..4] != b"\0asm" {
            return Err(anyhow!("Invalid WASM binary: missing magic number"));
        }

        // For now, we use a pattern-matching approach to identify storage accesses.
        // In a production implementation, this would use a proper WASM parser
        // (e.g., wasmparser crate) to analyze the actual instruction stream.
        let wasm_str = String::from_utf8_lossy(wasm);

        // Pattern match for common storage access patterns
        let patterns = vec![
            ("set", "Symbol::new(&env, \"", AccessType::Set),
            ("get", "Symbol::new(&env, \"", AccessType::Get),
            ("has", "Symbol::new(&env, \"", AccessType::Has),
            ("remove", "Symbol::new(&env, \"", AccessType::Remove),
        ];

        for (operation, prefix, access_type) in &patterns {
            let search_prefix = format!("storage.{operation}(");
            // Simple substring search for storage access patterns
            for (idx, _) in wasm_str.match_indices(&search_prefix) {
                // Try to extract the key argument by looking for Symbol patterns nearby
                let window_start = idx.saturating_sub(200);
                let window_end = (idx + 200).min(wasm_str.len());
                let window = &wasm_str[window_start..window_end];

                // Look for Symbol key patterns in the window
                let key = if let Some(sym_start) = window.find(prefix) {
                    let after_prefix = &window[sym_start + prefix.len()..];
                    if let Some(quote_end) = after_prefix.find('\"') {
                        KeyExpr::Symbol(after_prefix[..quote_end].to_string())
                    } else {
                        KeyExpr::Unknown(format!("unparseable_key_{}", idx))
                    }
                } else {
                    KeyExpr::Unknown(format!("dynamic_key_{}", idx))
                };

                // Determine storage domain
                let storage_type = if window.contains("instance()") {
                    StorageDomain::Instance
                } else if window.contains("persistent()") {
                    StorageDomain::Persistent
                } else if window.contains("temporary()") {
                    StorageDomain::Temporary
                } else {
                    StorageDomain::Instance // default
                };

                // Try to infer value type from context
                let value_type = self.infer_type_from_context(window);

                accesses.push(StorageAccess {
                    location: format!("{}_offset_{}", operation, idx),
                    key: key.clone(),
                    access_type: access_type.clone(),
                    storage_type,
                    value_type,
                    logical_source: format!("{}_at_{}", operation, idx),
                });
            }
        }

        Ok(accesses)
    }

    /// Infer the Soroban type from a code context window.
    fn infer_type_from_context(&self, context: &str) -> Option<StoredType> {
        if context.contains("i128") {
            Some(StoredType::I128)
        } else if context.contains("i64") {
            Some(StoredType::I64)
        } else if context.contains("i32") {
            Some(StoredType::I32)
        } else if context.contains("u128") {
            Some(StoredType::U128)
        } else if context.contains("u64") {
            Some(StoredType::U64)
        } else if context.contains("u32") {
            Some(StoredType::U32)
        } else if context.contains("Address") {
            Some(StoredType::Address)
        } else if context.contains("Symbol") {
            Some(StoredType::Symbol)
        } else if context.contains("Bytes") {
            Some(StoredType::Bytes)
        } else if context.contains("String") {
            Some(StoredType::String)
        } else if context.contains("bool") {
            Some(StoredType::Bool)
        } else if context.contains("Vec") {
            Some(StoredType::Vec(Box::new(StoredType::Unknown)))
        } else if context.contains("Map") {
            Some(StoredType::Map(
                Box::new(StoredType::Unknown),
                Box::new(StoredType::Unknown),
            ))
        } else {
            None
        }
    }

    /// Compare old and new storage footprints and produce a report.
    fn compare_footprints(
        &self,
        old: &StorageFootprint,
        new: &StorageFootprint,
    ) -> Result<StorageSafetyReport> {
        let mut collisions = Vec::new();
        let mut orphaned_keys = Vec::new();
        let mut new_keys = Vec::new();
        let mut compatible_keys = Vec::new();
        let mut critical_issues = Vec::new();
        let mut warnings = Vec::new();

        // Find key collisions: keys present in BOTH old and new
        for old_key in &old.key_set {
            if new.key_set.contains(old_key) {
                // Key exists in both - check for type mismatches and logical source differences
                let old_type = old
                    .write_types
                    .get(old_key)
                    .or_else(|| old.read_types.get(old_key));
                let new_type = new
                    .write_types
                    .get(old_key)
                    .or_else(|| new.read_types.get(old_key));

                // Find the logical sources for this key
                let old_source = old
                    .accesses
                    .iter()
                    .find(|a| &a.key == old_key)
                    .map(|a| a.logical_source.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let new_source = new
                    .accesses
                    .iter()
                    .find(|a| &a.key == old_key)
                    .map(|a| a.logical_source.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                let type_mismatch = match (old_type, new_type) {
                    (Some(ot), Some(nt)) => ot != nt,
                    _ => false,
                };

                if type_mismatch {
                    let issue = format!(
                        "Type mismatch for key '{}': old type is {:?}, new type is {:?}",
                        old_key, old_type, new_type
                    );
                    critical_issues.push(issue.clone());

                    collisions.push(KeyCollision {
                        key: old_key.clone(),
                        old_logical_source: old_source,
                        new_logical_source: new_source,
                        old_type: old_type.cloned(),
                        new_type: new_type.cloned(),
                        type_mismatch: true,
                        collision_condition: None,
                        severity: CollisionSeverity::Critical,
                        description: issue,
                    });
                } else if old_source != new_source {
                    // Same key, different logical source - potential collision
                    let issue = format!(
                        "Same key '{}' used for different data: old='{}' vs new='{}'",
                        old_key, old_source, new_source
                    );
                    warnings.push(issue.clone());

                    collisions.push(KeyCollision {
                        key: old_key.clone(),
                        old_logical_source: old_source,
                        new_logical_source: new_source,
                        old_type: old_type.cloned(),
                        new_type: new_type.cloned(),
                        type_mismatch: false,
                        collision_condition: None,
                        severity: CollisionSeverity::Warning,
                        description: issue,
                    });
                } else {
                    compatible_keys.push(old_key.clone());
                }
            } else {
                // Key in old but not in new → orphaned
                let is_critical = self.is_critical_key(old_key);
                let old_type = old
                    .write_types
                    .get(old_key)
                    .or_else(|| old.read_types.get(old_key));

                let migration = if is_critical {
                    MigrationSuggestion::MigrateTo {
                        old_key: old_key.to_string(),
                        new_key: format!("{}_v2", old_key),
                    }
                } else {
                    MigrationSuggestion::Remove(format!(
                        "Key '{}' is no longer used in the new contract version",
                        old_key
                    ))
                };

                if is_critical {
                    critical_issues.push(format!(
                        "Critical key '{}' will be orphaned after upgrade. Migration required.",
                        old_key
                    ));
                } else {
                    warnings.push(format!("Key '{}' will be orphaned after upgrade.", old_key));
                }

                orphaned_keys.push(OrphanedKey {
                    key: old_key.clone(),
                    value_type: old_type.cloned(),
                    is_critical,
                    migration_suggestion: migration,
                });
            }
        }

        // Find new keys (in new but not in old)
        for new_key in &new.key_set {
            if !old.key_set.contains(new_key) {
                new_keys.push(new_key.clone());
            }
        }

        // Check for dynamic key collisions
        let dynamic_collisions = self.detect_dynamic_key_collisions(old, new);
        collisions.extend(dynamic_collisions);

        let migration_required = !critical_issues.is_empty();

        // Generate migration skeleton if needed
        let migration_skeleton = if migration_required {
            Some(self.generate_migration_skeleton(&orphaned_keys, &collisions))
        } else {
            None
        };

        let summary = if migration_required {
            format!(
                "Storage migration required: {} collisions, {} orphaned keys, {} new keys. {} critical issue(s) found.",
                collisions.len(),
                orphaned_keys.len(),
                new_keys.len(),
                critical_issues.len(),
            )
        } else if !warnings.is_empty() {
            format!(
                "Storage compatible with warnings: {} warning(s). {} orphaned keys, {} new keys.",
                warnings.len(),
                orphaned_keys.len(),
                new_keys.len(),
            )
        } else {
            format!(
                "Storage fully compatible. {} compatible keys, {} new keys.",
                compatible_keys.len(),
                new_keys.len(),
            )
        };

        Ok(StorageSafetyReport {
            summary,
            collisions,
            orphaned_keys,
            new_keys,
            compatible_keys,
            migration_required,
            critical_issues,
            warnings,
            migration_skeleton,
        })
    }

    /// Detect dynamic key collisions where two different logical variables could
    /// produce the same concrete key at runtime.
    fn detect_dynamic_key_collisions(
        &self,
        old: &StorageFootprint,
        new: &StorageFootprint,
    ) -> Vec<KeyCollision> {
        let mut collisions = Vec::new();

        // Find keys with Unknown/Concat expressions that could overlap at runtime
        for old_access in &old.accesses {
            if matches!(old_access.key, KeyExpr::Unknown(_) | KeyExpr::Concat(_, _)) {
                for new_access in &new.accesses {
                    if matches!(new_access.key, KeyExpr::Unknown(_) | KeyExpr::Concat(_, _)) {
                        // Check if the logical sources differ but keys could collide at runtime
                        if old_access.logical_source != new_access.logical_source {
                            // Check for potential collision based on key structure
                            if self.could_collide_at_runtime(&old_access.key, &new_access.key) {
                                collisions.push(KeyCollision {
                                    key: old_access.key.clone(),
                                    old_logical_source: old_access.logical_source.clone(),
                                    new_logical_source: new_access.logical_source.clone(),
                                    old_type: old_access.value_type.clone(),
                                    new_type: new_access.value_type.clone(),
                                    type_mismatch: old_access.value_type != new_access.value_type,
                                    collision_condition: Some(format!(
                                        "Dynamic collision possible between '{}' and '{}'",
                                        old_access.logical_source, new_access.logical_source
                                    )),
                                    severity: CollisionSeverity::Warning,
                                    description: format!(
                                        "Potential dynamic collision: '{}' (old) vs '{}' (new) - values computed at runtime may overlap",
                                        old_access.logical_source, new_access.logical_source
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        collisions
    }

    /// Check if two key expressions could produce the same value at runtime.
    fn could_collide_at_runtime(&self, a: &KeyExpr, b: &KeyExpr) -> bool {
        // Two Unknown keys with similar structure could collide
        match (a, b) {
            (KeyExpr::Unknown(a_str), KeyExpr::Unknown(b_str)) => {
                // Same unknown pattern likely uses same key computation path
                a_str == b_str
            }
            (KeyExpr::Concat(_, _), KeyExpr::Concat(_, _)) => true,
            (KeyExpr::Concat(_, _), KeyExpr::Unknown(_)) => true,
            (KeyExpr::Unknown(_), KeyExpr::Concat(_, _)) => true,
            _ => false,
        }
    }

    /// Check if a storage key is critical (contains balance, ownership, or supply data).
    fn is_critical_key(&self, key: &KeyExpr) -> bool {
        let key_str = key.to_string().to_lowercase();
        key_str.contains("balance")
            || key_str.contains("total_supply")
            || key_str.contains("owner")
            || key_str.contains("admin")
            || key_str.contains("escrow")
            || key_str.contains("allowance")
    }

    /// Generate a Rust migration function skeleton for the developer to fill in.
    fn generate_migration_skeleton(
        &self,
        orphaned: &[OrphanedKey],
        collisions: &[KeyCollision],
    ) -> String {
        let mut skeleton = String::new();
        skeleton.push_str("/// Migration function for upgrading from old storage layout to new.\n");
        skeleton.push_str("/// This function should be called once during the upgrade process.\n");
        skeleton.push_str("pub fn migrate_storage(env: &Env) {\n");

        for o in orphaned {
            match &o.migration_suggestion {
                MigrationSuggestion::Remove(reason) => {
                    skeleton.push_str(&format!(
                        "    // WARNING: {} → removing key '{}'\n",
                        reason, o.key
                    ));
                    skeleton.push_str(&format!(
                        "    // env.storage().instance().remove(&Symbol::new(env, \"{}\"));\n",
                        o.key
                    ));
                }
                MigrationSuggestion::MigrateTo { old_key, new_key } => {
                    skeleton.push_str(&format!("    // Migrate '{}' → '{}':\n", old_key, new_key));
                    skeleton.push_str(&format!(
                        "    // let old_val: Option<Data> = env.storage().instance().get(&Symbol::new(env, \"{}\"));\n",
                        old_key
                    ));
                    skeleton.push_str("    // if let Some(val) = old_val {\n");
                    skeleton.push_str(&format!(
                        "    //     env.storage().instance().set(&Symbol::new(env, \"{}\"), &val);\n",
                        new_key
                    ));
                    skeleton.push_str(&format!(
                        "    //     env.storage().instance().remove(&Symbol::new(env, \"{}\"));\n",
                        old_key
                    ));
                    skeleton.push_str("    // }\n");
                }
                MigrationSuggestion::Export(reason) => {
                    skeleton.push_str(&format!("    // Export '{}': {}\n", o.key, reason));
                }
                MigrationSuggestion::Keep => {
                    skeleton.push_str(&format!(
                        "    // Key '{}' is intentionally preserved\n",
                        o.key
                    ));
                }
            }
        }

        for c in collisions {
            if c.type_mismatch {
                skeleton.push_str(&format!(
                    "    // Type mismatch: key '{}' was {:?} in old, now {:?} in new.\n",
                    c.key, c.old_type, c.new_type,
                ));
                skeleton.push_str("    // You must convert the value type before the upgrade.\n");
            }
        }

        skeleton.push_str("}\n");
        skeleton
    }
}

impl Default for StorageSafetyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── CLI Integration ──────────────────────────────────────────────────────

/// Run the storage safety audit from the CLI.
/// Usage: `stellar-scanner storage-audit --old <wasm> --new <wasm>`
pub fn run_storage_audit(old_wasm_path: &str, new_wasm_path: &str) -> Result<()> {
    use std::fs;

    let old_wasm = fs::read(old_wasm_path)
        .map_err(|e| anyhow!("Failed to read old WASM file '{}': {}", old_wasm_path, e))?;
    let new_wasm = fs::read(new_wasm_path)
        .map_err(|e| anyhow!("Failed to read new WASM file '{}': {}", new_wasm_path, e))?;

    let analyzer = StorageSafetyAnalyzer::new();
    let report = analyzer.analyze_upgrade(&old_wasm, &new_wasm)?;

    println!("{}", report.to_readable_string());

    if report.has_critical_issues() {
        eprintln!(
            "\n❌ Storage safety audit FAILED: {} critical issue(s) found.",
            report.critical_issues.len()
        );
        eprintln!("   Fix the critical issues before proceeding with the upgrade.");
        std::process::exit(1);
    } else if report.migration_required {
        println!(
            "\n⚠️  Storage safety audit passed with warnings. Review the warnings before upgrading."
        );
    } else {
        println!("\n✅ Storage safety audit PASSED. No issues detected.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expr_display() {
        let key = KeyExpr::Symbol("admin".to_string());
        assert_eq!(key.to_string(), "Symbol(\"admin\")");

        let key = KeyExpr::Concat(
            Box::new(KeyExpr::Symbol("balance_".to_string())),
            Box::new(KeyExpr::AddressParam(0)),
        );
        assert!(key.to_string().contains("Concat"));
    }

    #[test]
    fn test_storage_footprint_add_access() {
        let mut footprint = StorageFootprint::new();
        let access = StorageAccess {
            location: "test_fn".to_string(),
            key: KeyExpr::Symbol("balance".to_string()),
            access_type: AccessType::Set,
            storage_type: StorageDomain::Persistent,
            value_type: Some(StoredType::I128),
            logical_source: "user_balance".to_string(),
        };
        footprint.add_access(access);
        assert_eq!(footprint.accesses.len(), 1);
        assert_eq!(footprint.key_set.len(), 1);
        assert_eq!(footprint.write_types.len(), 1);
    }

    #[test]
    fn test_is_critical_key() {
        let analyzer = StorageSafetyAnalyzer::new();
        assert!(analyzer.is_critical_key(&KeyExpr::Symbol("balance".to_string())));
        assert!(analyzer.is_critical_key(&KeyExpr::Symbol("total_supply".to_string())));
        assert!(analyzer.is_critical_key(&KeyExpr::Symbol("owner".to_string())));
        assert!(!analyzer.is_critical_key(&KeyExpr::Symbol("counter".to_string())));
        assert!(!analyzer.is_critical_key(&KeyExpr::Symbol("temp".to_string())));
    }

    #[test]
    fn test_empty_wasm_audit() {
        let analyzer = StorageSafetyAnalyzer::new();
        // Invalid WASM (not starting with magic bytes) should return an error
        let result = analyzer.analyze_upgrade(b"not-wasm", b"also-not-wasm");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_wasm_audit() {
        let analyzer = StorageSafetyAnalyzer::new();
        // Minimal valid WASM header
        let wasm = b"\0asm\x01\0\0\0";
        let result = analyzer.analyze_upgrade(wasm, wasm);
        assert!(result.is_ok());
        let report = result.unwrap();
        // Same WASM should have zero collisions
        assert_eq!(report.collisions.len(), 0);
        assert!(!report.migration_required);
    }

    #[test]
    fn test_type_mismatch_detection() {
        let analyzer = StorageSafetyAnalyzer::new();

        let mut old = StorageFootprint::new();
        old.add_access(StorageAccess {
            location: "fn1".to_string(),
            key: KeyExpr::Symbol("balance".to_string()),
            access_type: AccessType::Set,
            storage_type: StorageDomain::Persistent,
            value_type: Some(StoredType::I128),
            logical_source: "balance".to_string(),
        });

        let mut new = StorageFootprint::new();
        new.add_access(StorageAccess {
            location: "fn2".to_string(),
            key: KeyExpr::Symbol("balance".to_string()),
            access_type: AccessType::Get,
            storage_type: StorageDomain::Persistent,
            value_type: Some(StoredType::U64),
            logical_source: "balance".to_string(),
        });

        let report = analyzer.analyze_footprints(&old, &new).unwrap();
        // Same key, different types → type mismatch collision
        assert!(!report.collisions.is_empty());
        assert!(report.collisions.iter().any(|c| c.type_mismatch));
    }

    #[test]
    fn test_orphaned_key_detection() {
        let analyzer = StorageSafetyAnalyzer::new();

        let mut old = StorageFootprint::new();
        old.add_access(StorageAccess {
            location: "fn1".to_string(),
            key: KeyExpr::Symbol("old_counter".to_string()),
            access_type: AccessType::Set,
            storage_type: StorageDomain::Instance,
            value_type: Some(StoredType::U32),
            logical_source: "counter".to_string(),
        });

        let new = StorageFootprint::new(); // Empty footprint

        let report = analyzer.analyze_footprints(&old, &new).unwrap();
        assert!(!report.orphaned_keys.is_empty());
        assert_eq!(report.orphaned_keys.len(), 1);
    }

    #[test]
    fn test_compatible_keys() {
        let analyzer = StorageSafetyAnalyzer::new();

        let make_access = |key: &str| StorageAccess {
            location: "fn".to_string(),
            key: KeyExpr::Symbol(key.to_string()),
            access_type: AccessType::Set,
            storage_type: StorageDomain::Instance,
            value_type: Some(StoredType::U32),
            logical_source: key.to_string(),
        };

        let mut old = StorageFootprint::new();
        old.add_access(make_access("admin"));

        let mut new = StorageFootprint::new();
        new.add_access(make_access("admin"));

        let report = analyzer.analyze_footprints(&old, &new).unwrap();
        assert!(!report.compatible_keys.is_empty());
        assert!(report.collisions.is_empty());
    }

    #[test]
    fn test_migration_skeleton_generation() {
        let analyzer = StorageSafetyAnalyzer::new();

        let orphaned = vec![OrphanedKey {
            key: KeyExpr::Symbol("old_balance".to_string()),
            value_type: Some(StoredType::I128),
            is_critical: true,
            migration_suggestion: MigrationSuggestion::MigrateTo {
                old_key: "old_balance".to_string(),
                new_key: "balance_v2".to_string(),
            },
        }];

        let collisions = vec![KeyCollision {
            key: KeyExpr::Symbol("data".to_string()),
            old_logical_source: "old_data".to_string(),
            new_logical_source: "new_data".to_string(),
            old_type: Some(StoredType::U32),
            new_type: Some(StoredType::U64),
            type_mismatch: true,
            collision_condition: None,
            severity: CollisionSeverity::Critical,
            description: "Type mismatch".to_string(),
        }];

        let skeleton = analyzer.generate_migration_skeleton(&orphaned, &collisions);
        assert!(skeleton.contains("migrate_storage"));
        assert!(skeleton.contains("old_balance"));
        assert!(skeleton.contains("balance_v2"));
        assert!(skeleton.contains("Type mismatch"));
    }
}
