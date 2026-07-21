//! Incremental scan support for the Stellar Security Scanner.
//!
//! This module provides a scan manifest system that tracks file hashes
//! and dependencies, enabling the scanner to only re-scan files that
//! have changed since the last run.

use crate::ScanResult;
use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Directory where the scan manifest is stored, relative to the project root.
pub const SCANNER_DIR: &str = ".stellar-scanner";
/// Name of the manifest file.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Current manifest schema version for forward/backward compatibility.
pub const MANIFEST_VERSION: u32 = 1;

/// A persistent record of the last scan, tracking file hashes and
/// dependencies so that future scans can be incremental.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanManifest {
    /// Schema version for forward/backward compatibility.
    pub version: u32,
    /// Unix timestamp (seconds) of the last completed scan.
    pub last_scan_timestamp: u64,
    /// Total number of files in the previous scan.
    pub total_files: usize,
    /// Duration of the previous scan in milliseconds.
    pub previous_scan_duration_ms: u64,
    /// Per-file metadata, keyed by relative path from the project root.
    pub files: HashMap<String, FileInfo>,
}

/// Per-file metadata stored in the scan manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// SHA-256 hash of the file contents.
    pub hash: String,
    /// Module paths imported by this file (e.g., `crate::config`, `crate::analysis`).
    pub dependencies: Vec<String>,
    /// Unix timestamp (seconds) when this file was last scanned.
    pub last_scan_timestamp: u64,
}

/// Result of computing which files are affected by changes.
#[derive(Debug, Clone)]
pub struct IncrementalScanPlan {
    /// Files that should be scanned (changed + dependents).
    pub files_to_scan: HashSet<String>,
    /// Files that are unchanged and can be skipped.
    pub files_to_skip: HashSet<String>,
    /// Total number of files in the project.
    pub total_files: usize,
    /// Estimated full scan time based on previous average per-file time.
    pub estimated_full_scan_seconds: f64,
}

impl ScanManifest {
    /// Create a new empty manifest.
    pub fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            last_scan_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            total_files: 0,
            previous_scan_duration_ms: 0,
            files: HashMap::new(),
        }
    }

    /// Load the manifest from the `.stellar-scanner/manifest.json` file.
    ///
    /// Returns `None` if no manifest exists yet (first scan).
    pub fn load(project_root: &Path) -> Result<Option<Self>> {
        let manifest_path = Self::manifest_path(project_root);
        if !manifest_path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&manifest_path)
            .with_context(|| format!("Failed to read manifest at {}", manifest_path.display()))?;
        let manifest: ScanManifest =
            serde_json::from_str(&content).with_context(|| "Failed to parse scan manifest")?;
        Ok(Some(manifest))
    }

    /// Save the manifest to the `.stellar-scanner/manifest.json` file.
    pub fn save(&self, project_root: &Path) -> Result<()> {
        let scanner_dir = project_root.join(SCANNER_DIR);
        fs::create_dir_all(&scanner_dir)
            .with_context(|| format!("Failed to create directory {}", scanner_dir.display()))?;

        let manifest_path = Self::manifest_path(project_root);
        let content = serde_json::to_string_pretty(self)
            .with_context(|| "Failed to serialize scan manifest")?;
        fs::write(&manifest_path, content)
            .with_context(|| format!("Failed to write manifest to {}", manifest_path.display()))?;

        info!(
            "Scan manifest saved: {} files tracked in {}",
            self.files.len(),
            manifest_path.display()
        );
        Ok(())
    }

    /// Delete the manifest (useful after --force-full to reset state).
    pub fn delete(project_root: &Path) -> Result<()> {
        let manifest_path = Self::manifest_path(project_root);
        if manifest_path.exists() {
            fs::remove_file(&manifest_path).with_context(|| {
                format!("Failed to delete manifest at {}", manifest_path.display())
            })?;
        }
        Ok(())
    }

    /// Get the full path to the manifest file.
    pub fn manifest_path(project_root: &Path) -> PathBuf {
        project_root.join(SCANNER_DIR).join(MANIFEST_FILE)
    }

    /// Update the manifest with the results of a scan.
    ///
    /// Updates file info for scanned files and preserves existing info for
    /// unchanged files.
    pub fn update(
        &mut self,
        scanned_files: &HashSet<String>,
        all_file_info: &HashMap<String, (String, Vec<String>)>,
        scan_duration_ms: u64,
    ) {
        self.last_scan_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.previous_scan_duration_ms = scan_duration_ms;
        self.total_files = all_file_info.len();

        let now = self.last_scan_timestamp;

        for (path, (hash, deps)) in all_file_info {
            let was_scanned = scanned_files.contains(path);
            self.files.insert(
                path.clone(),
                FileInfo {
                    hash: hash.clone(),
                    dependencies: deps.clone(),
                    last_scan_timestamp: if was_scanned {
                        now
                    } else {
                        self.files
                            .get(path)
                            .map(|f| f.last_scan_timestamp)
                            .unwrap_or(now)
                    },
                },
            );
        }
    }

    /// Compute files affected by changes since the last scan.
    ///
    /// Returns a plan that identifies which files need to be scanned
    /// and which can be skipped.
    pub fn compute_affected_files(
        &self,
        current_file_info: &HashMap<String, (String, Vec<String>)>,
    ) -> IncrementalScanPlan {
        let total_files = current_file_info.len();

        // Find directly changed files (new, modified, or deleted)
        let mut directly_changed: HashSet<String> = HashSet::new();
        let mut unchanged: HashSet<String> = HashSet::new();

        for (path, (hash, _deps)) in current_file_info {
            match self.files.get(path) {
                Some(existing) if existing.hash == *hash => {
                    unchanged.insert(path.clone());
                }
                _ => {
                    // New file, modified file, or hash mismatch
                    directly_changed.insert(path.clone());
                }
            }
        }

        // Files in manifest but no longer in current_file_info are deleted
        // - they are not added to directly_changed since they don't exist

        // Build the inverse dependency graph:
        // For each file, which other files depend on it?
        let mut dependents_of: HashMap<&str, HashSet<&str>> = HashMap::new();

        for (path, (_hash, deps)) in current_file_info {
            for dep in deps {
                // Resolve the dependency to a file path
                if let Some(dep_path) = Self::resolve_module_to_file(dep, current_file_info) {
                    dependents_of
                        .entry(dep_path)
                        .or_default()
                        .insert(path.as_str());
                }
            }
        }

        // BFS to find all transitively affected files
        let mut files_to_scan: HashSet<String> = directly_changed.clone();
        let mut queue: VecDeque<String> = directly_changed.iter().cloned().collect();

        while let Some(changed_file) = queue.pop_front() {
            if let Some(dependents) = dependents_of.get(changed_file.as_str()) {
                for dependent in dependents {
                    let dep_str = dependent.to_string();
                    if files_to_scan.insert(dep_str.clone()) {
                        queue.push_back(dep_str);
                    }
                }
            }
        }

        // Files to skip = all files minus files to scan
        let files_to_skip: HashSet<String> = current_file_info
            .keys()
            .filter(|p| !files_to_scan.contains(*p))
            .cloned()
            .collect();

        // Estimate full scan time based on actual previous scan timing data
        let estimated_full_scan_seconds =
            if self.previous_scan_duration_ms > 0 && self.total_files > 0 {
                let per_file_ms = self.previous_scan_duration_ms as f64 / self.total_files as f64;
                (per_file_ms * total_files as f64) / 1000.0
            } else {
                // Fallback: assume ~5 seconds per file
                total_files as f64 * 5.0
            };

        IncrementalScanPlan {
            files_to_scan,
            files_to_skip,
            total_files,
            estimated_full_scan_seconds,
        }
    }

    /// Resolve a Rust module path to a file path relative to the project root.
    ///
    /// Handles common patterns:
    /// - `crate::foo::bar` → `src/foo/bar.rs` or `src/foo/bar/mod.rs`
    /// - `super::baz` → resolves relative to parent module
    /// - `foo` (bare use) → `src/foo.rs` or `src/foo/mod.rs`
    fn resolve_module_to_file<'a>(
        module_path: &str,
        file_info: &'a HashMap<String, (String, Vec<String>)>,
    ) -> Option<&'a str> {
        // Try the most common case: crate::module → src/module.rs
        let relative = if let Some(stripped) = module_path.strip_prefix("crate::") {
            stripped.replace("::", "/")
        } else if module_path.starts_with("super::") {
            // For super:: references, try to match against known files
            let stripped = module_path.strip_prefix("super::").unwrap_or(module_path);
            stripped.replace("::", "/")
        } else {
            module_path.replace("::", "/")
        };

        // Try src/{relative}.rs
        let candidate_rs = format!("src/{}.rs", relative);
        if file_info.contains_key(&candidate_rs) {
            // Find the key exactly
            return file_info
                .keys()
                .find(|k| **k == candidate_rs)
                .map(|s| s.as_str());
        }

        // Try src/{relative}/mod.rs
        let candidate_mod = format!("src/{}/mod.rs", relative);
        if file_info.contains_key(&candidate_mod) {
            return file_info
                .keys()
                .find(|k| **k == candidate_mod)
                .map(|s| s.as_str());
        }

        None
    }
}

impl Default for ScanManifest {
    fn default() -> Self {
        Self::new()
    }
}
/// Extract Rust imports and module declarations from source content.
///
/// Uses regex for speed; handles both single-line `use crate::foo::bar;`
/// and multi-line grouped imports like:
/// ```ignore
/// use crate::{
///     config::ScannerConfig,
///     analysis::AnalysisResult,
/// };
/// ```
///
/// Returns a list of module paths referenced by the file.
pub fn extract_dependencies(content: &str) -> Vec<String> {
    let mut deps = Vec::new();

    // Match single-line `use crate::foo::bar;` or `use foo::bar;`
    let use_re = regex::Regex::new(r"^\s*(?:pub\s+)?use\s+([\w:]+(?:::[\w:]+)*)\s*;").unwrap();
    // Match `mod foo;` (not `mod foo {`)
    let mod_re = regex::Regex::new(r"^\s*(?:pub\s+)?mod\s+(\w+)\s*;").unwrap();
    // Match grouped `use crate::{ ... };` - the opening brace
    let grouped_use_re =
        regex::Regex::new(r"^\s*(?:pub\s+)?use\s+([\w:]+(?:::[\w:]+)*)::\s*\{").unwrap();

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Check for grouped/multi-line use
        if let Some(caps) = grouped_use_re.captures(line) {
            let prefix = caps.get(1).unwrap().as_str().to_string();
            // Scan forward to collect items inside { ... }
            let mut j = i;
            while j < lines.len() {
                if lines[j].contains('}') && (j > i || !line.contains('}')) {
                    // Extract module names from all lines between { and }
                    for k in i..=j {
                        // Extract identifiers that look like module paths
                        let item_re = regex::Regex::new(r"(\w+(?:::(\w+))*)").unwrap();
                        for item_cap in item_re.captures_iter(lines[k]) {
                            let item = item_cap.get(1).unwrap().as_str();
                            // Skip keywords and the prefix itself
                            if item != "use"
                                && item != "pub"
                                && item != "crate"
                                && item != "self"
                                && item != "super"
                                && !item.starts_with("as ")
                            {
                                let full_path = format!("{}::{}", prefix, item);
                                if prefix.starts_with("crate::")
                                    || prefix.starts_with("super::")
                                    || !prefix.contains("::")
                                {
                                    deps.push(full_path);
                                }
                            }
                        }
                    }
                    i = j + 1;
                    break;
                }
                j += 1;
                if j >= lines.len() {
                    i += 1;
                    break;
                }
            }
            if i <= lines.len() && i > 0 && lines.get(i - 1).map_or(false, |l| l.contains('}')) {
                // Already advanced past the block
            } else {
                i += 1;
            }
            continue;
        }

        if let Some(caps) = use_re.captures(line) {
            let path = caps.get(1).unwrap().as_str();
            let path_str = path.to_string();
            // Only track crate-internal dependencies (crate::, super::)
            if path.starts_with("crate::") || path.starts_with("super::") || !path.contains("::") {
                deps.push(path_str);
            }
        }
        if let Some(caps) = mod_re.captures(line) {
            let mod_name = caps.get(1).unwrap().as_str();
            deps.push(mod_name.to_string());
        }

        i += 1;
    }

    deps
}

/// Compute the SHA-256 hash of file contents.
pub fn compute_file_hash(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)?;
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Scan a directory and collect file info for all `.rs` files.
///
/// Returns a map of relative path → (SHA-256 hash, dependencies).
pub fn collect_file_info(dir_path: &Path) -> Result<HashMap<String, (String, Vec<String>)>> {
    let mut file_info = HashMap::new();

    for entry in walkdir::WalkDir::new(dir_path) {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "rs") {
            let relative = path
                .strip_prefix(dir_path)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let content = fs::read_to_string(path)?;
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let hash = format!("{:x}", hasher.finalize());
            let deps = extract_dependencies(&content);

            file_info.insert(relative, (hash, deps));
        }
    }

    Ok(file_info)
}

/// Format the incremental scan summary message.
pub fn format_scan_summary(
    files_scanned: usize,
    files_skipped: usize,
    total_files: usize,
    actual_seconds: f64,
    estimated_full_seconds: f64,
) -> String {
    if files_skipped == 0 {
        format!(
            "Scanned {}/{} files (full scan) in {:.1}s",
            files_scanned, total_files, actual_seconds
        )
    } else {
        format!(
            "Scanned {}/{} files (incremental) in {:.1}s — full scan would have taken ~{:.0}s",
            files_scanned, total_files, actual_seconds, estimated_full_seconds
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_extract_dependencies() {
        let content = r#"
use crate::config::ScannerConfig;
use crate::analysis::AnalysisResult;
pub use super::utils;
use std::collections::HashMap;
mod tests;
"#;
        let deps = extract_dependencies(content);
        assert!(deps.contains(&"crate::config::ScannerConfig".to_string()));
        assert!(deps.contains(&"crate::analysis::AnalysisResult".to_string()));
        assert!(deps.contains(&"super::utils".to_string()));
        assert!(deps.contains(&"tests".to_string()));
        // std:: should NOT be included (not crate-internal)
        assert!(!deps.contains(&"std::collections::HashMap".to_string()));
    }

    #[test]
    fn test_compute_file_hash() -> Result<()> {
        let dir = TempDir::new()?;
        let file_path = dir.path().join("test.rs");
        let mut file = fs::File::create(&file_path)?;
        writeln!(file, "fn main() {{}}")?;

        let hash = compute_file_hash(&file_path)?;
        assert_eq!(hash.len(), 64); // SHA-256 is 64 hex chars
        Ok(())
    }

    #[test]
    fn test_manifest_save_and_load() -> Result<()> {
        let dir = TempDir::new()?;
        let project_root = dir.path();

        let mut manifest = ScanManifest::new();
        manifest.files.insert(
            "src/main.rs".to_string(),
            FileInfo {
                hash: "abc123".to_string(),
                dependencies: vec!["crate::config".to_string()],
                last_scan_timestamp: 1000,
            },
        );

        // Save
        manifest.save(project_root)?;
        assert!(project_root.join(SCANNER_DIR).join(MANIFEST_FILE).exists());

        // Load
        let loaded = ScanManifest::load(project_root)?.expect("manifest should exist");
        assert_eq!(loaded.version, MANIFEST_VERSION);
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.files.get("src/main.rs").unwrap().hash, "abc123");

        Ok(())
    }

    #[test]
    fn test_load_nonexistent_manifest() -> Result<()> {
        let dir = TempDir::new()?;
        let result = ScanManifest::load(dir.path())?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_collect_file_info() -> Result<()> {
        let dir = TempDir::new()?;

        // Create a few .rs files
        let main_rs = dir.path().join("main.rs");
        let mut f = fs::File::create(&main_rs)?;
        writeln!(f, "use crate::config;\nfn main() {{}}")?;

        let lib_rs = dir.path().join("lib.rs");
        let mut f = fs::File::create(&lib_rs)?;
        writeln!(f, "pub mod config;\npub fn hello() {{}}")?;

        // Create a non-.rs file that should be ignored
        let toml = dir.path().join("Cargo.toml");
        fs::File::create(&toml)?;

        let info = collect_file_info(dir.path())?;
        assert_eq!(info.len(), 2);
        assert!(info.contains_key("main.rs"));
        assert!(info.contains_key("lib.rs"));

        Ok(())
    }

    #[test]
    fn test_compute_affected_files_no_changes() {
        let mut manifest = ScanManifest::new();
        manifest.total_files = 2;

        manifest.files.insert(
            "src/a.rs".to_string(),
            FileInfo {
                hash: "hash_a".to_string(),
                dependencies: vec![],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/b.rs".to_string(),
            FileInfo {
                hash: "hash_b".to_string(),
                dependencies: vec!["crate::a".to_string()],
                last_scan_timestamp: 1000,
            },
        );

        // Same hashes - no changes
        let mut current = HashMap::new();
        current.insert("src/a.rs".to_string(), ("hash_a".to_string(), vec![]));
        current.insert(
            "src/b.rs".to_string(),
            ("hash_b".to_string(), vec!["crate::a".to_string()]),
        );

        let plan = manifest.compute_affected_files(&current);
        assert!(
            plan.files_to_scan.is_empty(),
            "No files should need rescanning"
        );
        assert_eq!(plan.files_to_skip.len(), 2);
    }

    #[test]
    fn test_compute_affected_files_one_changed() {
        let mut manifest = ScanManifest::new();
        manifest.total_files = 3;

        manifest.files.insert(
            "src/a.rs".to_string(),
            FileInfo {
                hash: "hash_a_old".to_string(),
                dependencies: vec![],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/b.rs".to_string(),
            FileInfo {
                hash: "hash_b".to_string(),
                dependencies: vec!["crate::a".to_string()],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/c.rs".to_string(),
            FileInfo {
                hash: "hash_c".to_string(),
                dependencies: vec![],
                last_scan_timestamp: 1000,
            },
        );

        // a.rs changed hash
        let mut current = HashMap::new();
        current.insert("src/a.rs".to_string(), ("hash_a_new".to_string(), vec![]));
        current.insert(
            "src/b.rs".to_string(),
            ("hash_b".to_string(), vec!["crate::a".to_string()]),
        );
        current.insert("src/c.rs".to_string(), ("hash_c".to_string(), vec![]));

        let plan = manifest.compute_affected_files(&current);

        // a.rs changed, b.rs depends on a, c.rs unchanged
        assert!(plan.files_to_scan.contains("src/a.rs"), "a.rs changed");
        assert!(
            plan.files_to_scan.contains("src/b.rs"),
            "b.rs depends on a.rs"
        );
        assert!(!plan.files_to_scan.contains("src/c.rs"), "c.rs unchanged");
        assert_eq!(plan.files_to_skip.len(), 1);
    }

    #[test]
    fn test_compute_affected_files_new_file() {
        let mut manifest = ScanManifest::new();
        manifest.total_files = 1;
        manifest.files.insert(
            "src/a.rs".to_string(),
            FileInfo {
                hash: "hash_a".to_string(),
                dependencies: vec![],
                last_scan_timestamp: 1000,
            },
        );

        // New file b.rs added
        let mut current = HashMap::new();
        current.insert("src/a.rs".to_string(), ("hash_a".to_string(), vec![]));
        current.insert(
            "src/b.rs".to_string(),
            ("hash_b".to_string(), vec!["crate::a".to_string()]),
        );

        let plan = manifest.compute_affected_files(&current);

        // b.rs is new, a.rs unchanged and NOT a dependency of b
        assert!(plan.files_to_scan.contains("src/b.rs"), "b.rs is new");
        assert!(!plan.files_to_scan.contains("src/a.rs"), "a.rs unchanged");
    }

    #[test]
    fn test_compute_affected_files_transitive() {
        // a → b → c (c depends on b, b depends on a)
        // Change a → scan a, b, c
        let mut manifest = ScanManifest::new();
        manifest.total_files = 3;

        manifest.files.insert(
            "src/a.rs".to_string(),
            FileInfo {
                hash: "hash_a_old".to_string(),
                dependencies: vec![],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/b.rs".to_string(),
            FileInfo {
                hash: "hash_b".to_string(),
                dependencies: vec!["crate::a".to_string()],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/c.rs".to_string(),
            FileInfo {
                hash: "hash_c".to_string(),
                dependencies: vec!["crate::b".to_string()],
                last_scan_timestamp: 1000,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            "src/a.rs".to_string(),
            ("hash_a_new".to_string(), vec![]), // changed
        );
        current.insert(
            "src/b.rs".to_string(),
            ("hash_b".to_string(), vec!["crate::a".to_string()]),
        );
        current.insert(
            "src/c.rs".to_string(),
            ("hash_c".to_string(), vec!["crate::b".to_string()]),
        );

        let plan = manifest.compute_affected_files(&current);

        assert!(plan.files_to_scan.contains("src/a.rs"), "a.rs changed");
        assert!(plan.files_to_scan.contains("src/b.rs"), "b depends on a");
        assert!(
            plan.files_to_scan.contains("src/c.rs"),
            "c depends on b, transitive"
        );
        assert_eq!(plan.files_to_scan.len(), 3);
    }

    #[test]
    fn test_format_scan_summary() {
        let summary = format_scan_summary(3, 47, 50, 12.4, 180.0);
        assert!(summary.contains("3/50"));
        assert!(summary.contains("incremental"));
        assert!(summary.contains("12.4s"));
        assert!(summary.contains("~180s"));

        let summary_full = format_scan_summary(50, 0, 50, 180.0, 180.0);
        assert!(summary_full.contains("full scan"));
    }

    #[test]
    fn test_resolve_module_to_file() {
        let mut file_info: HashMap<String, (String, Vec<String>)> = HashMap::new();
        file_info.insert("src/config.rs".to_string(), ("hash".to_string(), vec![]));
        file_info.insert("src/analysis.rs".to_string(), ("hash".to_string(), vec![]));
        file_info.insert("src/foo/mod.rs".to_string(), ("hash".to_string(), vec![]));

        // crate::config → src/config.rs
        let result = ScanManifest::resolve_module_to_file("crate::config", &file_info);
        assert_eq!(result, Some("src/config.rs"));

        // crate::analysis → src/analysis.rs
        let result = ScanManifest::resolve_module_to_file("crate::analysis", &file_info);
        assert_eq!(result, Some("src/analysis.rs"));

        // crate::foo → src/foo/mod.rs
        let result = ScanManifest::resolve_module_to_file("crate::foo", &file_info);
        assert!(result.is_some());
    }

    #[test]
    fn test_compute_affected_files_circular_dependency() {
        // A depends on B, B depends on A (circular)
        // Changing A should scan both A and B
        let mut manifest = ScanManifest::new();
        manifest.total_files = 2;

        manifest.files.insert(
            "src/a.rs".to_string(),
            FileInfo {
                hash: "hash_a_old".to_string(),
                dependencies: vec!["crate::b".to_string()],
                last_scan_timestamp: 1000,
            },
        );
        manifest.files.insert(
            "src/b.rs".to_string(),
            FileInfo {
                hash: "hash_b".to_string(),
                dependencies: vec!["crate::a".to_string()],
                last_scan_timestamp: 1000,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            "src/a.rs".to_string(),
            ("hash_a_new".to_string(), vec!["crate::b".to_string()]), // changed
        );
        current.insert(
            "src/b.rs".to_string(),
            ("hash_b".to_string(), vec!["crate::a".to_string()]),
        );

        let plan = manifest.compute_affected_files(&current);

        // Both should be scanned, but BFS terminates due to insert dedup
        assert!(plan.files_to_scan.contains("src/a.rs"));
        assert!(plan.files_to_scan.contains("src/b.rs"));
        assert_eq!(plan.files_to_scan.len(), 2);
        assert_eq!(plan.files_to_skip.len(), 0);
    }

    #[test]
    fn test_extract_dependencies_multi_line_use() {
        let content = r#"
use crate::{
    config::ScannerConfig,
    analysis::AnalysisResult,
    scanners::SecurityScanner,
};
"#;
        let deps = extract_dependencies(content);
        // Should find the grouped imports
        assert!(
            deps.iter().any(|d| d.contains("ScannerConfig")),
            "Should find ScannerConfig in grouped use. Got: {:?}",
            deps
        );
    }

    #[test]
    fn test_force_full_deletes_manifest() -> Result<()> {
        let dir = TempDir::new()?;
        let project_root = dir.path();

        // Create a manifest first
        let manifest = ScanManifest::new();
        manifest.save(project_root)?;
        assert!(ScanManifest::manifest_path(project_root).exists());

        // Delete it
        ScanManifest::delete(project_root)?;
        assert!(!ScanManifest::manifest_path(project_root).exists());

        // Deleting when none exists should not error
        ScanManifest::delete(project_root)?;

        Ok(())
    }
}
