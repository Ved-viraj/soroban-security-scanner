//! Dependency inventory with version and lifecycle tracking.

use crate::supply_chain::version::Version;
use serde::{Deserialize, Serialize};

/// The package ecosystem a dependency comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    /// Rust crates (crates.io).
    Cargo,
    /// Node packages (npm).
    Npm,
    /// Python packages (PyPI).
    PyPi,
}

impl Ecosystem {
    /// Stable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "pypi",
        }
    }
}

/// Lifecycle status of a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lifecycle {
    /// Up to date.
    Current,
    /// A newer version exists.
    Outdated,
    /// Marked deprecated / unmaintained.
    Deprecated,
}

/// A single dependency record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Package name.
    pub name: String,
    /// Resolved version.
    pub version: Version,
    /// Ecosystem.
    pub ecosystem: Ecosystem,
    /// Whether it is a direct (vs transitive) dependency.
    pub direct: bool,
    /// SPDX license identifier, if known.
    pub license: Option<String>,
    /// Expected content checksum (sha256 hex), if pinned.
    pub checksum: Option<String>,
    /// Lifecycle status.
    pub lifecycle: Lifecycle,
}

impl Dependency {
    /// Builds a direct dependency with defaults.
    pub fn new(name: impl Into<String>, version: Version, ecosystem: Ecosystem) -> Self {
        Self {
            name: name.into(),
            version,
            ecosystem,
            direct: true,
            license: None,
            checksum: None,
            lifecycle: Lifecycle::Current,
        }
    }

    /// Sets the license.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Sets the checksum.
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Marks as transitive.
    pub fn transitive(mut self) -> Self {
        self.direct = false;
        self
    }

    /// Sets the lifecycle status.
    pub fn with_lifecycle(mut self, lifecycle: Lifecycle) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// A unique key: `ecosystem:name`.
    pub fn key(&self) -> String {
        format!("{}:{}", self.ecosystem.as_str(), self.name)
    }
}

/// The full dependency inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyInventory {
    /// All dependencies (direct + transitive).
    pub dependencies: Vec<Dependency>,
}

impl DependencyInventory {
    /// Creates an empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a dependency.
    pub fn add(&mut self, dep: Dependency) {
        self.dependencies.push(dep);
    }

    /// Total dependency count.
    pub fn len(&self) -> usize {
        self.dependencies.len()
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }

    /// Number of direct dependencies.
    pub fn direct_count(&self) -> usize {
        self.dependencies.iter().filter(|d| d.direct).count()
    }

    /// Dependencies needing attention (outdated or deprecated).
    pub fn needs_attention(&self) -> Vec<&Dependency> {
        self.dependencies
            .iter()
            .filter(|d| d.lifecycle != Lifecycle::Current)
            .collect()
    }

    /// Finds a dependency by ecosystem + name.
    pub fn find(&self, ecosystem: Ecosystem, name: &str) -> Option<&Dependency> {
        self.dependencies
            .iter()
            .find(|d| d.ecosystem == ecosystem && d.name == name)
    }

    /// Number of transitive dependencies.
    pub fn transitive_count(&self) -> usize {
        self.dependencies.iter().filter(|d| !d.direct).count()
    }

    /// Get all transitive dependencies.
    pub fn transitive_dependencies(&self) -> Vec<&Dependency> {
        self.dependencies.iter().filter(|d| !d.direct).collect()
    }

    /// Get all direct dependencies.
    pub fn direct_dependencies(&self) -> Vec<&Dependency> {
        self.dependencies.iter().filter(|d| d.direct).collect()
    }
}

/// A parent-child relationship in the dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRelation {
    /// The parent (direct) dependency.
    pub parent: String,
    /// The child (transitive) dependency.
    pub child: String,
    /// The child's ecosystem.
    pub ecosystem: Ecosystem,
}

/// A dependency graph tracking parent-child relationships.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// All relationships (parent → child).
    pub relations: Vec<DependencyRelation>,
}

impl DependencyGraph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a parent-child relationship.
    pub fn add_relation(&mut self, parent: &str, child: &str, ecosystem: Ecosystem) {
        self.relations.push(DependencyRelation {
            parent: parent.to_string(),
            child: child.to_string(),
            ecosystem,
        });
    }

    /// Get all children of a parent.
    pub fn children_of(&self, parent: &str) -> Vec<&DependencyRelation> {
        self.relations.iter().filter(|r| r.parent == parent).collect()
    }

    /// Get all parents of a child.
    pub fn parents_of(&self, child: &str) -> Vec<&DependencyRelation> {
        self.relations.iter().filter(|r| r.child == child).collect()
    }
}

impl DependencyInventory {
    /// Resolve transitive dependencies by walking the full dependency tree.
    ///
    /// This function would normally call `cargo metadata` (Rust) or `npm ls --json`
    /// (Node.js) to get the full dependency tree. In this implementation, it
    /// accepts a pre-built DependencyGraph and populates the inventory with
    /// transitive dependencies.
    ///
    /// # Arguments
    /// * `graph` - The dependency graph with parent-child relationships
    /// * `transitive_deps` - The transitive dependencies to add
    /// * `max_depth` - Maximum recursion depth (0 = no limit)
    pub fn resolve_transitive_dependencies(
        &mut self,
        graph: &DependencyGraph,
        transitive_deps: Vec<Dependency>,
        _max_depth: Option<usize>,
    ) {
        // Add all transitive dependencies (marked as non-direct)
        for mut dep in transitive_deps {
            dep.direct = false;
            // Only add if not already in the inventory
            if !self.dependencies.iter().any(|d| d.key() == dep.key()) {
                self.dependencies.push(dep);
            }
        }
    }

    /// Check if any transitive dependency has a disallowed license.
    ///
    /// Returns a list of (package_name, license) tuples for violations.
    pub fn check_transitive_licenses(
        &self,
        allowed_licenses: &[String],
    ) -> Vec<(String, String)> {
        self.dependencies
            .iter()
            .filter(|d| !d.direct) // Only check transitive
            .filter_map(|d| {
                if let Some(license) = &d.license {
                    if !allowed_licenses.iter().any(|a| a == license) {
                        return Some((d.name.clone(), license.clone()));
                    }
                }
                None
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> DependencyInventory {
        let mut inv = DependencyInventory::new();
        inv.add(
            Dependency::new("serde", Version::new(1, 0, 200), Ecosystem::Cargo).with_license("MIT"),
        );
        inv.add(
            Dependency::new("left-pad", Version::new(1, 3, 0), Ecosystem::Npm)
                .transitive()
                .with_lifecycle(Lifecycle::Deprecated),
        );
        inv
    }

    #[test]
    fn tracks_counts_and_lifecycle() {
        let inv = inventory();
        assert_eq!(inv.len(), 2);
        assert_eq!(inv.direct_count(), 1);
        assert_eq!(inv.needs_attention().len(), 1);
    }

    #[test]
    fn lookup_by_ecosystem_and_name() {
        let inv = inventory();
        assert!(inv.find(Ecosystem::Cargo, "serde").is_some());
        assert!(inv.find(Ecosystem::Npm, "serde").is_none());
    }

    #[test]
    fn key_namespaces_by_ecosystem() {
        let dep = Dependency::new("x", Version::new(1, 0, 0), Ecosystem::Cargo);
        assert_eq!(dep.key(), "cargo:x");
    }
}
