//! Dependency security policy.
//!
//! Encodes the organization's rules: which licenses are allowed, which packages
//! are high-risk (always require human approval), and the severity at or above
//! which a vulnerable dependency must be addressed before release.

use crate::supply_chain::inventory::Dependency;
use crate::supply_chain::vuln::VulnSeverity;
use serde::{Deserialize, Serialize};

/// The scope at which license policy is evaluated (Issue #437).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicensePolicyScope {
    /// Only evaluate direct dependencies (current behavior).
    DirectOnly,
    /// Evaluate direct AND transitive dependencies (new default).
    DirectAndTransitive,
    /// Evaluate all but allow specific GPL packages via an ignore list.
    TransitiveIgnoreList,
}

/// The dependency security policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPolicy {
    /// Allowed SPDX license ids. Empty means "any license permitted".
    pub allowed_licenses: Vec<String>,
    /// Packages that always require manual approval to add or update.
    pub high_risk_packages: Vec<String>,
    /// Severity at/above which a vulnerability blocks release.
    pub block_at_severity: VulnSeverity,
    /// License policy scope (Issue #437).
    pub license_scope: LicensePolicyScope,
    /// Packages to ignore when checking transitive licenses (for TransitiveIgnoreList).
    pub transitive_ignore_list: Vec<String>,
}

impl Default for DependencyPolicy {
    fn default() -> Self {
        Self {
            allowed_licenses: vec![
                "MIT".to_string(),
                "Apache-2.0".to_string(),
                "BSD-3-Clause".to_string(),
                "ISC".to_string(),
            ],
            high_risk_packages: Vec::new(),
            block_at_severity: VulnSeverity::High,
            license_scope: LicensePolicyScope::DirectAndTransitive,
            transitive_ignore_list: Vec::new(),
        }
    }
}

/// A policy violation for a dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyViolation {
    /// The dependency's license is not on the allowlist.
    DisallowedLicense {
        /// Package name.
        package: String,
        /// The license found.
        license: String,
    },
    /// The dependency has no license information.
    MissingLicense {
        /// Package name.
        package: String,
    },
}

impl DependencyPolicy {
    /// Whether a package is classified high-risk.
    pub fn is_high_risk(&self, package: &str) -> bool {
        self.high_risk_packages.iter().any(|p| p == package)
    }

    /// Whether a vulnerability of `severity` must block release.
    pub fn blocks_release(&self, severity: VulnSeverity) -> bool {
        severity >= self.block_at_severity
    }

    /// Checks a dependency's license against the allowlist.
    pub fn check_license(&self, dep: &Dependency) -> Option<PolicyViolation> {
        if self.allowed_licenses.is_empty() {
            return None; // any license allowed
        }
        match &dep.license {
            None => Some(PolicyViolation::MissingLicense {
                package: dep.name.clone(),
            }),
            Some(license) if !self.allowed_licenses.contains(license) => {
                Some(PolicyViolation::DisallowedLicense {
                    package: dep.name.clone(),
                    license: license.clone(),
                })
            }
            Some(_) => None,
        }
    }

    /// Check license for a dependency, respecting the policy scope (Issue #437).
    ///
    /// - `DirectOnly`: Skip transitive dependencies
    /// - `DirectAndTransitive`: Check all dependencies
    /// - `TransitiveIgnoreList`: Check all but skip packages in the ignore list
    pub fn check_license_with_scope(&self, dep: &Dependency) -> Option<PolicyViolation> {
        match self.license_scope {
            LicensePolicyScope::DirectOnly => {
                if !dep.direct {
                    return None; // Skip transitive
                }
                self.check_license(dep)
            }
            LicensePolicyScope::DirectAndTransitive => {
                self.check_license(dep)
            }
            LicensePolicyScope::TransitiveIgnoreList => {
                if !dep.direct && self.transitive_ignore_list.contains(&dep.name) {
                    return None; // Skip ignored transitive package
                }
                self.check_license(dep)
            }
        }
    }

    /// Check all dependencies in an inventory for license violations (Issue #437).
    pub fn check_inventory(&self, inventory: &crate::supply_chain::inventory::DependencyInventory) -> Vec<PolicyViolation> {
        inventory
            .dependencies
            .iter()
            .filter_map(|d| self.check_license_with_scope(d))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::inventory::Ecosystem;
    use crate::supply_chain::version::Version;

    fn dep(license: Option<&str>) -> Dependency {
        let mut d = Dependency::new("pkg", Version::new(1, 0, 0), Ecosystem::Cargo);
        d.license = license.map(|s| s.to_string());
        d
    }

    #[test]
    fn allowed_license_passes() {
        let policy = DependencyPolicy::default();
        assert!(policy.check_license(&dep(Some("MIT"))).is_none());
    }

    #[test]
    fn disallowed_license_flagged() {
        let policy = DependencyPolicy::default();
        assert!(matches!(
            policy.check_license(&dep(Some("GPL-3.0"))),
            Some(PolicyViolation::DisallowedLicense { .. })
        ));
    }

    #[test]
    fn missing_license_flagged() {
        let policy = DependencyPolicy::default();
        assert!(matches!(
            policy.check_license(&dep(None)),
            Some(PolicyViolation::MissingLicense { .. })
        ));
    }

    #[test]
    fn empty_allowlist_permits_any() {
        let policy = DependencyPolicy {
            allowed_licenses: vec![],
            ..DependencyPolicy::default()
        };
        assert!(policy.check_license(&dep(Some("GPL-3.0"))).is_none());
    }

    #[test]
    fn severity_blocking_and_high_risk() {
        let policy = DependencyPolicy {
            high_risk_packages: vec!["openssl-sys".to_string()],
            ..DependencyPolicy::default()
        };
        assert!(policy.blocks_release(VulnSeverity::Critical));
        assert!(!policy.blocks_release(VulnSeverity::Medium));
        assert!(policy.is_high_risk("openssl-sys"));
        assert!(!policy.is_high_risk("serde"));
    }
}
