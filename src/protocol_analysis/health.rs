//! Phase 7 — Protocol Health Dashboard.
//!
//! Creates a `ProtocolHealth` dashboard that shows:
//! - All defined invariants with their current verification status
//! - A protocol call graph visualization with invariant annotations
//! - Simulation coverage heatmap
//! - A list of recent invariant violations with reproduction steps

use crate::protocol_analysis::call_graph::{InvariantCriticalSection, ProtocolCallGraph};
use crate::protocol_analysis::manifest::ProtocolManifest;
use crate::protocol_analysis::static_analysis::{StaticVerificationResult, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Status of a single invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantStatus {
    /// Verified through static analysis.
    Verified,
    /// Not yet verified (needs simulation).
    Unknown,
    /// Violated during simulation or exploration.
    Violated,
    /// Verification is in progress.
    InProgress,
}

/// Coverage information for the health dashboard simulation.
/// Distinct from `simulator::SimulationCoverage` which has different fields.
#[derive(Debug, Clone)]
pub struct HealthCoverage {
    /// How many operations of each type were executed.
    pub operations_executed: HashMap<String, u64>,
    /// Which contracts were interacted with.
    pub contracts_interacted: Vec<String>,
    /// Which invariants were covered by the simulation.
    pub invariants_covered: Vec<String>,
    /// Which invariants were violated.
    pub invariants_violated: Vec<String>,
    /// Coverage percentage.
    pub coverage_percentage: f64,
}

/// Overall protocol health report.
#[derive(Debug, Clone)]
pub struct ProtocolHealth {
    /// Protocol name.
    pub protocol_name: String,
    /// Protocol version.
    pub protocol_version: String,
    /// Invariant statuses keyed by invariant name.
    pub invariants: BTreeMap<String, InvariantHealthEntry>,
    /// Summary statistics.
    pub summary: HealthSummary,
    /// Call graph with invariant annotations.
    pub call_graph: Option<ProtocolCallGraph>,
    /// Simulation coverage.
    pub sim_coverage_result: Option<HealthCoverage>,
    /// Critical sections identified.
    pub critical_sections: Vec<InvariantCriticalSection>,
    /// Last updated timestamp.
    pub last_updated: String,
}

/// Health entry for a single invariant.
#[derive(Debug, Clone)]
pub struct InvariantHealthEntry {
    /// Current verification status.
    pub status: InvariantStatus,
    /// Human-readable description.
    pub description: String,
    /// Severity of the invariant.
    pub severity: String,
    /// Category.
    pub category: String,
    /// Contracts involved.
    pub involved_contracts: Vec<String>,
    /// Static verification result (if available).
    pub static_result: Option<StaticVerificationResult>,
    /// Whether this was auto-inferred.
    pub auto_inferred: bool,
    /// Mitigation suggestions if violated.
    pub mitigations: Vec<String>,
}

/// Summary statistics for the protocol health dashboard.
#[derive(Debug, Clone)]
pub struct HealthSummary {
    /// Total invariants defined.
    pub total_invariants: usize,
    /// Number of invariants verified.
    pub verified_count: usize,
    /// Number of invariants violated.
    pub violated_count: usize,
    /// Number of unknown invariants.
    pub unknown_count: usize,
    /// Number of auto-inferred invariants.
    pub auto_inferred_count: usize,
    /// Overall health score (0.0 - 1.0).
    pub health_score: f64,
    /// Number of contracts in the protocol.
    pub contract_count: usize,
    /// Number of interactions defined.
    pub interaction_count: usize,
}

/// The protocol health dashboard.
pub struct ProtocolHealthDashboard;

impl ProtocolHealthDashboard {
    /// Generate a complete health report for a protocol.
    pub fn generate(
        manifest: &ProtocolManifest,
        static_results: &[StaticVerificationResult],
        simulation_coverage: Option<HealthCoverage>,
        call_graph: Option<ProtocolCallGraph>,
    ) -> ProtocolHealth {
        let mut invariants = BTreeMap::new();
        let mut verified_count = 0;
        let mut violated_count = 0;
        let mut unknown_count = 0;
        let mut auto_inferred_count = 0;

        // Build the invariant health entries
        let static_map: HashMap<&str, &StaticVerificationResult> = static_results
            .iter()
            .map(|r| (r.invariant_name.as_str(), r))
            .collect();

        for inv_spec in &manifest.invariants {
            let static_result = static_map.get(inv_spec.name.as_str()).copied();

            let status = match static_result {
                Some(r) => match r.status {
                    VerificationStatus::Verified => {
                        verified_count += 1;
                        InvariantStatus::Verified
                    }
                    VerificationStatus::Violated { .. } => {
                        violated_count += 1;
                        InvariantStatus::Violated
                    }
                    VerificationStatus::Unknown { .. } => {
                        unknown_count += 1;
                        InvariantStatus::Unknown
                    }
                    VerificationStatus::Skipped { .. } => {
                        unknown_count += 1;
                        InvariantStatus::Unknown
                    }
                },
                None => {
                    unknown_count += 1;
                    InvariantStatus::Unknown
                }
            };

            if inv_spec.auto_inferred {
                auto_inferred_count += 1;
            }

            let involved_contracts = Self::extract_contracts(manifest, inv_spec);

            invariants.insert(
                inv_spec.name.clone(),
                InvariantHealthEntry {
                    status,
                    description: inv_spec.description.clone(),
                    severity: inv_spec.severity.clone(),
                    category: inv_spec.category.clone(),
                    involved_contracts,
                    static_result: static_result.cloned(),
                    auto_inferred: inv_spec.auto_inferred,
                    mitigations: Self::generate_mitigations(inv_spec),
                },
            );
        }

        // Capture length before moving invariants
        let total_invariants = invariants.len();

        // Calculate health score
        let total = total_invariants as f64;
        let health_score = if total > 0.0 {
            (verified_count as f64 * 1.0
                + unknown_count as f64 * 0.5
                + (total - violated_count as f64 - verified_count as f64 - unknown_count as f64)
                    * 0.0)
                / total
        } else {
            1.0
        };

        // Extract critical sections from call graph
        let critical_sections = call_graph
            .as_ref()
            .map(|cg| cg.critical_sections.clone())
            .unwrap_or_default();

        // Build simulation coverage if available
        let sim_coverage = simulation_coverage.map(|sc| HealthCoverage {
            operations_executed: sc.operations_executed.clone(),
            contracts_interacted: sc.contracts_interacted.clone(),
            invariants_covered: sc.invariants_covered.clone(),
            invariants_violated: sc.invariants_violated.clone(),
            coverage_percentage: if manifest.invariants.is_empty() {
                100.0
            } else {
                (sc.invariants_covered.len() as f64 / manifest.invariants.len() as f64) * 100.0
            },
        });

        ProtocolHealth {
            protocol_name: manifest.name.clone(),
            protocol_version: manifest.version.clone(),
            invariants,
            summary: HealthSummary {
                total_invariants,
                verified_count,
                violated_count,
                unknown_count,
                auto_inferred_count,
                health_score,
                contract_count: manifest.contracts.len(),
                interaction_count: manifest.interactions.len(),
            },
            call_graph,
            sim_coverage_result: sim_coverage,
            critical_sections,
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Extract contracts involved in an invariant.
    fn extract_contracts(
        manifest: &ProtocolManifest,
        inv_spec: &crate::protocol_analysis::manifest::InvariantSpec,
    ) -> Vec<String> {
        let mut contracts = Vec::new();
        // Collect contract names from the expression
        Self::collect_contract_names_for_invariant(&inv_spec.expression, &mut contracts, manifest);
        contracts.sort();
        contracts.dedup();
        contracts
    }

    fn collect_contract_names_for_invariant(
        expr: &crate::protocol_analysis::manifest::Expression,
        names: &mut Vec<String>,
        _manifest: &ProtocolManifest,
    ) {
        match expr {
            crate::protocol_analysis::manifest::Expression::Storage { contract, .. } => {
                names.push((**contract).clone());
            }
            crate::protocol_analysis::manifest::Expression::Reserve { pool, token } => {
                names.push((**pool).clone());
                names.push((**token).clone());
            }
            crate::protocol_analysis::manifest::Expression::TotalSupply { token } => {
                names.push((**token).clone());
            }
            crate::protocol_analysis::manifest::Expression::TotalDeposits { pool } => {
                names.push((**pool).clone());
            }
            crate::protocol_analysis::manifest::Expression::TotalLoans { pool } => {
                names.push((**pool).clone());
            }
            crate::protocol_analysis::manifest::Expression::ConstantK { pool } => {
                names.push((**pool).clone());
            }
            crate::protocol_analysis::manifest::Expression::LockedSoroban { bridge } => {
                names.push((**bridge).clone());
            }
            crate::protocol_analysis::manifest::Expression::MintedCounterpart { bridge } => {
                names.push((**bridge).clone());
            }
            crate::protocol_analysis::manifest::Expression::TotalVotingPower { gov } => {
                names.push((**gov).clone());
            }
            crate::protocol_analysis::manifest::Expression::SumDelegatedPower { gov } => {
                names.push((**gov).clone());
            }
            _ => {}
        }
    }

    /// Generate mitigations for an invariant.
    fn generate_mitigations(
        inv_spec: &crate::protocol_analysis::manifest::InvariantSpec,
    ) -> Vec<String> {
        let mut mitigations = Vec::new();

        match inv_spec.category.as_str() {
            "dex" => {
                mitigations.push("Add invariant check after every swap operation".to_string());
                mitigations.push("Ensure k constant is preserved before state changes".to_string());
            }
            "lending" => {
                mitigations.push("Check solvency before allowing new borrows".to_string());
                mitigations
                    .push("Implement liquidation mechanism for underwater positions".to_string());
            }
            "bridge" => {
                mitigations.push("Atomic cross-chain verification of mint/burn".to_string());
                mitigations.push("Rate limit bridge operations".to_string());
            }
            "stablecoin" => {
                mitigations.push("Regularly check collateralization ratio".to_string());
                mitigations
                    .push("Implement emergency shutdown for under-collateralization".to_string());
            }
            _ => {
                mitigations.push(format!(
                    "Implement invariant checks for '{}'",
                    inv_spec.name
                ));
            }
        }

        mitigations
    }

    /// Generate a JSON representation of the dashboard for UI consumption.
    pub fn to_json(health: &ProtocolHealth) -> Result<String, String> {
        serde_json::to_string_pretty(health).map_err(|e| format!("JSON serialization error: {}", e))
    }

    /// Generate a text summary of protocol health.
    pub fn format_summary(health: &ProtocolHealth) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n📊 Protocol Health Dashboard: {}\n",
            health.protocol_name
        ));
        output.push_str(&format!("   Version: {}\n", health.protocol_version));
        output.push_str("   ═══════════════════════════════════════\n");

        output.push_str(&format!(
            "\n   🏥 Health Score: {:.1}%\n",
            health.summary.health_score * 100.0
        ));
        output.push_str(&format!(
            "   ✓ Verified:    {}\n",
            health.summary.verified_count
        ));
        output.push_str(&format!(
            "   ✗ Violated:    {}\n",
            health.summary.violated_count
        ));
        output.push_str(&format!(
            "   ⚠ Unknown:     {}\n",
            health.summary.unknown_count
        ));
        output.push_str(&format!(
            "   🤖 Auto-Inferred: {}\n",
            health.summary.auto_inferred_count
        ));

        output.push_str(&format!(
            "\n   📦 Contracts:   {}\n",
            health.summary.contract_count
        ));
        output.push_str(&format!(
            "   🔗 Interactions: {}\n",
            health.summary.interaction_count
        ));

        if !health.critical_sections.is_empty() {
            output.push_str(&format!(
                "\n   ⛔ Critical Sections: {}\n",
                health.critical_sections.len()
            ));
            for section in &health.critical_sections {
                output.push_str(&format!(
                    "      - '{}' can be violated between {} and {}\n",
                    section.invariant_name, section.broken_at, section.restored_at
                ));
            }
        }

        output
    }
}

// ── Serialization support ───────────────────────────────────────────────────

impl serde::Serialize for InvariantHealthEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("InvariantHealthEntry", 7)?;
        s.serialize_field("status", &self.status)?;
        s.serialize_field("description", &self.description)?;
        s.serialize_field("severity", &self.severity)?;
        s.serialize_field("category", &self.category)?;
        s.serialize_field("involved_contracts", &self.involved_contracts)?;
        s.serialize_field("auto_inferred", &self.auto_inferred)?;
        s.serialize_field("mitigations", &self.mitigations)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for InvariantHealthEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct InvariantHealthEntryHelper {
            status: InvariantStatus,
            description: String,
            severity: String,
            category: String,
            involved_contracts: Vec<String>,
            auto_inferred: bool,
            mitigations: Vec<String>,
        }
        let helper = InvariantHealthEntryHelper::deserialize(deserializer)?;
        Ok(InvariantHealthEntry {
            status: helper.status,
            description: helper.description,
            severity: helper.severity,
            category: helper.category,
            involved_contracts: helper.involved_contracts,
            static_result: None,
            auto_inferred: helper.auto_inferred,
            mitigations: helper.mitigations,
        })
    }
}

impl serde::Serialize for ProtocolHealth {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ProtocolHealth", 8)?;
        s.serialize_field("protocol_name", &self.protocol_name)?;
        s.serialize_field("protocol_version", &self.protocol_version)?;
        s.serialize_field("invariants", &self.invariants)?;
        s.serialize_field("summary", &self.summary)?;
        s.serialize_field("call_graph", &self.call_graph)?;
        s.serialize_field("sim_coverage_result", &self.sim_coverage_result)?;
        s.serialize_field("critical_sections", &self.critical_sections)?;
        s.serialize_field("last_updated", &self.last_updated)?;
        s.end()
    }
}

impl serde::Serialize for HealthSummary {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("HealthSummary", 8)?;
        s.serialize_field("total_invariants", &self.total_invariants)?;
        s.serialize_field("verified_count", &self.verified_count)?;
        s.serialize_field("violated_count", &self.violated_count)?;
        s.serialize_field("unknown_count", &self.unknown_count)?;
        s.serialize_field("auto_inferred_count", &self.auto_inferred_count)?;
        s.serialize_field("health_score", &self.health_score)?;
        s.serialize_field("contract_count", &self.contract_count)?;
        s.serialize_field("interaction_count", &self.interaction_count)?;
        s.end()
    }
}

impl serde::Serialize for HealthCoverage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("SimulationCoverage", 5)?;
        s.serialize_field("operations_executed", &self.operations_executed)?;
        s.serialize_field("contracts_interacted", &self.contracts_interacted)?;
        s.serialize_field("invariants_covered", &self.invariants_covered)?;
        s.serialize_field("invariants_violated", &self.invariants_violated)?;
        s.serialize_field("coverage_percentage", &self.coverage_percentage)?;
        s.end()
    }
}
