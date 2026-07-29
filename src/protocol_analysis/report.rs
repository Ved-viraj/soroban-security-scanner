//! Phase 8 — CI Integration and Reporting.
//!
//! Provides the `stellar-scanner protocol-verify --manifest protocol.yaml` command
//! and the `ProtocolVerifyReport` that:
//! - Loads the protocol manifest
//! - Runs static verification on all structural invariants
//! - Runs dynamic simulation on all economic invariants
//! - Combines results from auto-inference, static analysis, simulation, and adversarial checks
//! - Outputs a combined report
//! - Exits with code 0 (all pass), 1 (violations), or 2 (unknown/unprovable)

use crate::protocol_analysis::adversarial::{
    AdversarialAgent, AdversarialReport, ExplorationConfig,
};
use crate::protocol_analysis::call_graph::{ProtocolCallGraph, ProtocolCallGraphBuilder};
use crate::protocol_analysis::health::{HealthCoverage, ProtocolHealth, ProtocolHealthDashboard};
use crate::protocol_analysis::inference::PatternDetector;
use crate::protocol_analysis::manifest::ProtocolManifest;
use crate::protocol_analysis::simulator::{ProtocolSimulator, SimulationConfig, SimulationReport};
use crate::protocol_analysis::static_analysis::{
    StaticAnalyzer, StaticVerificationResult, VerificationStatus,
};

/// Configuration for the verification process.
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Number of simulation steps.
    pub simulation_steps: u64,
    /// Whether to run adversarial exploration.
    pub adversarial_exploration: bool,
    /// Whether to auto-infer invariants.
    pub auto_infer: bool,
    /// Whether to generate call graph.
    pub generate_call_graph: bool,
    /// Output format (console, json, html, markdown).
    pub output_format: String,
    /// Whether to stop on first violation.
    pub stop_on_first_violation: bool,
    /// Verbose output.
    pub verbose: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            simulation_steps: 100_000,
            adversarial_exploration: true,
            auto_infer: true,
            generate_call_graph: true,
            output_format: "console".to_string(),
            stop_on_first_violation: false,
            verbose: false,
        }
    }
}

/// Exit code for CI integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// All invariants verified.
    AllPassed = 0,
    /// Some invariants violated.
    ViolationsFound = 1,
    /// Some invariants unprovable.
    Unprovable = 2,
}

impl ExitCode {
    pub fn to_i32(&self) -> i32 {
        *self as i32
    }
}

/// The complete report from a protocol verification run.
#[derive(Debug, Clone)]
pub struct ProtocolVerifyReport {
    /// Protocol name.
    pub protocol_name: String,
    /// Whether manifest was valid.
    pub manifest_valid: bool,
    /// Manifest validation errors (if any).
    pub manifest_errors: Vec<String>,
    /// The parsed manifest.
    pub manifest: Option<ProtocolManifest>,
    /// Auto-inferred invariants.
    pub inferred_invariants: Vec<crate::protocol_analysis::inference::InferredInvariant>,
    /// Results from static verification.
    pub static_results: Vec<StaticVerificationResult>,
    /// Report from dynamic simulation.
    pub simulation_report: Option<SimulationReport>,
    /// Report from adversarial exploration.
    pub adversarial_report: Option<AdversarialReport>,
    /// The protocol call graph.
    pub call_graph: Option<ProtocolCallGraph>,
    /// Protocol health dashboard.
    pub health: Option<ProtocolHealth>,
    /// Exit code for CI.
    pub exit_code: ExitCode,
    /// Total verification time.
    pub total_time_ms: u64,
}

/// Public CLI command interface.
pub struct ProtocolVerifyCommand;

impl ProtocolVerifyCommand {
    /// Run the full protocol verification pipeline.
    pub fn run(
        manifest_path: &std::path::Path,
        config: VerificationConfig,
    ) -> ProtocolVerifyReport {
        let start = std::time::Instant::now();

        // Phase 0: Parse manifest
        let manifest = ProtocolParser::from_file(manifest_path);
        let (manifest_obj, manifest_valid, manifest_errors) = match manifest {
            Ok(m) => {
                let validation = ProtocolParser::validate(&m);
                match validation {
                    Ok(()) => (Some(m), true, vec![]),
                    Err(errors) => (Some(m), false, errors),
                }
            }
            Err(e) => (None, false, vec![e]),
        };

        let manifest_ref = match &manifest_obj {
            Some(m) => m,
            None => {
                return ProtocolVerifyReport {
                    protocol_name: "unknown".to_string(),
                    manifest_valid: false,
                    manifest_errors,
                    manifest: None,
                    inferred_invariants: vec![],
                    static_results: vec![],
                    simulation_report: None,
                    adversarial_report: None,
                    call_graph: None,
                    health: None,
                    exit_code: ExitCode::Unprovable,
                    total_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        let protocol_name = manifest_ref.name.clone();

        // Phase 2: Auto-inference
        let inferred = if config.auto_infer {
            PatternDetector::infer_all(manifest_ref)
        } else {
            vec![]
        };

        // Phase 3: Static analysis
        let static_results = StaticAnalyzer::verify_all(manifest_ref);

        // Phase 4: Dynamic simulation
        let sim_config = SimulationConfig {
            num_steps: config.simulation_steps,
            stop_on_first_violation: config.stop_on_first_violation,
            ..Default::default()
        };
        let mut simulator = ProtocolSimulator::new(manifest_ref.clone(), sim_config);
        let simulation_report = simulator.run();

        // Phase 5: Build call graph
        let call_graph = if config.generate_call_graph {
            let mut cg = ProtocolCallGraphBuilder::build(manifest_ref);
            ProtocolCallGraphBuilder::annotate_invariants(&mut cg, manifest_ref);
            Some(cg)
        } else {
            None
        };

        // Phase 6: Adversarial exploration
        let adversarial_report = if config.adversarial_exploration {
            let adv_config = ExplorationConfig {
                num_rounds: 5,
                sequence_length: 30,
                ..Default::default()
            };
            let mut agent = AdversarialAgent::new(manifest_ref.clone(), adv_config);
            let report = agent.explore();

            // Merge adversarial findings into simulation
            if !report.exploits.is_empty() {
                // In a real implementation, we'd re-run simulation with adversarial operations
            }

            Some(report)
        } else {
            None
        };

        // Phase 7: Health dashboard
        let sim_coverage = HealthCoverage {
            operations_executed: simulation_report.coverage.operations_executed.clone(),
            contracts_interacted: simulation_report.coverage.contracts_interacted.clone(),
            invariants_covered: simulation_report.coverage.invariants_covered.clone(),
            invariants_violated: simulation_report.coverage.invariants_violated.clone(),
            coverage_percentage: if manifest_ref.invariants.is_empty() {
                100.0
            } else {
                (simulation_report.coverage.invariants_covered.len() as f64
                    / manifest_ref.invariants.len() as f64)
                    * 100.0
            },
        };

        let health = Some(ProtocolHealthDashboard::generate(
            manifest_ref,
            &static_results,
            Some(sim_coverage),
            call_graph.clone(),
        ));

        // Determine exit code
        let has_violations = static_results
            .iter()
            .any(|r| matches!(r.status, VerificationStatus::Violated { .. }))
            || !simulation_report.violations_found.is_empty()
            || adversarial_report
                .as_ref()
                .map(|r| !r.exploits.is_empty())
                .unwrap_or(false);

        let has_unknown = static_results.iter().any(|r| {
            matches!(r.status, VerificationStatus::Unknown { .. })
                || matches!(r.status, VerificationStatus::Skipped { .. })
        });

        let exit_code = if has_violations {
            ExitCode::ViolationsFound
        } else if has_unknown {
            ExitCode::Unprovable
        } else {
            ExitCode::AllPassed
        };

        let total_time = start.elapsed().as_millis() as u64;

        ProtocolVerifyReport {
            protocol_name,
            manifest_valid,
            manifest_errors,
            manifest: manifest_obj,
            inferred_invariants: inferred,
            static_results,
            simulation_report: Some(simulation_report),
            adversarial_report,
            call_graph,
            health,
            exit_code,
            total_time_ms: total_time,
        }
    }

    /// Generate a formatted text report.
    pub fn format_report(report: &ProtocolVerifyReport, verbose: bool) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n🔬 Protocol Verification Report: {}\n",
            report.protocol_name
        ));
        output.push_str("   ═══════════════════════════════════════\n");
        output.push_str(&format!("   ⏱ Total time: {}ms\n", report.total_time_ms));

        // Manifest validation
        output.push_str(&format!(
            "\n📋 Manifest: {}\n",
            if report.manifest_valid {
                "✓ Valid"
            } else {
                "✗ Invalid"
            }
        ));
        if !report.manifest_errors.is_empty() {
            for err in &report.manifest_errors {
                output.push_str(&format!("   ⚠ {}\n", err));
            }
        }

        // Auto-inferred invariants
        if !report.inferred_invariants.is_empty() {
            output.push_str(&format!(
                "\n🤖 Auto-Inferred Invariants ({})\n",
                report.inferred_invariants.len()
            ));
            for inv in &report.inferred_invariants {
                output.push_str(&format!(
                    "   • {} [{}] (confidence: {})\n",
                    inv.invariant.name, inv.pattern, inv.confidence
                ));
            }
        }

        // Static verification results
        output.push_str(&format!(
            "\n🔍 Static Verification Results ({})\n",
            report.static_results.len()
        ));
        for result in &report.static_results {
            let icon = match result.status {
                VerificationStatus::Verified => "✓",
                VerificationStatus::Violated { .. } => "✗",
                VerificationStatus::Unknown { .. } => "⚠",
                VerificationStatus::Skipped { .. } => "–",
            };
            output.push_str(&format!(
                "   {} {} ({}ms, depth: {})\n",
                icon, result.invariant_name, result.verification_time_ms, result.proof_depth
            ));
        }

        // Simulation results
        if let Some(sim) = &report.simulation_report {
            output.push_str("\n🎲 Dynamic Simulation\n");
            output.push_str(&format!("   • Steps executed: {}\n", sim.total_steps));
            output.push_str(&format!(
                "   • Invariants violated: {}\n",
                sim.violations_found.len()
            ));
            output.push_str(&format!(
                "   • Execution time: {}ms\n",
                sim.execution_time_ms
            ));
        }

        // Adversarial results
        if let Some(adv) = &report.adversarial_report {
            output.push_str("\n🕵️ Adversarial Exploration\n");
            output.push_str(&format!("   • Exploits found: {}\n", adv.exploits.len()));
            output.push_str(&format!(
                "   • Total estimated profit: ${:.2}\n",
                adv.total_estimated_profit
            ));
            if verbose {
                for exploit in &adv.exploits {
                    output.push_str(&format!(
                        "   • {} [{}] - ${:.2}\n",
                        exploit.name, exploit.difficulty, exploit.estimated_profit
                    ));
                    output.push_str(&format!("     {}\n", exploit.description));
                }
            }
        }

        // Health summary
        if let Some(health) = &report.health {
            output.push_str("\n🏥 Health Summary\n");
            output.push_str(&format!(
                "   • Health score: {:.1}%\n",
                health.summary.health_score * 100.0
            ));
            output.push_str(&format!(
                "   • Verified: {} | Violated: {} | Unknown: {}\n",
                health.summary.verified_count,
                health.summary.violated_count,
                health.summary.unknown_count
            ));

            if !health.critical_sections.is_empty() {
                output.push_str(&format!(
                    "\n   ⛔ Critical Sections ({})\n",
                    health.critical_sections.len()
                ));
                for section in &health.critical_sections {
                    output.push_str(&format!(
                        "      • '{}' at risk in {} -> {}\n",
                        section.invariant_name, section.broken_at, section.restored_at
                    ));
                }
            }
        }

        // Exit status
        output.push_str(&format!(
            "\n📊 Exit Code: {} ({})\n",
            report.exit_code.to_i32(),
            match report.exit_code {
                ExitCode::AllPassed => "All invariants verified",
                ExitCode::ViolationsFound => "Invariant violations detected",
                ExitCode::Unprovable => "Some invariants could not be proven",
            }
        ));

        output
    }

    /// Generate a JSON report.
    pub fn to_json(report: &ProtocolVerifyReport) -> Result<String, String> {
        serde_json::to_string_pretty(report).map_err(|e| format!("JSON serialization error: {}", e))
    }
}

// Simple manifest parser helper
use crate::protocol_analysis::manifest::ProtocolParser;

// ── Serialization support for report types ───────────────────────────────────

impl serde::Serialize for ExitCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.to_i32())
    }
}

impl<'de> serde::Deserialize<'de> for ExitCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = i32::deserialize(deserializer)?;
        match n {
            0 => Ok(ExitCode::AllPassed),
            1 => Ok(ExitCode::ViolationsFound),
            2 => Ok(ExitCode::Unprovable),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid exit code: {}",
                n
            ))),
        }
    }
}

impl serde::Serialize for ProtocolVerifyReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ProtocolVerifyReport", 12)?;
        s.serialize_field("protocol_name", &self.protocol_name)?;
        s.serialize_field("manifest_valid", &self.manifest_valid)?;
        s.serialize_field("manifest_errors", &self.manifest_errors)?;
        s.serialize_field("inferred_invariants", &self.inferred_invariants)?;
        s.serialize_field("static_results", &self.static_results)?;
        s.serialize_field("simulation_report", &self.simulation_report)?;
        s.serialize_field("adversarial_report", &self.adversarial_report)?;
        s.serialize_field("exit_code", &self.exit_code)?;
        s.serialize_field("total_time_ms", &self.total_time_ms)?;
        s.end()
    }
}

// Manual Serialize/Deserialize impls for complex types that need them
impl serde::Serialize for VerificationStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            VerificationStatus::Verified => {
                let mut s = serializer.serialize_struct("VerificationStatus", 1)?;
                s.serialize_field("status", "verified")?;
                s.end()
            }
            VerificationStatus::Violated { counterexample } => {
                let mut s = serializer.serialize_struct("VerificationStatus", 2)?;
                s.serialize_field("status", "violated")?;
                s.serialize_field("counterexample", counterexample)?;
                s.end()
            }
            VerificationStatus::Unknown { reason } => {
                let mut s = serializer.serialize_struct("VerificationStatus", 2)?;
                s.serialize_field("status", "unknown")?;
                s.serialize_field("reason", reason)?;
                s.end()
            }
            VerificationStatus::Skipped { reason } => {
                let mut s = serializer.serialize_struct("VerificationStatus", 2)?;
                s.serialize_field("status", "skipped")?;
                s.serialize_field("reason", reason)?;
                s.end()
            }
        }
    }
}
