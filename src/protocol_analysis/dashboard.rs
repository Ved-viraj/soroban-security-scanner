//! Phase 7 – Protocol Health Dashboard
//!
//! Data structures for the `ProtocolHealth` dashboard showing:
//! - all defined invariants with verification status,
//! - protocol call graph with invariant annotations,
//! - simulation coverage heatmap,
//! - recent invariant violations with reproduction steps.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::call_graph::ProtocolCallGraph;
use super::simulation::InvariantViolation;
use super::{ProtocolInvariant, VerificationStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHealth {
    pub protocol_name: String,
    pub invariants: Vec<InvariantStatusRow>,
    pub call_graph_summary: CallGraphSummary,
    pub coverage_heatmap: HashMap<String, f64>,
    pub recent_violations: Vec<ViolationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantStatusRow {
    pub name: String,
    pub description: String,
    pub verification_status: VerificationStatus,
    pub auto_inferred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphSummary {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub external_edges: usize,
    pub critical_sections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationEntry {
    pub invariant_name: String,
    pub step: u64,
    pub operation_sequence: Vec<String>,
    pub reproduction_steps: String,
}

impl ProtocolHealth {
    pub fn new(
        protocol_name: &str,
        invariants: &[ProtocolInvariant],
        call_graph: &ProtocolCallGraph,
        coverage_heatmap: HashMap<String, f64>,
        violations: &[InvariantViolation],
    ) -> Self {
        let rows: Vec<InvariantStatusRow> = invariants
            .iter()
            .map(|i| InvariantStatusRow {
                name: i.name.clone(),
                description: i.description.clone(),
                verification_status: i.status,
                auto_inferred: i.auto_inferred,
            })
            .collect();

        let external_edges = call_graph.edges.iter().filter(|e| e.is_external).count();

        let violation_entries: Vec<ViolationEntry> = violations
            .iter()
            .map(|v| ViolationEntry {
                invariant_name: v.invariant_name.clone(),
                step: v.step,
                operation_sequence: v
                    .operation_sequence
                    .iter()
                    .map(|op| format!("{}.{}", op.contract, op.function))
                    .collect(),
                reproduction_steps: format!(
                    "At step {}: call {} on contract {}",
                    v.step,
                    v.operation_sequence
                        .first()
                        .map(|o| o.function.as_str())
                        .unwrap_or("unknown"),
                    v.operation_sequence
                        .first()
                        .map(|o| o.contract.as_str())
                        .unwrap_or("unknown"),
                ),
            })
            .collect();

        ProtocolHealth {
            protocol_name: protocol_name.to_string(),
            invariants: rows,
            call_graph_summary: CallGraphSummary {
                total_nodes: call_graph.nodes.len(),
                total_edges: call_graph.edges.len(),
                external_edges,
                critical_sections: call_graph.critical_sections.len(),
            },
            coverage_heatmap,
            recent_violations: violation_entries,
        }
    }

    /// Render the dashboard as a string.
    pub fn render(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("\n╔══════════════════════════════════════════╗\n"));
        out.push_str(&format!("║  PROTOCOL HEALTH DASHBOARD                ║\n"));
        out.push_str(&format!("╠══════════════════════════════════════════╣\n"));
        out.push_str(&format!("║  Protocol: {:30}║\n", self.protocol_name));
        out.push_str(&format!("╠══════════════════════════════════════════╣\n"));
        out.push_str(&format!("║  INVARIANTS                              ║\n"));

        for row in &self.invariants {
            let emoji = row.verification_status.as_emoji();
            let auto = if row.auto_inferred { "[auto]" } else { "" };
            out.push_str(&format!(
                "║  {} {:35} {} ║\n",
                emoji,
                if row.name.len() > 35 {
                    &row.name[..35]
                } else {
                    &row.name
                },
                auto
            ));
        }

        out.push_str(&format!("╠══════════════════════════════════════════╣\n"));
        out.push_str(&format!("║  CALL GRAPH                              ║\n"));
        out.push_str(&format!(
            "║  Nodes: {:4}  Edges: {:4}  External: {:4} ║\n",
            self.call_graph_summary.total_nodes,
            self.call_graph_summary.total_edges,
            self.call_graph_summary.external_edges
        ));
        out.push_str(&format!(
            "║  Critical sections: {:4}               ║\n",
            self.call_graph_summary.critical_sections
        ));

        out.push_str(&format!("╠══════════════════════════════════════════╣\n"));
        out.push_str(&format!("║  SIMULATION COVERAGE                     ║\n"));
        for (contract, cov) in &self.coverage_heatmap {
            let bar_len = (cov * 20.0) as usize;
            let bar = "█".repeat(bar_len);
            out.push_str(&format!(
                "║  {:20} {:20} {:.0}% ║\n",
                contract,
                bar,
                cov * 100.0
            ));
        }

        if !self.recent_violations.is_empty() {
            out.push_str(&format!("╠══════════════════════════════════════════╣\n"));
            out.push_str(&format!("║  RECENT VIOLATIONS                       ║\n"));
            for v in &self.recent_violations.iter().take(5) {
                out.push_str(&format!(
                    "║  ✗ {:35} ║\n",
                    if v.invariant_name.len() > 35 {
                        &v.invariant_name[..35]
                    } else {
                        &v.invariant_name
                    }
                ));
            }
        }

        out.push_str(&format!("╚══════════════════════════════════════════╝\n"));

        out
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
