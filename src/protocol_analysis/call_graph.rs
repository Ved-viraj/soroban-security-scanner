//! Phase 5 – Cross-Contract Call Graph Analysis
//!
//! Builds a `ProtocolCallGraph` that captures protocol-level control flow:
//! entry point → authentication → validation → core logic →
//! state updates → event emission → cross-contract calls → cleanup.
//!
//! Annotates the graph with protocol invariants that must hold at each node,
//! and identifies "invariant-critical sections" where an invariant is
//! temporarily broken and must be restored before the sequence ends.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::manifest::ProtocolManifest;

// ---------------------------------------------------------------------------
// Protocol Call Graph
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCallGraph {
    pub nodes: Vec<ProtocolCallNode>,
    pub edges: Vec<ProtocolCallEdge>,
    /// Invariant-critical sections: sequences of nodes where an invariant
    /// is temporarily broken and must be restored.
    pub critical_sections: Vec<CriticalSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCallNode {
    pub id: String,
    pub contract: String,
    pub function: String,
    pub phase: ProtocolPhase,
    /// Invariants that must hold when entering this node.
    pub invariants_at_entry: Vec<String>,
    /// Invariants that must hold when exiting this node.
    pub invariants_at_exit: Vec<String>,
}

/// Protocol-level control flow phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolPhase {
    EntryPoint,
    Authentication,
    Validation,
    CoreLogic,
    StateUpdate,
    EventEmission,
    CrossContractCall,
    Cleanup,
}

impl std::fmt::Display for ProtocolPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolPhase::EntryPoint => write!(f, "EntryPoint"),
            ProtocolPhase::Authentication => write!(f, "Auth"),
            ProtocolPhase::Validation => write!(f, "Validation"),
            ProtocolPhase::CoreLogic => write!(f, "CoreLogic"),
            ProtocolPhase::StateUpdate => write!(f, "StateUpdate"),
            ProtocolPhase::EventEmission => write!(f, "Event"),
            ProtocolPhase::CrossContractCall => write!(f, "XContract"),
            ProtocolPhase::Cleanup => write!(f, "Cleanup"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCallEdge {
    pub from: String,
    pub to: String,
    /// True if this edge represents an external (cross-contract) call.
    pub is_external: bool,
}

/// A critical section – ordered list of node ids and the invariant
/// that is temporarily broken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalSection {
    pub invariant: String,
    pub node_sequence: Vec<String>,
    pub restored_by: String, // node id where the invariant is restored
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub fn build_protocol_call_graph(protocol: &ProtocolManifest) -> Result<ProtocolCallGraph> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Phase ordering
    let phases = [
        ProtocolPhase::EntryPoint,
        ProtocolPhase::Authentication,
        ProtocolPhase::Validation,
        ProtocolPhase::CoreLogic,
        ProtocolPhase::StateUpdate,
        ProtocolPhase::EventEmission,
        ProtocolPhase::CrossContractCall,
        ProtocolPhase::Cleanup,
    ];

    for contract in &protocol.contracts {
        for phase in &phases {
            let func = phase_to_function_name(phase, &contract.name);
            let node_id = format!("{}::{}", contract.name, func);

            nodes.push(ProtocolCallNode {
                id: node_id.clone(),
                contract: contract.name.clone(),
                function: func,
                phase: phase.clone(),
                invariants_at_entry: find_invariants_for_contract(
                    &protocol.invariants,
                    &contract.name,
                ),
                invariants_at_exit: Vec::new(),
            });
        }
    }

    // Create edges: within each contract's phases (sequential)
    for contract in &protocol.contracts {
        for i in 0..phases.len() - 1 {
            let from = format!(
                "{}::{}",
                contract.name,
                phase_to_function_name(&phases[i], &contract.name)
            );
            let to = format!(
                "{}::{}",
                contract.name,
                phase_to_function_name(&phases[i + 1], &contract.name)
            );
            edges.push(ProtocolCallEdge {
                from,
                to,
                is_external: false,
            });
        }
    }

    // Cross-contract edges from interactions
    for ix in &protocol.interactions {
        for phase in [ProtocolPhase::CoreLogic, ProtocolPhase::CrossContractCall] {
            let from = format!(
                "{}::{}",
                ix.from_contract,
                phase_to_function_name(&phase, &ix.from_contract)
            );
            let to = format!(
                "{}::{}",
                ix.to_contract,
                phase_to_function_name(&ProtocolPhase::EntryPoint, &ix.to_contract)
            );
            edges.push(ProtocolCallEdge {
                from,
                to,
                is_external: true,
            });
        }
    }

    // Find critical sections
    let critical_sections = find_critical_sections(protocol, &nodes, &edges);

    Ok(ProtocolCallGraph {
        nodes,
        edges,
        critical_sections,
    })
}

fn phase_to_function_name(phase: &ProtocolPhase, contract: &str) -> String {
    match phase {
        ProtocolPhase::EntryPoint => format!("{}_entry", contract),
        ProtocolPhase::Authentication => format!("{}_auth", contract),
        ProtocolPhase::Validation => format!("{}_validate", contract),
        ProtocolPhase::CoreLogic => format!("{}_execute", contract),
        ProtocolPhase::StateUpdate => format!("{}_update_state", contract),
        ProtocolPhase::EventEmission => format!("{}_emit_events", contract),
        ProtocolPhase::CrossContractCall => format!("{}_invoke_external", contract),
        ProtocolPhase::Cleanup => format!("{}_cleanup", contract),
    }
}

fn find_invariants_for_contract(
    invariants: &[super::ProtocolInvariant],
    contract_name: &str,
) -> Vec<String> {
    invariants
        .iter()
        .filter(|inv| inv.spans_contracts.contains(&contract_name.to_string()))
        .map(|inv| inv.name.clone())
        .collect()
}

fn find_critical_sections(
    protocol: &ProtocolManifest,
    nodes: &[ProtocolCallNode],
    _edges: &[ProtocolCallEdge],
) -> Vec<CriticalSection> {
    let mut sections = Vec::new();

    // An invariant-critical section is a sequence where state is temporarily
    // inconsistent. For example, during a swap, `reserve_x * reserve_y` may
    // temporarily change before the invariant is restored.
    for inv in &protocol.invariants {
        if inv.expression.contains("reserve_x") || inv.expression.contains("total_deposits") {
            // Find the state-update and cleanup nodes for contracts in this invariant
            let mut seq = Vec::new();
            for c in &inv.spans_contracts {
                let core = format!("{}::{}_execute", c, c);
                let state = format!("{}::{}_update_state", c, c);
                let cleanup = format!("{}::{}_cleanup", c, c);

                if nodes.iter().any(|n| n.id == core) {
                    seq.push(core);
                }
                if nodes.iter().any(|n| n.id == state) {
                    seq.push(state);
                }
                if nodes.iter().any(|n| n.id == cleanup) {
                    seq.push(cleanup);
                }
            }

            if seq.len() >= 2 {
                let restored_by = seq.last().cloned().unwrap_or_default();
                sections.push(CriticalSection {
                    invariant: inv.name.clone(),
                    node_sequence: seq.clone(),
                    restored_by,
                });
            }
        }
    }

    sections
}
