//! Phase 5 — Cross-Contract Call Graph Analysis.
//!
//! Builds a `ProtocolCallGraph` that captures not just which contracts call which
//! but the *protocol-level control flow*:
//!
//! entry point → authentication → validation → core logic → state updates
//! → event emission → cross-contract calls → cleanup
//!
//! The call graph is annotated with protocol invariants that must hold at each node.
//! Uses this to identify "invariant-critical sections" — sequences of operations
//! where a protocol invariant is temporarily broken and must be restored.

use crate::protocol_analysis::manifest::{ContractRole, Expression, ProtocolManifest};
use std::collections::{HashMap, HashSet, VecDeque};

/// Protocol-level call graph annotated with invariant information.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProtocolCallGraph {
    /// Nodes in the call graph, keyed by node ID.
    pub nodes: HashMap<String, CallGraphNode>,
    /// Edges between nodes.
    pub edges: Vec<CallGraphEdge>,
    /// Entry points into the protocol (top-level user-facing functions).
    pub entry_points: Vec<String>,
    /// Invariant-critical sections identified in the graph.
    pub critical_sections: Vec<InvariantCriticalSection>,
}

/// A node in the protocol call graph.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphNode {
    /// Unique node ID (e.g. "pool_a::swap").
    pub id: String,
    /// Contract name.
    pub contract: String,
    /// Function name.
    pub function: String,
    /// Phase within the protocol control flow.
    pub phase: ControlFlowPhase,
    /// Invariants that must hold at this node.
    pub invariants_before: Vec<String>,
    /// Invariants that must hold after this node.
    pub invariants_after: Vec<String>,
    /// Whether this node involves external calls.
    pub has_external_call: bool,
    /// Whether this node modifies state.
    pub modifies_state: bool,
}

/// Phases of protocol-level control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ControlFlowPhase {
    /// User-facing entry point (e.g. swap(), deposit()).
    EntryPoint,
    /// Authentication / authorization checks.
    Authentication,
    /// Input validation / precondition checks.
    Validation,
    /// Core business logic execution.
    CoreLogic,
    /// State variable updates.
    StateUpdate,
    /// Event emission (logging state changes).
    EventEmission,
    /// Cross-contract calls to other contracts.
    CrossContractCall,
    /// Cleanup / post-invariant checks.
    Cleanup,
}

/// An edge in the protocol call graph.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraphEdge {
    /// Source node ID.
    pub from: String,
    /// Destination node ID.
    pub to: String,
    /// Type of call.
    pub call_type: CallEdgeType,
    /// Whether this is a critical path for invariants.
    pub is_invariant_critical: bool,
}

/// Type of call edge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum CallEdgeType {
    /// Direct function call.
    Direct,
    /// External (cross-contract) call.
    External,
    /// Delegate/proxy call.
    Delegate,
    /// Event emission.
    Event,
    /// State read dependency.
    StateRead,
    /// State write dependency.
    StateWrite,
}

/// A critical section in the protocol where an invariant is temporarily broken
/// and must be restored before the section ends.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InvariantCriticalSection {
    /// Name of the invariant that is temporarily broken.
    pub invariant_name: String,
    /// Node where the invariant is broken.
    pub broken_at: String,
    /// Node where the invariant must be restored.
    pub restored_at: String,
    /// Sequence of nodes between break and restoration.
    pub sequence: Vec<String>,
    /// Risk level if the invariant is not restored.
    pub risk_level: String,
    /// Description of the vulnerability if this section is exploited.
    pub exploit_risk: String,
}

/// Builder and analyzer for protocol call graphs.
pub struct ProtocolCallGraphBuilder;

impl ProtocolCallGraphBuilder {
    /// Build a protocol call graph from a manifest.
    pub fn build(manifest: &ProtocolManifest) -> ProtocolCallGraph {
        let mut nodes = HashMap::new();
        let mut edges = Vec::new();
        let mut entry_points = Vec::new();

        // Create nodes for all contracts and their interactions
        for contract in &manifest.contracts {
            let has_external_calls = manifest
                .interactions
                .iter()
                .any(|i| i.from_contract == contract.name);

            for function in &contract.functions {
                let node_id = format!("{}::{}", contract.name, function.name);

                // Determine control flow phase
                let phase = Self::classify_function_phase(&function.name, &contract.role);

                let node = CallGraphNode {
                    id: node_id.clone(),
                    contract: contract.name.clone(),
                    function: function.name.clone(),
                    phase,
                    invariants_before: Vec::new(),
                    invariants_after: Vec::new(),
                    has_external_call: has_external_calls,
                    modifies_state: function.mutability == "write"
                        || function.mutability == "payable",
                };

                nodes.insert(node_id.clone(), node);

                // Check if this is an entry point
                if Self::is_entry_point(&function.name) {
                    entry_points.push(node_id);
                }
            }
        }

        // Create edges from interactions
        for interaction in &manifest.interactions {
            let from_id = format!(
                "{}::{}",
                interaction.from_contract, interaction.from_function
            );
            let to_id = format!("{}::{}", interaction.to_contract, interaction.to_function);

            edges.push(CallGraphEdge {
                from: from_id,
                to: to_id,
                call_type: CallEdgeType::External,
                is_invariant_critical: true,
            });
        }

        // Find critical sections
        let critical_sections = Self::find_critical_sections(&nodes, &edges, manifest);

        ProtocolCallGraph {
            nodes,
            edges,
            entry_points,
            critical_sections,
        }
    }

    /// Classify a function into a control flow phase.
    fn classify_function_phase(function_name: &str, _role: &ContractRole) -> ControlFlowPhase {
        let name_lower = function_name.to_lowercase();

        if name_lower.contains("auth")
            || name_lower.contains("require")
            || name_lower.contains("verify")
        {
            ControlFlowPhase::Authentication
        } else if name_lower.contains("validate")
            || name_lower.contains("check")
            || name_lower.contains("assert")
        {
            ControlFlowPhase::Validation
        } else if name_lower.contains("swap")
            || name_lower.contains("execute")
            || name_lower.contains("process")
        {
            ControlFlowPhase::CoreLogic
        } else if name_lower.contains("update")
            || name_lower.contains("set")
            || name_lower.contains("write")
        {
            ControlFlowPhase::StateUpdate
        } else if name_lower.contains("emit")
            || name_lower.contains("event")
            || name_lower.contains("log")
        {
            ControlFlowPhase::EventEmission
        } else if name_lower.contains("call")
            || name_lower.contains("invoke")
            || name_lower.contains("delegate")
        {
            ControlFlowPhase::CrossContractCall
        } else if name_lower.contains("cleanup")
            || name_lower.contains("finalize")
            || name_lower.contains("reset")
        {
            ControlFlowPhase::Cleanup
        } else {
            ControlFlowPhase::EntryPoint
        }
    }

    /// Check if a function is an entry point.
    fn is_entry_point(function_name: &str) -> bool {
        let entry_functions = [
            "swap",
            "add_liquidity",
            "remove_liquidity",
            "deposit",
            "borrow",
            "repay",
            "liquidate",
            "mint",
            "burn",
            "transfer",
            "vote",
            "delegate",
            "propose",
            "bridge_deposit",
            "bridge_withdraw",
        ];
        entry_functions.contains(&function_name)
    }

    /// Find invariant-critical sections in the call graph.
    fn find_critical_sections(
        nodes: &HashMap<String, CallGraphNode>,
        _edges: &[CallGraphEdge],
        manifest: &ProtocolManifest,
    ) -> Vec<InvariantCriticalSection> {
        let mut sections = Vec::new();

        // For each defined invariant, check if there's a state-update sequence
        // where the invariant could be temporarily broken.
        for invariant in &manifest.invariants {
            let deps = Self::find_invariant_dependencies(&invariant.expression, nodes);

            // A critical section is where state is modified across multiple nodes
            // and an invariant could be broken temporarily.
            if deps.len() >= 2 {
                // Find sequences of state-modifying nodes that reference the invariant's data
                let state_nodes: Vec<&CallGraphNode> = nodes
                    .values()
                    .filter(|n| {
                        n.modifies_state
                            && deps
                                .iter()
                                .any(|d| n.contract.contains(d) || d.contains(&n.contract))
                    })
                    .collect();

                if state_nodes.len() >= 2 {
                    let sequence: Vec<String> = state_nodes.iter().map(|n| n.id.clone()).collect();

                    sections.push(InvariantCriticalSection {
                        invariant_name: invariant.name.clone(),
                        broken_at: sequence.first().cloned().unwrap_or_default(),
                        restored_at: sequence.last().cloned().unwrap_or_default(),
                        sequence: sequence.clone(),
                        risk_level: invariant.severity.clone(),
                        exploit_risk: format!(
                            "Invariant '{}' can be violated between {} and {}",
                            invariant.name,
                            sequence.first().unwrap_or(&"start".to_string()),
                            sequence.last().unwrap_or(&"end".to_string())
                        ),
                    });
                }
            }
        }

        sections
    }

    /// Find which contracts an invariant expression depends on.
    fn find_invariant_dependencies(
        expr: &Expression,
        _nodes: &HashMap<String, CallGraphNode>,
    ) -> Vec<String> {
        let mut deps = Vec::new();
        Self::collect_contract_names(expr, &mut deps);
        deps.sort();
        deps.dedup();
        deps
    }

    fn collect_contract_names(expr: &Expression, names: &mut Vec<String>) {
        match expr {
            Expression::Storage { contract, .. } => names.push((**contract).clone()),
            Expression::Reserve { pool, token } => {
                names.push((**pool).clone());
                names.push((**token).clone());
            }
            Expression::TotalSupply { token } => names.push((**token).clone()),
            Expression::TotalDeposits { pool } => names.push((**pool).clone()),
            Expression::TotalLoans { pool } => names.push((**pool).clone()),
            Expression::ConstantK { pool } => names.push((**pool).clone()),
            Expression::LockedSoroban { bridge } => names.push((**bridge).clone()),
            Expression::MintedCounterpart { bridge } => names.push((**bridge).clone()),
            Expression::TotalVotingPower { gov } => names.push((**gov).clone()),
            Expression::SumDelegatedPower { gov } => names.push((**gov).clone()),
            Expression::Add { left, right }
            | Expression::Sub { left, right }
            | Expression::Mul { left, right }
            | Expression::Div { left, right }
            | Expression::Eq { left, right }
            | Expression::Neq { left, right }
            | Expression::Gte { left, right }
            | Expression::Lte { left, right }
            | Expression::Gt { left, right }
            | Expression::Lt { left, right } => {
                Self::collect_contract_names(left, names);
                Self::collect_contract_names(right, names);
            }
            Expression::Before { expr: inner, .. } | Expression::After { expr: inner, .. } => {
                Self::collect_contract_names(inner, names);
            }
            Expression::Sum(items) => {
                for item in items {
                    Self::collect_contract_names(item, names);
                }
            }
            Expression::ForAll {
                condition,
                collection,
                ..
            } => {
                Self::collect_contract_names(condition, names);
                Self::collect_contract_names(collection, names);
            }
            Expression::Implies {
                antecedent,
                consequent,
            } => {
                Self::collect_contract_names(antecedent, names);
                Self::collect_contract_names(consequent, names);
            }
            Expression::Not(inner) => Self::collect_contract_names(inner, names),
            _ => {}
        }
    }

    /// Annotate nodes with invariant information.
    pub fn annotate_invariants(graph: &mut ProtocolCallGraph, manifest: &ProtocolManifest) {
        // Pre-compute dependencies for each invariant outside the loop
        let invariant_deps: Vec<(String, Vec<String>)> = manifest
            .invariants
            .iter()
            .map(|inv| {
                let deps = Self::find_invariant_dependencies(&inv.expression, &graph.nodes);
                (inv.name.clone(), deps)
            })
            .collect();

        for node in graph.nodes.values_mut() {
            for (inv_name, deps) in &invariant_deps {
                // If this node's contract is referenced by the invariant
                if deps
                    .iter()
                    .any(|d| node.contract.contains(d) || d.contains(&node.contract))
                {
                    node.invariants_before.push(format!("before:{}", inv_name));
                    node.invariants_after.push(format!("after:{}", inv_name));
                }
            }
        }
    }

    /// Find the shortest path between two nodes in the call graph.
    pub fn find_path(graph: &ProtocolCallGraph, from: &str, to: &str) -> Option<Vec<String>> {
        if !graph.nodes.contains_key(from) || !graph.nodes.contains_key(to) {
            return None;
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<String, Option<String>> = HashMap::new();

        queue.push_back(from.to_string());
        visited.insert(from.to_string());
        parent.insert(from.to_string(), None);

        while let Some(current) = queue.pop_front() {
            if current == *to {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = Some(to.to_string());
                while let Some(n) = node {
                    path.push(n.clone());
                    node = parent.get(&n).and_then(|p| p.clone());
                }
                path.reverse();
                return Some(path);
            }

            for edge in &graph.edges {
                if edge.from == current && !visited.contains(&edge.to) {
                    visited.insert(edge.to.clone());
                    parent.insert(edge.to.clone(), Some(current.clone()));
                    queue.push_back(edge.to.clone());
                }
            }
        }

        None
    }

    /// Generate a DOT graph representation for visualization.
    pub fn to_dot(graph: &ProtocolCallGraph) -> String {
        let mut dot = String::from("digraph ProtocolCallGraph {\n");
        dot.push_str("    rankdir=LR;\n");
        dot.push_str("    node [shape=box, style=rounded];\n\n");

        // Nodes
        for (id, node) in &graph.nodes {
            let color = match node.phase {
                ControlFlowPhase::EntryPoint => "lightblue",
                ControlFlowPhase::Authentication => "orange",
                ControlFlowPhase::Validation => "yellow",
                ControlFlowPhase::CoreLogic => "lightgreen",
                ControlFlowPhase::StateUpdate => "pink",
                ControlFlowPhase::EventEmission => "violet",
                ControlFlowPhase::CrossContractCall => "lightcoral",
                ControlFlowPhase::Cleanup => "lightgray",
            };
            dot.push_str(&format!(
                "    \"{}\" [label=\"{}\\n{:?}\", fillcolor={}, style=filled];\n",
                id.replace('"', "\\\""),
                id.replace('"', "\\\""),
                node.phase,
                color
            ));
        }

        dot.push('\n');

        // Edges
        for edge in &graph.edges {
            let style = if edge.is_invariant_critical {
                "penwidth=2.0, color=red"
            } else {
                "color=gray"
            };
            dot.push_str(&format!(
                "    \"{}\" -> \"{}\" [label=\"{:?}\", {}];\n",
                edge.from.replace('"', "\\\""),
                edge.to.replace('"', "\\\""),
                edge.call_type,
                style
            ));
        }

        dot.push_str("}\n");
        dot
    }
}
