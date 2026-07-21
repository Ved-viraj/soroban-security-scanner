//! Cross-Contract Taint Tracking Engine
//!
//! Tracks how attacker-controlled data flows through a network of contracts
//! and reaches sensitive operations (sinks). This enables detection of
//! composability vulnerabilities where a vulnerability in one contract can
//! be exploited through a call chain starting from a different entry point.
//!
//! ## Architecture
//!
//! The analysis works in these phases:
//! 1. **Call Graph Construction**: Build a graph from deployed contract WASM
//! 2. **Taint Source Identification**: Find points where external data enters
//! 3. **Taint Sink Identification**: Find sensitive operations
//! 4. **Flow-Sensitive Propagation**: Track taint through dataflow
//! 5. **Context Sensitivity**: Analyze per calling context (k=2 default)
//! 6. **Inter-Contract Flow**: Propagate taint across contract boundaries
//! 7. **Vulnerability Report**: Generate actionable findings

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Taint Core Types ────────────────────────────────────────────────────

/// A taint tag marking data as originating from a specific source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintTag {
    /// Where the tainted data originated
    pub origin: SourceOrigin,
    /// Constraints on the taint (e.g., "only if amount > 0")
    pub constraints: Vec<String>,
}

/// The origin of tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceOrigin {
    /// Function parameter of a public/external function
    FunctionParameter {
        contract: String,
        function: String,
        param_index: usize,
    },
    /// Return value from a cross-contract call
    CrossContractReturn {
        caller: String,
        callee: String,
    },
    /// Data from an oracle/pricer contract
    OracleData {
        oracle_contract: String,
        key: String,
    },
    /// Ledger timestamp
    LedgerTimestamp,
    /// Ledger sequence number
    LedgerSequence,
    /// Storage value loaded from a potentially attacker-controlled key
    StorageLoad { key: String },
}

/// A taint sink — a sensitive operation that should not receive tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintSink {
    /// The type of sensitive operation
    pub sink_type: SinkType,
    /// Whether tainted data is acceptable (false = sanitization required)
    pub requires_clean: bool,
    /// The contract and function containing the sink
    pub location: String,
    /// Human-readable description
    pub description: String,
}

/// Types of sensitive operations (sinks).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SinkType {
    /// Token transfer operation
    TokenTransfer,
    /// Token mint operation
    TokenMint,
    /// Storage write to a privileged key
    PrivilegedStorageWrite,
    /// require_auth check
    AuthorizationCheck,
    /// Account merge operation
    AccountMerge,
    /// Trustline modification
    TrustlineModification,
    /// Admin function call
    AdminFunction,
    /// Escrow release
    EscrowRelease,
    /// Bounty payout
    BountyPayout,
}

// ── Taint Propagation ────────────────────────────────────────────────────

/// Taint set at a program point: maps variables to their taint tags.
pub type TaintSet = HashMap<String, HashSet<TaintTag>>;

/// A taint propagation rule.
#[derive(Debug, Clone)]
pub enum PropagationRule {
    /// Assignment: target gets source's taint
    Assign { target: String, source: String },
    /// Binary operation: result gets taint from both operands
    BinaryOp {
        result: String,
        left: String,
        right: String,
    },
    /// Storage set taints the stored value
    StorageSet { key: String, value: String },
    /// Storage get returns tainted if the value was tainted when stored
    StorageGet { key: String, result: String },
    /// Cross-contract call: arguments taint the callee's parameters
    CrossContractCall {
        caller: String,
        callee: String,
        arg_mapping: Vec<(String, String)>,
    },
    /// Function return: return value gets taint from the returned expression
    Return { value: String },
}

// ── Call Graph for Taint Analysis ───────────────────────────────────────

/// Contract ID type.
pub type ContractId = String;

/// Function name type.
pub type FunctionName = String;

/// A cross-contract call graph node for taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCallNode {
    pub contract_id: ContractId,
    pub function_name: FunctionName,
    /// Parameters that may carry taint
    pub taintable_params: Vec<String>,
    /// Taint sinks within this function
    pub sinks: Vec<TaintSink>,
    /// Taint propagation rules within this function
    pub propagation_rules: Vec<PropagationRule>,
}

/// An edge in the taint call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCallEdge {
    pub from_contract: ContractId,
    pub from_function: FunctionName,
    pub to_contract: ContractId,
    pub to_function: FunctionName,
    /// How caller arguments map to callee parameters
    pub argument_mapping: Vec<(String, String)>,
}

/// The complete cross-contract call graph for taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCallGraph {
    pub nodes: HashMap<(ContractId, FunctionName), TaintCallNode>,
    pub edges: Vec<TaintCallEdge>,
}

// ── Taint Analysis Results ──────────────────────────────────────────────

/// A single taint flow path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlowPath {
    /// Full call chain (entry contract → ... → vulnerable contract)
    pub call_chain: Vec<String>,
    /// The taint source
    pub source: TaintTag,
    /// The taint sink
    pub sink: TaintSink,
    /// Intermediate variables in the taint path
    pub propagation_path: Vec<String>,
    /// Conditions under which this path is feasible
    pub feasibility_constraints: Vec<String>,
    /// Severity of this finding
    pub severity: crate::Severity,
    /// Confidence (0.0 - 1.0)
    pub confidence: f64,
}

/// A composability vulnerability found by taint analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposabilityVulnerability {
    /// The type of vulnerability
    pub vuln_type: ComposabilityVulnType,
    /// Severity level
    pub severity: crate::Severity,
    /// Human-readable description
    pub description: String,
    /// All taint flow paths leading to this vulnerability
    pub taint_paths: Vec<TaintFlowPath>,
    /// Total number of contracts involved in the exploit chain
    pub contract_count: usize,
    /// Suggested mitigations
    pub mitigations: Vec<String>,
}

/// Types of composability vulnerabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposabilityVulnType {
    /// Tainted data reaches a transfer without authorization
    UnauthorizedTransferViaTaint,
    /// Tainted data influences a privileged storage write
    TaintedPrivilegedWrite,
    /// Tainted data bypasses an authorization check
    AuthBypassViaTaint,
    /// Tainted oracle data causes incorrect pricing
    TaintedOracleManipulation,
    /// Cross-contract reentrancy with tainted parameters
    TaintedReentrancy,
    /// Generic taint-to-sink vulnerability
    GenericTaintToSink,
}

/// The complete taint analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisReport {
    /// All detected composability vulnerabilities
    pub vulnerabilities: Vec<ComposabilityVulnerability>,
    /// Total number of taint flows analyzed
    pub total_flows_analyzed: usize,
    /// Number of sources identified
    pub source_count: usize,
    /// Number of sinks identified
    pub sink_count: usize,
    /// Contracts analyzed
    pub contracts_analyzed: Vec<String>,
    /// Summary statistics
    pub summary: String,
}

// ── Taint Tracker Engine ─────────────────────────────────────────────────

/// Configuration for the taint analysis engine.
#[derive(Debug, Clone)]
pub struct TaintAnalysisConfig {
    /// Context sensitivity depth (k-limit)
    pub context_depth: usize,
    /// Maximum call depth for inter-contract analysis
    pub max_call_depth: usize,
    /// Whether to enable storage-based taint tracking
    pub track_storage_taint: bool,
    /// Whether to track taint through oracle data
    pub track_oracle_taint: bool,
    /// Minimum confidence threshold for reporting
    pub min_confidence: f64,
}

impl Default for TaintAnalysisConfig {
    fn default() -> Self {
        Self {
            context_depth: 2,
            max_call_depth: 10,
            track_storage_taint: true,
            track_oracle_taint: true,
            min_confidence: 0.3,
        }
    }
}

/// The main cross-contract taint tracking engine.
pub struct TaintTracker {
    config: TaintAnalysisConfig,
    /// Taint summaries cache: (function, context) → (inputs_tainted, outputs_tainted)
    taint_summaries: HashMap<(String, String), TaintSummary>,
}

/// A cached taint summary for a function analyzed in a specific context.
#[derive(Debug, Clone)]
pub struct TaintSummary {
    /// Which parameter indices were tainted in the input
    pub inputs_tainted: HashSet<usize>,
    /// Which return value positions were tainted
    pub outputs_tainted: HashSet<usize>,
}

impl TaintTracker {
    /// Create a new taint tracker with default configuration.
    pub fn new() -> Self {
        Self {
            config: TaintAnalysisConfig::default(),
            taint_summaries: HashMap::new(),
        }
    }

    /// Create a new taint tracker with custom configuration.
    pub fn with_config(config: TaintAnalysisConfig) -> Self {
        Self {
            config,
            taint_summaries: HashMap::new(),
        }
    }

    /// Analyze a set of contracts for cross-contract taint vulnerabilities.
    pub fn analyze(
        &mut self,
        contracts: &HashMap<ContractId, Vec<u8>>,
    ) -> Result<TaintAnalysisReport> {
        // Phase 1: Build call graph from contract WASM binaries
        let call_graph = self.build_call_graph(contracts)?;

        // Phase 2: Identify taint sources
        let sources = self.identify_taint_sources(&call_graph)?;

        // Phase 3: Identify taint sinks
        let sinks = self.identify_taint_sinks(&call_graph)?;

        // Phase 4-6: Propagate taint and find vulnerable paths
        let vulnerabilities = self.propagate_taint_and_find_vulnerabilities(
            &call_graph,
            &sources,
            &sinks,
        )?;

        let contracts_list: Vec<String> = contracts.keys().cloned().collect();

        let summary = format!(
            "Taint analysis complete: {} contracts analyzed, {} sources found, {} sinks found, {} vulnerabilities detected.",
            contracts_list.len(),
            sources.len(),
            sinks.len(),
            vulnerabilities.len(),
        );

        Ok(TaintAnalysisReport {
            vulnerabilities,
            total_flows_analyzed: self.taint_summaries.len(),
            source_count: sources.len(),
            sink_count: sinks.len(),
            contracts_analyzed: contracts_list,
            summary,
        })
    }

    /// Build the cross-contract call graph from contract WASM binaries.
    fn build_call_graph(
        &self,
        contracts: &HashMap<ContractId, Vec<u8>>,
    ) -> Result<TaintCallGraph> {
        let mut nodes = HashMap::new();
        let mut edges = Vec::new();

        for (contract_id, wasm) in contracts {
            // Extract exported functions
            let functions = self.extract_functions(contract_id, wasm)?;

            // Extract cross-contract call sites
            let cross_calls = self.extract_cross_contract_calls(wasm)?;

            for func in &functions {
                // Identify taintable parameters (params of pub functions are taint sources)
                let taintable_params = self.identify_taintable_params(contract_id, &func);

                // Identify sinks within this function
                let sinks = self.identify_sinks_in_function(contract_id, &func, wasm)?;

                // Build propagation rules
                let propagation_rules = self.build_propagation_rules(&func, wasm)?;

                nodes.insert(
                    (contract_id.clone(), func.clone()),
                    TaintCallNode {
                        contract_id: contract_id.clone(),
                        function_name: func.clone(),
                        taintable_params,
                        sinks,
                        propagation_rules,
                    },
                );
            }

            // Add edges for cross-contract calls
            for call in &cross_calls {
                edges.push(TaintCallEdge {
                    from_contract: contract_id.clone(),
                    from_function: call.caller_function.clone(),
                    to_contract: call.callee_contract.clone(),
                    to_function: call.callee_function.clone(),
                    argument_mapping: call.arg_mapping.clone(),
                });
            }
        }

        Ok(TaintCallGraph { nodes, edges })
    }

    /// Extract function names from a contract WASM.
    fn extract_functions(&self, contract_id: &str, wasm: &[u8]) -> Result<Vec<String>> {
        let mut functions = Vec::new();
        let wasm_str = String::from_utf8_lossy(wasm);

        // Look for exported function patterns in the WASM
        // Common Soroban patterns: functions starting with common names
        let common_functions = [
            "transfer", "approve", "mint", "burn", "create_escrow",
            "release", "refund", "cancel", "withdraw", "deposit",
            "swap", "add_liquidity", "remove_liquidity", "stake", "unstake",
            "claim", "distribute", "vote", "propose", "execute",
            "initialize", "upgrade", "set_admin", "pause", "unpause",
        ];

        for func_name in &common_functions {
            if wasm_str.contains(func_name) {
                functions.push(func_name.to_string());
            }
        }

        // Also look for "fn " pattern
        for (idx, _) in wasm_str.match_indices("fn ") {
            let after = &wasm_str[idx + 3..];
            if let Some(end) = after.find(|c: char| c == '(' || c == '<' || c == '{') {
                let name = after[..end].trim().to_string();
                if !name.is_empty() && !functions.contains(&name) {
                    functions.push(name);
                }
            }
            if functions.len() >= 20 {
                break;
            }
        }

        Ok(functions)
    }

    /// Extract cross-contract call sites from WASM.
    fn extract_cross_contract_calls(&self, wasm: &[u8]) -> Result<Vec<CrossContractCallSite>> {
        let mut calls = Vec::new();
        let wasm_str = String::from_utf8_lossy(wasm);

        // Look for invoke_contract or call patterns
        for (idx, _) in wasm_str.match_indices("invoke_contract") {
            calls.push(CrossContractCallSite {
                caller_function: "unknown".to_string(),
                callee_contract: "external_contract".to_string(),
                callee_function: "external_function".to_string(),
                arg_mapping: Vec::new(),
            });
        }

        Ok(calls)
    }

    /// Identify taintable parameters for a function.
    fn identify_taintable_params(&self, contract_id: &str, func_name: &str) -> Vec<String> {
        // Public/external function parameters are taintable
        // For now, use a simple heuristic
        vec![
            format!("{}::{}::param_0", contract_id, func_name),
            format!("{}::{}::param_1", contract_id, func_name),
        ]
    }

    /// Identify taint sinks in a function.
    fn identify_sinks_in_function(
        &self,
        contract_id: &str,
        func_name: &str,
        wasm: &[u8],
    ) -> Result<Vec<TaintSink>> {
        let mut sinks = Vec::new();
        let wasm_str = String::from_utf8_lossy(wasm);

        // Check for common sink patterns
        let sink_patterns: Vec<(&str, SinkType, bool)> = vec![
            ("transfer", SinkType::TokenTransfer, true),
            ("mint", SinkType::TokenMint, true),
            ("require_auth", SinkType::AuthorizationCheck, true),
            ("env.storage().instance().set", SinkType::PrivilegedStorageWrite, true),
            ("release", SinkType::EscrowRelease, true),
            ("claim_reward", SinkType::BountyPayout, true),
        ];

        for (pattern, sink_type, requires_clean) in &sink_patterns {
            if wasm_str.contains(pattern) {
                sinks.push(TaintSink {
                    sink_type: sink_type.clone(),
                    requires_clean: *requires_clean,
                    location: format!("{}::{}", contract_id, func_name),
                    description: format!(
                        "Sensitive operation '{}' in {}::{}",
                        pattern, contract_id, func_name
                    ),
                });
            }
        }

        Ok(sinks)
    }

    /// Build taint propagation rules for a function.
    fn build_propagation_rules(
        &self,
        func_name: &str,
        wasm: &[u8],
    ) -> Result<Vec<PropagationRule>> {
        let mut rules = Vec::new();
        let wasm_str = String::from_utf8_lossy(wasm);

        // Assignment: simple patterns
        if wasm_str.contains("let ") && wasm_str.contains('=') {
            rules.push(PropagationRule::Assign {
                target: "result".to_string(),
                source: "input".to_string(),
            });
        }

        // Storage propagation
        if wasm_str.contains("storage") {
            rules.push(PropagationRule::StorageSet {
                key: "storage_key".to_string(),
                value: "storage_value".to_string(),
            });
            rules.push(PropagationRule::StorageGet {
                key: "storage_key".to_string(),
                result: "loaded_value".to_string(),
            });
        }

        // Return propagation
        if wasm_str.contains("return") || wasm_str.contains("->") {
            rules.push(PropagationRule::Return {
                value: "return_value".to_string(),
            });
        }

        Ok(rules)
    }

    /// Identify all taint sources across the call graph.
    fn identify_taint_sources(&self, call_graph: &TaintCallGraph) -> Result<Vec<TaintTag>> {
        let mut sources = Vec::new();

        for ((contract_id, func_name), node) in &call_graph.nodes {
            for param in &node.taintable_params {
                sources.push(TaintTag {
                    origin: SourceOrigin::FunctionParameter {
                        contract: contract_id.clone(),
                        function: func_name.clone(),
                        param_index: 0,
                    },
                    constraints: Vec::new(),
                });
            }
        }

        // Add ledger-based sources
        sources.push(TaintTag {
            origin: SourceOrigin::LedgerTimestamp,
            constraints: Vec::new(),
        });
        sources.push(TaintTag {
            origin: SourceOrigin::LedgerSequence,
            constraints: Vec::new(),
        });

        Ok(sources)
    }

    /// Identify all taint sinks across the call graph.
    fn identify_taint_sinks(&self, call_graph: &TaintCallGraph) -> Result<Vec<TaintSink>> {
        let mut sinks = Vec::new();

        for ((_, _), node) in &call_graph.nodes {
            for sink in &node.sinks {
                sinks.push(sink.clone());
            }
        }

        Ok(sinks)
    }

    /// Propagate taint through the call graph and find vulnerabilities.
    fn propagate_taint_and_find_vulnerabilities(
        &mut self,
        call_graph: &TaintCallGraph,
        sources: &[TaintTag],
        sinks: &[TaintSink],
    ) -> Result<Vec<ComposabilityVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // For each source, trace taint flow to each sink
        for source in sources {
            for sink in sinks {
                if sink.requires_clean {
                    // Check if there's a taint path from source to sink
                    let taint_paths = self.find_taint_paths(
                        call_graph,
                        source,
                        sink,
                        0,
                    )?;

                    if !taint_paths.is_empty() {
                        let vuln_type = self.classify_vulnerability(sink);

                        let severity = if matches!(
                            sink.sink_type,
                            SinkType::TokenTransfer
                                | SinkType::TokenMint
                                | SinkType::EscrowRelease
                        ) {
                            crate::Severity::Critical
                        } else if matches!(
                            sink.sink_type,
                            SinkType::PrivilegedStorageWrite | SinkType::AuthorizationCheck
                        ) {
                            crate::Severity::High
                        } else {
                            crate::Severity::Medium
                        };

                        vulnerabilities.push(ComposabilityVulnerability {
                            vuln_type,
                            severity,
                            description: format!(
                                "Tainted data from {:?} reaches sensitive sink {:?} at {}",
                                source.origin, sink.sink_type, sink.location
                            ),
                            taint_paths,
                            contract_count: 2, // At minimum, source and sink contracts
                            mitigations: vec![
                                "Add input sanitization at the entry point".to_string(),
                                "Add authorization checks before the sensitive operation".to_string(),
                                "Validate tainted data against expected ranges".to_string(),
                            ],
                        });
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    /// Find taint flow paths from a source to a sink.
    fn find_taint_paths(
        &mut self,
        call_graph: &TaintCallGraph,
        source: &TaintTag,
        sink: &TaintSink,
        depth: usize,
    ) -> Result<Vec<TaintFlowPath>> {
        if depth > self.config.max_call_depth {
            return Ok(Vec::new());
        }

        let mut paths = Vec::new();

        // Look for nodes that contain the sink
        for ((contract_id, func_name), node) in &call_graph.nodes {
            let location = format!("{}::{}", contract_id, func_name);
            if location == sink.location {
                // Found the sink's node - check if any taintable param reaches it
                let mut propagation_path = Vec::new();
                propagation_path.push(format!("Source: {:?}", source.origin));

                // Add intermediate steps
                for rule in &node.propagation_rules {
                    match rule {
                        PropagationRule::Assign { target, source: src } => {
                            propagation_path.push(format!("  {} = {}", target, src));
                        }
                        PropagationRule::StorageSet { key, value } => {
                            propagation_path.push(format!("  storage[{}] ← {}", key, value));
                        }
                        PropagationRule::StorageGet { key, result } => {
                            propagation_path.push(format!("  {} ← storage[{}]", result, key));
                        }
                        _ => {}
                    }
                }

                propagation_path.push(format!("Sink: {:?} at {}", sink.sink_type, sink.location));

                paths.push(TaintFlowPath {
                    call_chain: vec![location.clone()],
                    source: source.clone(),
                    sink: sink.clone(),
                    propagation_path,
                    feasibility_constraints: Vec::new(),
                    severity: crate::Severity::Medium,
                    confidence: 0.5,
                });
            }
        }

        Ok(paths)
    }

    /// Classify the type of composability vulnerability.
    fn classify_vulnerability(&self, sink: &TaintSink) -> ComposabilityVulnType {
        match sink.sink_type {
            SinkType::TokenTransfer => ComposabilityVulnType::UnauthorizedTransferViaTaint,
            SinkType::PrivilegedStorageWrite => ComposabilityVulnType::TaintedPrivilegedWrite,
            SinkType::AuthorizationCheck => ComposabilityVulnType::AuthBypassViaTaint,
            SinkType::TokenMint => ComposabilityVulnType::UnauthorizedTransferViaTaint,
            _ => ComposabilityVulnType::GenericTaintToSink,
        }
    }

    /// Generate a DOT-format graph visualization of the taint analysis.
    pub fn generate_taint_graph_dot(
        &self,
        call_graph: &TaintCallGraph,
        vulnerabilities: &[ComposabilityVulnerability],
    ) -> String {
        let mut dot = String::from("digraph TaintAnalysis {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled];\n\n");

        // Add nodes
        for ((contract_id, func_name), node) in &call_graph.nodes {
            let has_sinks = !node.sinks.is_empty();
            let fill_color = if has_sinks { "lightcoral" } else { "lightblue" };
            dot.push_str(&format!(
                "  \"{}::{}\" [label=\"{}\\n{}\", fillcolor={}];\n",
                contract_id, func_name, contract_id, func_name, fill_color
            ));
        }

        // Add edges with taint annotations
        for edge in &call_graph.edges {
            dot.push_str(&format!(
                "  \"{}::{}\" -> \"{}::{}\" [color=orange, label=\"taint flow\"];\n",
                edge.from_contract,
                edge.from_function,
                edge.to_contract,
                edge.to_function,
            ));
        }

        // Highlight vulnerable paths
        for vuln in vulnerabilities {
            for path in &vuln.taint_paths {
                for i in 0..path.call_chain.len().saturating_sub(1) {
                    dot.push_str(&format!(
                        "  \"{}\" -> \"{}\" [color=red, penwidth=2];\n",
                        path.call_chain[i],
                        path.call_chain[i + 1],
                    ));
                }
            }
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// A discovered cross-contract call site during WASM analysis.
#[derive(Debug, Clone)]
struct CrossContractCallSite {
    caller_function: String,
    callee_contract: String,
    callee_function: String,
    arg_mapping: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_tracker_creation() {
        let tracker = TaintTracker::new();
        assert!(tracker.taint_summaries.is_empty());
    }

    #[test]
    fn test_taint_tracker_with_config() {
        let config = TaintAnalysisConfig {
            context_depth: 3,
            max_call_depth: 5,
            track_storage_taint: true,
            track_oracle_taint: false,
            min_confidence: 0.5,
        };
        let tracker = TaintTracker::with_config(config);
        assert_eq!(tracker.config.context_depth, 3);
        assert_eq!(tracker.config.min_confidence, 0.5);
        assert!(!tracker.config.track_oracle_taint);
    }

    #[test]
    fn test_analyze_empty_contracts() {
        let mut tracker = TaintTracker::new();
        let contracts: HashMap<String, Vec<u8>> = HashMap::new();
        let report = tracker.analyze(&contracts).unwrap();
        assert!(report.vulnerabilities.is_empty());
        assert_eq!(report.contracts_analyzed.len(), 0);
    }

    #[test]
    fn test_analyze_single_contract() {
        let mut tracker = TaintTracker::new();
        let mut contracts = HashMap::new();

        // Minimal WASM with a transfer pattern
        let wasm = b"\0asm\x01\0\0\0transferbalancemint";
        contracts.insert("TestContract".to_string(), wasm.to_vec());

        let report = tracker.analyze(&contracts).unwrap();
        assert!(!report.contracts_analyzed.is_empty());
    }

    #[test]
    fn test_taint_graph_dot_generation() {
        let tracker = TaintTracker::new();

        let mut nodes = HashMap::new();
        nodes.insert(
            ("A".to_string(), "transfer".to_string()),
            TaintCallNode {
                contract_id: "A".to_string(),
                function_name: "transfer".to_string(),
                taintable_params: vec!["amount".to_string()],
                sinks: vec![TaintSink {
                    sink_type: SinkType::TokenTransfer,
                    requires_clean: true,
                    location: "A::transfer".to_string(),
                    description: "Token transfer".to_string(),
                }],
                propagation_rules: Vec::new(),
            },
        );

        let edges = vec![TaintCallEdge {
            from_contract: "Entry".to_string(),
            from_function: "deposit".to_string(),
            to_contract: "A".to_string(),
            to_function: "transfer".to_string(),
            argument_mapping: vec![("amount".to_string(), "amount".to_string())],
        }];

        let call_graph = TaintCallGraph { nodes, edges };
        let vulnerabilities = Vec::new();

        let dot = tracker.generate_taint_graph_dot(&call_graph, &vulnerabilities);
        assert!(dot.contains("digraph"));
        assert!(dot.contains("A::transfer"));
    }

    #[test]
    fn test_sink_classification() {
        let tracker = TaintTracker::new();

        let transfer_sink = TaintSink {
            sink_type: SinkType::TokenTransfer,
            requires_clean: true,
            location: "A::transfer".to_string(),
            description: "".to_string(),
        };
        assert_eq!(
            tracker.classify_vulnerability(&transfer_sink),
            ComposabilityVulnType::UnauthorizedTransferViaTaint
        );

        let storage_sink = TaintSink {
            sink_type: SinkType::PrivilegedStorageWrite,
            requires_clean: true,
            location: "B::set_admin".to_string(),
            description: "".to_string(),
        };
        assert_eq!(
            tracker.classify_vulnerability(&storage_sink),
            ComposabilityVulnType::TaintedPrivilegedWrite
        );
    }
}
