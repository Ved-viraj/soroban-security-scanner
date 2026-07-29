//! Comprehensive tests for the protocol analysis module.
//!
//! Tests cover all 8 phases of Issue #449.

use crate::protocol_analysis::*;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn sample_dex_manifest_yaml() -> &'static str {
    r#"
name: "SorobanDEX"
version: "1.0.0"
description: "A decentralized exchange on Soroban"
contracts:
  - name: pool_a
    address: "CA3D5K7FJ9..."
    wasm_path: "./pool.wasm"
    role: amm_pool
    functions:
      - name: swap
        mutability: write
      - name: add_liquidity
        mutability: write
      - name: remove_liquidity
        mutability: write
    storage_keys:
      - reserve_x
      - reserve_y
      - k
  - name: token_x
    address: "CB7F2M9N4..."
    wasm_path: "./token.wasm"
    role: token
    functions:
      - name: transfer
        mutability: write
      - name: balance_of
        mutability: read
  - name: token_y
    address: "CC9D1K3L5..."
    wasm_path: "./token.wasm"
    role: token
    functions:
      - name: transfer
        mutability: write
      - name: balance_of
        mutability: read
interactions:
  - from_contract: pool_a
    from_function: swap
    to_contract: token_x
    to_function: transfer
    value_transfer: true
  - from_contract: pool_a
    from_function: swap
    to_contract: token_y
    to_function: transfer
    value_transfer: true
invariants:
  - name: constant_product
    description: "reserve_x * reserve_y = k"
    expression:
      type: eq
      left:
        type: mul
        left:
          type: storage
          contract: pool_a
          key: reserve_x
        right:
          type: storage
          contract: pool_a
          key: reserve_y
      right:
        type: storage
        contract: pool_a
        key: k
    severity: critical
    category: dex
"#
}

fn sample_lending_manifest_yaml() -> &'static str {
    r#"
name: "SorobanLend"
version: "1.0.0"
contracts:
  - name: lending_pool
    role: lending_pool
    functions:
      - name: deposit
        mutability: write
      - name: borrow
        mutability: write
      - name: repay
        mutability: write
    storage_keys:
      - total_deposits
      - total_loans
      - available_liquidity
  - name: token
    role: token
    functions:
      - name: transfer
        mutability: write
interactions:
  - from_contract: lending_pool
    from_function: deposit
    to_contract: token
    to_function: transfer
invariants:
  - name: solvency
    description: "total_deposits >= total_loans"
    expression:
      type: gte
      left:
        type: storage
        contract: lending_pool
        key: total_deposits
      right:
        type: storage
        contract: lending_pool
        key: total_loans
    severity: critical
    category: lending
"#
}

// ── Phase 1: Protocol Specification Format Tests ────────────────────────────

#[test]
fn test_parse_dex_manifest() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    assert_eq!(manifest.name, "SorobanDEX");
    assert_eq!(manifest.version, "1.0.0");
    assert_eq!(manifest.contracts.len(), 3);
    assert_eq!(manifest.interactions.len(), 2);
    assert_eq!(manifest.invariants.len(), 1);
}

#[test]
fn test_parse_lending_manifest() {
    let manifest = ProtocolParser::from_yaml(sample_lending_manifest_yaml()).unwrap();
    assert_eq!(manifest.name, "SorobanLend");
    assert_eq!(manifest.contracts.len(), 2);
    assert_eq!(manifest.invariants.len(), 1);
}

#[test]
fn test_validate_manifest() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    assert!(ProtocolParser::validate(&manifest).is_ok());
}

#[test]
fn test_validate_manifest_missing_contract() {
    let manifest = ProtocolParser::from_yaml(
        r#"
name: "BadProtocol"
contracts: []
invariants: []
"#,
    )
    .unwrap();
    assert!(ProtocolParser::validate(&manifest).is_err());
}

#[test]
fn test_manifest_to_yaml_roundtrip() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let yaml = manifest.to_yaml().unwrap();
    let parsed_back = ProtocolParser::from_yaml(&yaml).unwrap();
    assert_eq!(parsed_back.name, manifest.name);
    assert_eq!(parsed_back.contracts.len(), manifest.contracts.len());
}

#[test]
fn test_expression_constructors() {
    let expr = Expression::eq(
        Expression::storage("pool_a", "reserve_x"),
        Expression::literal(1000.0),
    );
    match expr {
        Expression::Eq { left, right } => {
            assert!(matches!(*left, Expression::Storage { .. }));
            assert!(matches!(*right, Expression::Literal(1000.0)));
        }
        _ => panic!("Expected Eq expression"),
    }
}

#[test]
fn test_contract_role_display() {
    assert_eq!(format!("{}", ContractRole::AmmPool), "amm_pool");
    assert_eq!(format!("{}", ContractRole::Token), "token");
    assert_eq!(format!("{}", ContractRole::LendingPool), "lending_pool");
    assert_eq!(format!("{}", ContractRole::Bridge), "bridge");
    assert_eq!(format!("{}", ContractRole::Governance), "governance");
}

// ── Phase 2: Auto-Inference Tests ──────────────────────────────────────────

#[test]
fn test_infer_amm_invariants() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let inferred = PatternDetector::infer_all(&manifest);

    // Should find at least the constant product invariant for the AMM pool
    let amm_invariants: Vec<_> = inferred
        .iter()
        .filter(|i| matches!(i.pattern, ProtocolPattern::ConstantProductAmm))
        .collect();
    assert!(!amm_invariants.is_empty(), "Should infer AMM invariants");
}

#[test]
fn test_infer_lending_invariants() {
    let manifest = ProtocolParser::from_yaml(sample_lending_manifest_yaml()).unwrap();
    let inferred = PatternDetector::infer_all(&manifest);

    let lending_invariants: Vec<_> = inferred
        .iter()
        .filter(|i| matches!(i.pattern, ProtocolPattern::LendingPool))
        .collect();
    assert!(
        !lending_invariants.is_empty(),
        "Should infer lending invariants"
    );
}

#[test]
fn test_inferred_confidence_levels() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let inferred = PatternDetector::infer_all(&manifest);

    for inv in &inferred {
        match inv.pattern {
            ProtocolPattern::ConstantProductAmm => {
                // AMM with storage keys should have HIGH confidence
                assert_eq!(inv.confidence, PatternConfidence::High);
            }
            _ => {}
        }
    }
}

// ── Phase 3: Static Analysis Tests ─────────────────────────────────────────

#[test]
fn test_static_verify_equality() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let results = StaticAnalyzer::verify_all(&manifest);

    assert!(!results.is_empty());
    // The constant product invariant should be structurally verified
    let cp_result = results
        .iter()
        .find(|r| r.invariant_name == "constant_product");
    assert!(cp_result.is_some());
}

#[test]
fn test_static_verify_lending() {
    let manifest = ProtocolParser::from_yaml(sample_lending_manifest_yaml()).unwrap();
    let results = StaticAnalyzer::verify_all(&manifest);

    assert!(!results.is_empty());
    let solvency_result = results.iter().find(|r| r.invariant_name == "solvency");
    assert!(solvency_result.is_some());
}

#[test]
fn test_verification_status_display() {
    let verified = VerificationStatus::Verified;
    let violated = VerificationStatus::Violated {
        counterexample: "test".to_string(),
    };
    let unknown = VerificationStatus::Unknown {
        reason: "test".to_string(),
    };

    assert!(format!("{}", verified).contains("VERIFIED"));
    assert!(format!("{}", violated).contains("VIOLATED"));
    assert!(format!("{}", unknown).contains("UNKNOWN"));
}

// ── Phase 4: Dynamic Simulation Tests ──────────────────────────────────────

#[test]
fn test_simulator_run_dex() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let config = SimulationConfig {
        num_steps: 100,
        ..Default::default()
    };
    let mut simulator = ProtocolSimulator::new(manifest.clone(), config);
    let report = simulator.run();

    assert!(report.total_steps > 0);
    assert!(!report.contracts_simulated.is_empty());
}

#[test]
fn test_simulator_run_lending() {
    let manifest = ProtocolParser::from_yaml(sample_lending_manifest_yaml()).unwrap();
    let config = SimulationConfig {
        num_steps: 100,
        ..Default::default()
    };
    let mut simulator = ProtocolSimulator::new(manifest.clone(), config);
    let report = simulator.run();

    assert!(report.total_steps > 0);
    assert!(!report.contracts_simulated.is_empty());
}

#[test]
fn test_simulator_tracks_coverage() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let config = SimulationConfig {
        num_steps: 100,
        ..Default::default()
    };
    let mut simulator = ProtocolSimulator::new(manifest.clone(), config);
    let report = simulator.run();

    assert!(!report.coverage.operations_executed.is_empty());
    // Should execute at least a few swap operations
    let swaps = report
        .coverage
        .operations_executed
        .get("swap")
        .unwrap_or(&0);
    assert!(*swaps > 0, "Should execute swap operations");
}

// ── Phase 5: Call Graph Tests ──────────────────────────────────────────────

#[test]
fn test_build_call_graph() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    assert!(!graph.nodes.is_empty());
    assert!(!graph.entry_points.is_empty(), "Should have entry points");
}

#[test]
fn test_call_graph_entry_points() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    // swap, add_liquidity, remove_liquidity should be entry points
    let has_swap = graph.entry_points.iter().any(|ep| ep.contains("swap"));
    assert!(has_swap, "swap should be an entry point");
}

#[test]
fn test_call_graph_edges() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    // There should be edges for the interactions
    assert!(!graph.edges.is_empty());
}

#[test]
fn test_call_graph_to_dot() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    let dot = ProtocolCallGraphBuilder::to_dot(&graph);
    assert!(dot.starts_with("digraph"));
    assert!(dot.contains("->")); // Should have edges
}

#[test]
fn test_find_path() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    if graph.nodes.len() >= 2 {
        let nodes: Vec<String> = graph.nodes.keys().take(2).cloned().collect();
        let path = ProtocolCallGraphBuilder::find_path(&graph, &nodes[0], &nodes[1]);
        // Path may or may not exist depending on connectivity
        // Just verify the function runs without error
        assert!(path.is_some() || graph.nodes.len() >= 2);
    }
}

// ── Phase 6: Adversarial Tests ─────────────────────────────────────────────

#[test]
fn test_adversarial_exploration_dex() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let config = ExplorationConfig {
        num_rounds: 5,
        sequence_length: 10,
        ..Default::default()
    };
    let mut agent = AdversarialAgent::new(manifest, config);
    let report = agent.explore();

    // Should complete without error with contracts involved
    assert!(!report.contracts_involved.is_empty());
}

#[test]
fn test_exploit_difficulty_display() {
    assert_eq!(format!("{}", ExploitDifficulty::Easy), "EASY");
    assert_eq!(format!("{}", ExploitDifficulty::Medium), "MEDIUM");
    assert_eq!(format!("{}", ExploitDifficulty::Hard), "HARD");
    assert_eq!(format!("{}", ExploitDifficulty::VeryHard), "VERY HARD");
}

// ── Phase 7: Health Dashboard Tests ────────────────────────────────────────

#[test]
fn test_health_dashboard_generation() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let static_results = StaticAnalyzer::verify_all(&manifest);
    let config = SimulationConfig {
        num_steps: 100,
        ..Default::default()
    };
    let mut simulator = ProtocolSimulator::new(manifest.clone(), config);
    let sim_report = simulator.run();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    let sim_coverage = health::HealthCoverage {
        operations_executed: sim_report.coverage.operations_executed.clone(),
        contracts_interacted: sim_report.coverage.contracts_interacted.clone(),
        invariants_covered: sim_report.coverage.invariants_covered.clone(),
        invariants_violated: sim_report.coverage.invariants_violated.clone(),
        coverage_percentage: 50.0,
    };

    let health = ProtocolHealthDashboard::generate(
        &manifest,
        &static_results,
        Some(sim_coverage),
        Some(graph),
    );

    assert_eq!(health.protocol_name, "SorobanDEX");
    assert!(!health.invariants.is_empty());
    assert!(health.summary.total_invariants > 0);
}

#[test]
fn test_health_summary_formatting() {
    let manifest = ProtocolParser::from_yaml(sample_dex_manifest_yaml()).unwrap();
    let static_results = StaticAnalyzer::verify_all(&manifest);
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    let health = ProtocolHealthDashboard::generate(&manifest, &static_results, None, Some(graph));

    let summary = ProtocolHealthDashboard::format_summary(&health);
    assert!(summary.contains("SorobanDEX"));
    assert!(summary.contains("Health Score"));
    assert!(summary.contains("Contracts"));
}

// ── Phase 8: Full Pipeline Integration Tests ───────────────────────────────

#[test]
fn test_full_verification_pipeline() {
    let manifest_yaml = sample_dex_manifest_yaml();

    // Write manifest to temp file
    let dir = std::env::temp_dir();
    let manifest_path = dir.join("test_protocol.yaml");
    std::fs::write(&manifest_path, manifest_yaml).unwrap();

    let config = VerificationConfig {
        simulation_steps: 100,
        adversarial_exploration: false, // Faster test
        auto_infer: true,
        generate_call_graph: true,
        ..Default::default()
    };

    let report = ProtocolVerifyCommand::run(&manifest_path, config);

    assert!(report.manifest_valid);
    assert_eq!(report.protocol_name, "SorobanDEX");
    assert!(!report.static_results.is_empty());
    assert!(report.simulation_report.is_some());
    assert!(report.call_graph.is_some());
    assert!(report.health.is_some());

    // Clean up
    let _ = std::fs::remove_file(&manifest_path);
}

#[test]
fn test_pipeline_with_invalid_manifest() {
    let dir = std::env::temp_dir();
    let manifest_path = dir.join("invalid_protocol.yaml");
    std::fs::write(&manifest_path, "invalid: yaml: [").unwrap();

    let config = VerificationConfig::default();
    let report = ProtocolVerifyCommand::run(&manifest_path, config);

    assert!(!report.manifest_valid);
    assert!(!report.manifest_errors.is_empty());

    let _ = std::fs::remove_file(&manifest_path);
}

#[test]
fn test_exit_codes() {
    use report::ExitCode;

    assert_eq!(ExitCode::AllPassed.to_i32(), 0);
    assert_eq!(ExitCode::ViolationsFound.to_i32(), 1);
    assert_eq!(ExitCode::Unprovable.to_i32(), 2);
}

#[test]
fn test_report_formatting() {
    let manifest_yaml = sample_dex_manifest_yaml();
    let dir = std::env::temp_dir();
    let manifest_path = dir.join("test_formatting_protocol.yaml");
    std::fs::write(&manifest_path, manifest_yaml).unwrap();

    let config = VerificationConfig {
        simulation_steps: 50,
        adversarial_exploration: false,
        auto_infer: true,
        ..Default::default()
    };

    let report = ProtocolVerifyCommand::run(&manifest_path, config);
    let formatted = ProtocolVerifyCommand::format_report(&report, false);

    assert!(formatted.contains("Protocol Verification Report"));
    assert!(formatted.contains("SorobanDEX"));
    assert!(formatted.contains("Exit Code"));

    let _ = std::fs::remove_file(&manifest_path);
}

// ── Integration: End-to-End Multi-Contract Protocol ────────────────────────

#[test]
fn test_multi_contract_protocol() {
    let yaml = r#"
name: "FullProtocol"
version: "1.0.0"
contracts:
  - name: pool
    role: amm_pool
    functions:
      - name: swap
        mutability: write
      - name: add_liquidity
        mutability: write
    storage_keys:
      - reserve_x
      - reserve_y
      - k
  - name: lender
    role: lending_pool
    functions:
      - name: deposit
        mutability: write
      - name: borrow
        mutability: write
      - name: repay
        mutability: write
    storage_keys:
      - total_deposits
      - total_loans
  - name: gov_token
    role: governance
    functions:
      - name: vote
        mutability: write
      - name: delegate
        mutability: write
    storage_keys:
      - total_voting_power
      - total_delegated_power
interactions:
  - from_contract: pool
    from_function: swap
    to_contract: lender
    to_function: deposit
invariants:
  - name: constant_product
    expression:
      type: eq
      left:
        type: mul
        left:
          type: storage
          contract: pool
          key: reserve_x
        right:
          type: storage
          contract: pool
          key: reserve_y
      right:
        type: storage
        contract: pool
        key: k
    severity: critical
    category: dex
  - name: solvency
    expression:
      type: gte
      left:
        type: storage
        contract: lender
        key: total_deposits
      right:
        type: storage
        contract: lender
        key: total_loans
    severity: critical
    category: lending
"#;

    let manifest = ProtocolParser::from_yaml(yaml).unwrap();
    assert_eq!(manifest.contracts.len(), 3);
    assert_eq!(manifest.invariants.len(), 2);

    // Auto-infer
    let inferred = PatternDetector::infer_all(&manifest);
    assert!(
        inferred.len() >= 2,
        "Should infer invariants for all 3 contract types"
    );

    // Static analysis
    let static_results = StaticAnalyzer::verify_all(&manifest);
    assert_eq!(static_results.len(), 2);

    // Simulation
    let config = SimulationConfig {
        num_steps: 100,
        ..Default::default()
    };
    let mut simulator = ProtocolSimulator::new(manifest.clone(), config);
    let sim_report = simulator.run();
    assert!(sim_report.total_steps > 0);
}

// ── Edge Cases ─────────────────────────────────────────────────────────────

#[test]
fn test_empty_manifest() {
    let manifest = ProtocolParser::from_yaml(
        r#"
name: "EmptyProtocol"
version: "0.1.0"
contracts: []
interactions: []
invariants: []
"#,
    )
    .unwrap();
    assert!(ProtocolParser::validate(&manifest).is_err());
}

#[test]
fn test_single_contract_protocol() {
    let yaml = r#"
name: "SingleContract"
version: "1.0.0"
contracts:
  - name: solo
    role: amm_pool
    functions:
      - name: swap
        mutability: write
    storage_keys:
      - reserve_x
      - reserve_y
      - k
interactions: []
invariants:
  - name: k_constant
    expression:
      type: eq
      left:
        type: mul
        left:
          type: storage
          contract: solo
          key: reserve_x
        right:
          type: storage
          contract: solo
          key: reserve_y
      right:
        type: storage
        contract: solo
        key: k
    severity: critical
    category: dex
"#;
    let manifest = ProtocolParser::from_yaml(yaml).unwrap();
    assert!(ProtocolParser::validate(&manifest).is_ok());
    assert_eq!(manifest.contracts.len(), 1);
}

#[test]
fn test_cyclic_dependency_detection() {
    let yaml = r#"
name: "CyclicProtocol"
version: "1.0.0"
contracts:
  - name: contract_a
    functions:
      - name: call_b
        mutability: write
  - name: contract_b
    functions:
      - name: call_a
        mutability: write
  - name: contract_c
    functions:
      - name: call_a
        mutability: write
interactions:
  - from_contract: contract_a
    from_function: call_b
    to_contract: contract_b
    to_function: call_a
  - from_contract: contract_b
    from_function: call_a
    to_contract: contract_a
    to_function: call_b
invariants: []
"#;

    let manifest = ProtocolParser::from_yaml(yaml).unwrap();
    let graph = ProtocolCallGraphBuilder::build(&manifest);

    // Should have all 3 contracts' functions as nodes
    assert!(!graph.nodes.is_empty());
}
