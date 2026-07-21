#[cfg(test)]
mod tests {
    use super::*;
    use super::defi_primitives::*;
    use super::attack_agent::*;
    use super::search_engine::*;
    use super::oracle_detection::*;
    use super::mev_detection::*;
    use super::flash_loan::*;
    use super::profitability::*;
    use super::report::*;

    // ── DeFi Primitives Tests ──────────────────────────────────────

    #[test]
    fn constant_product_amm_swap() {
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 1000, 1000);
        // 10 XLM swap should produce ~9.9 USD with 0.3% fee
        let out = pool.get_amount_out(10, "XLM").unwrap();
        assert!(out > 0);
        assert!(out < 10);
    }

    #[test]
    fn constant_product_amm_invariant() {
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 100, 200);
        assert_eq!(pool.k(), 20000);
    }

    #[test]
    fn constant_product_amm_spot_price() {
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 1000, 2000);
        assert!((pool.spot_price_a_in_b() - 2.0).abs() < 0.001);
        assert!((pool.spot_price_b_in_a() - 0.5).abs() < 0.001);
    }

    #[test]
    fn constant_product_amm_price_impact() {
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 100000, 100000);
        let impact = pool.price_impact_bps(1000, "XLM").unwrap();
        // Small trade should have small impact
        assert!(impact < 200);
    }

    #[test]
    fn constant_product_amm_large_price_impact() {
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 1000, 1000);
        let impact = pool.price_impact_bps(500, "XLM").unwrap();
        // Large trade relative to pool should have significant impact
        assert!(impact > 1000);
    }

    #[test]
    fn lending_pool_max_borrow() {
        let pool = LendingPool::new("lend1", "XLM", "USD", 1000000);
        let max = pool.max_borrow(1000, 2.0, 1.0);
        // 1000 XLM * 2.0 price = 2000 value, 150% ratio → ~1333 USD max
        assert!(max > 0);
    }

    #[test]
    fn lending_pool_liquidation_check() {
        let pool = LendingPool::new("lend1", "XLM", "USD", 1000000);
        // 1000 XLM collateral at $2, borrowing $1800 at $1 with 120% threshold
        let liquidatable = pool.is_liquidatable(1000, 1800, 2.0, 1.0);
        assert!(liquidatable);
    }

    #[test]
    fn lending_pool_not_liquidatable_with_sufficient_collateral() {
        let pool = LendingPool::new("lend1", "XLM", "USD", 1000000);
        // 1000 XLM collateral at $2, borrowing $1000 at $1 → 200% ratio
        let liquidatable = pool.is_liquidatable(1000, 1000, 2.0, 1.0);
        assert!(!liquidatable);
    }

    #[test]
    fn oracle_twap_calculation() {
        let mut oracle = Oracle::new("oracle1", "XLM/USD", 2.0);
        oracle.historical_prices = vec![
            (1000, 1.9),
            (2000, 2.0),
            (3000, 2.1),
        ];
        let twap = oracle.twap();
        assert!((twap - 2.0).abs() < 0.001);
    }

    // ── Attack Agent Tests ─────────────────────────────────────────

    #[test]
    fn attack_agent_initial_state() {
        let agent = AttackAgent::new(
            vec![AttackCapability::FlashLoan, AttackCapability::Swap],
            1000,
        );
        assert_eq!(agent.initial_balance, 1000);
        assert_eq!(agent.current_balance, 1000);
        assert!(agent.executed_actions.is_empty());
    }

    #[test]
    fn attack_agent_reset() {
        let mut agent = AttackAgent::new(vec![AttackCapability::Swap], 1000);
        agent.current_balance = 500;
        agent.record_action(AgentAction {
            capability: AttackCapability::Swap,
            target: "pool1".into(),
            amount: 100,
            token: "XLM".into(),
            timestamp: 0,
        });
        agent.reset();
        assert_eq!(agent.current_balance, 1000);
        assert!(agent.executed_actions.is_empty());
    }

    #[test]
    fn attack_agent_net_profit() {
        let agent = AttackAgent::new(vec![], 1000);
        let profit = agent.net_profit(100, 0.0000001);
        assert_eq!(profit, 0.0 - 0.00001); // No change minus gas
    }

    // ── Search Engine Tests ────────────────────────────────────────

    #[test]
    fn beam_search_finds_sequences() {
        let config = SearchConfig {
            algorithm: SearchAlgorithm::BeamSearch,
            max_depth: 3,
            beam_width: 5,
            ..Default::default()
        };
        let beam = BeamSearch::new(config);

        let initial = vec![TransactionSequence {
            transactions: vec![],
            total_profit: 0.0,
            total_gas: 0,
            success_probability: 1.0,
            fitness: 0.0,
        }];

        let result = beam.search(initial, |seq| {
            // Simple fitness: profit from swaps
            seq.transactions.len() as f64 * 10.0
        });

        assert!(result.iterations > 0);
        assert!(result.best_sequence.is_some());
    }

    #[test]
    fn genetic_algorithm_evolves() {
        let config = SearchConfig {
            algorithm: SearchAlgorithm::GeneticAlgorithm,
            generations: 10,
            population_size: 20,
            beam_width: 10,
            ..Default::default()
        };
        let ga = GeneticAlgorithm::new(config);

        let initial = (0..20)
            .map(|_| TransactionSequence {
                transactions: vec![],
                total_profit: 0.0,
                total_gas: 0,
                success_probability: 0.5,
                fitness: 0.0,
            })
            .collect();

        let result = ga.evolve(initial, |seq| {
            seq.transactions.len() as f64
        });

        assert!(result.iterations > 0);
    }

    #[test]
    fn mcts_search() {
        let config = SearchConfig {
            algorithm: SearchAlgorithm::MonteCarloTreeSearch,
            mcts_iterations: 50,
            max_depth: 3,
            ..Default::default()
        };
        let mcts = MonteCarloTreeSearch::new(config);

        let root = TransactionSequence {
            transactions: vec![],
            total_profit: 0.0,
            total_gas: 0,
            success_probability: 1.0,
            fitness: 0.0,
        };

        let result = mcts.search(root, |seq| seq.transactions.len() as f64);
        assert_eq!(result.iterations, 50);
    }

    // ── Oracle Detection Tests ────────────────────────────────────

    #[test]
    fn oracle_manipulation_detected() {
        let detector = OracleManipulationDetector::new(500); // 5% threshold
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 1000, 2000);
        let oracle = Oracle::new("oracle1", "XLM/USD", 2.0);

        let scenarios = detector.detect(&pool, &oracle);
        // With small pool, manipulation should be detectable
        assert!(!scenarios.is_empty());
    }

    #[test]
    fn twap_oracle_harder_to_manipulate() {
        let detector = OracleManipulationDetector::new(500);
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 1000, 2000);
        let mut oracle = Oracle::new("oracle1", "XLM/USD", 2.0);
        oracle.oracle_type = OracleType::TWAP;

        let scenarios = detector.detect(&pool, &oracle);
        assert!(scenarios.is_empty()); // TWAP is harder to manipulate
    }

    // ── MEV Detection Tests ───────────────────────────────────────

    #[test]
    fn sandwich_attack_detection() {
        let detector = MevDetector::new(0.001);
        let sandwich = detector.detect_sandwich(100, 1000, 1000, 30, true);
        // Should detect sandwich opportunity with sufficient reserves
        // May or may not be profitable depending on amounts
        assert!(sandwich.is_some());
    }

    #[test]
    fn mev_detector_scans_trades() {
        let detector = MevDetector::new(0.0);
        let trades = vec![(100, 1000, 1000, true), (50, 2000, 2000, false)];
        let opportunities = detector.scan(&trades);
        assert!(!opportunities.is_empty());
    }

    // ── Flash Loan Tests ──────────────────────────────────────────

    #[test]
    fn flash_loan_simulation() {
        let lending = LendingPool::new("lend1", "XLM", "USD", 1_000_000);
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 500_000, 500_000);
        let simulator = FlashLoanSimulator::new();

        let attack = simulator.simulate(&lending, &pool, 10_000);
        assert!(!attack.exploit_path.is_empty());
        assert_eq!(attack.exploit_path.len(), 4); // borrow, manipulate, exploit, repay
    }

    #[test]
    fn flash_loan_optimization() {
        let lending = LendingPool::new("lend1", "XLM", "USD", 1_000_000);
        let pool = ConstantProductAmm::new("pool1", "XLM", "USD", 500_000, 500_000);
        let simulator = FlashLoanSimulator::new();

        let attacks = simulator.optimize_flash_loan(&lending, &pool, 0.1, 5);
        assert_eq!(attacks.len(), 5);
    }

    // ── Profitability Tests ──────────────────────────────────────

    #[test]
    fn profitability_analyzer() {
        let analyzer = ProfitabilityAnalyzer::new();
        let result = analyzer.analyze(
            10_000,  // required capital
            500.0,   // gross profit
            10.0,    // fees
            100_000, // gas
            3,       // tx count
            5,       // timing window
            1_000_000, // pool liquidity
            0.1,     // risk of revert
        );

        assert!(result.net_profit > 0.0);
        assert!(result.is_exploitable);
    }

    #[test]
    fn exploit_difficulty_scoring() {
        let difficulty = ExploitDifficulty::calculate(
            5,        // tx count
            3,        // timing window (seconds)
            100_000,  // required capital
            1_000_000, // pool liquidity
        );

        assert!(difficulty.score > 0.0);
        assert!(difficulty.score <= 1.0);
        assert!((difficulty.capital_to_liquidity_ratio - 0.1).abs() < 0.001);
    }

    #[test]
    fn profitability_scoring() {
        let analyzer = ProfitabilityAnalyzer::new();
        let profitability = analyzer.analyze(
            10_000, 1000.0, 50.0, 100_000, 2, 3, 100_000, 0.05,
        );
        let score = analyzer.score(&profitability);

        assert!(score.overall_score > 0.0);
        assert!(score.overall_score <= 1.0);
        assert_ne!(score.recommendation, ProfitabilityRecommendation::NotExploitable);
    }

    // ── Report Tests ──────────────────────────────────────────────

    #[test]
    fn economic_report_adds_findings() {
        let mut report = EconomicExploitReport::new("Test Report", "TestProtocol");
        report.add_finding(EconomicFinding {
            id: 1,
            title: "Flash Loan Attack".into(),
            finding_type: EconomicFindingType::FlashLoanAttack,
            severity: EconomicSeverity::Critical,
            attack_sequence: vec![],
            profit_breakdown: Some(ProfitBreakdown {
                gross_profit: 1000.0,
                fees_paid: 50.0,
                gas_paid: 1.0,
                net_profit: 949.0,
                required_capital: 0,
                roi_percent: 0.0,
                is_profitable: true,
            }),
            required_preconditions: vec![],
            description: "Test flash loan attack".into(),
            recommendation: "Use TWAP oracle".into(),
        });

        assert_eq!(report.summary.total_findings, 1);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.total_profitable_attacks, 1);
    }

    #[test]
    fn economic_report_security_score() {
        let mut report = EconomicExploitReport::new("Test", "Protocol");
        report.add_finding(EconomicFinding {
            id: 1,
            title: "Critical".into(),
            finding_type: EconomicFindingType::OracleManipulation,
            severity: EconomicSeverity::Critical,
            attack_sequence: vec![],
            profit_breakdown: None,
            required_preconditions: vec![],
            description: "test".into(),
            recommendation: "test".into(),
        });
        report.calculate_security_score();
        assert!(report.summary.protocol_security_score < 100.0);
    }

    #[test]
    fn text_summary_output() {
        let mut report = EconomicExploitReport::new("Test", "Protocol");
        report.add_finding(EconomicFinding {
            id: 1,
            title: "Finding".into(),
            finding_type: EconomicFindingType::MevSandwich,
            severity: EconomicSeverity::High,
            attack_sequence: vec![],
            profit_breakdown: None,
            required_preconditions: vec![],
            description: "Test finding".into(),
            recommendation: "Fix".into(),
        });
        let text = report.to_text_summary();
        assert!(text.contains("Economic Exploit Report"));
        assert!(text.contains("Protocol"));
    }
}
