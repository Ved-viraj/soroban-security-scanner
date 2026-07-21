//! Transaction Sequence Search (#444 — Phase 3)
//!
//! Three search strategies for finding profitable exploit transaction
//! sequences: beam search, genetic algorithm, and Monte Carlo tree search.
//! Each strategy is selectable by configuration.

use serde::{Deserialize, Serialize};

// ── Transaction Sequence ──────────────────────────────────────────

/// A sequence of transactions that could form an exploit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSequence {
    pub transactions: Vec<TransactionStep>,
    pub total_profit: f64,
    pub total_gas: u64,
    pub success_probability: f64,
    pub fitness: f64,
}

/// A single step in a transaction sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStep {
    pub action: ActionType,
    pub target_pool: String,
    pub target_oracle: Option<String>,
    pub amount: u128,
    pub asset: String,
}

/// Types of actions available in a transaction step.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    FlashLoanBorrow,
    FlashLoanRepay,
    SwapAForB,
    SwapBForA,
    LargeSwap,
    ProvideLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    Liquidate,
    FrontRun,
    BackRun,
    Wait,
}

// ── Search Configuration ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchConfig {
    pub algorithm: SearchAlgorithm,
    pub max_depth: usize,
    pub beam_width: usize,
    pub population_size: usize,
    pub generations: usize,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub mcts_iterations: usize,
    pub min_profit_threshold: f64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            algorithm: SearchAlgorithm::BeamSearch,
            max_depth: 5,
            beam_width: 100,
            population_size: 200,
            generations: 50,
            mutation_rate: 0.1,
            crossover_rate: 0.7,
            mcts_iterations: 1000,
            min_profit_threshold: 1.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchAlgorithm {
    BeamSearch,
    GeneticAlgorithm,
    MonteCarloTreeSearch,
}

/// Result from a search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub best_sequence: Option<TransactionSequence>,
    pub all_sequences: Vec<TransactionSequence>,
    pub iterations: usize,
    pub time_taken_ms: u64,
    pub algorithm_used: SearchAlgorithm,
}

// ── Beam Search ───────────────────────────────────────────────────

pub struct BeamSearch {
    config: SearchConfig,
}

impl BeamSearch {
    pub fn new(config: SearchConfig) -> Self {
        Self { config }
    }

    /// Search for profitable transaction sequences using beam search.
    pub fn search(
        &self,
        initial_sequences: Vec<TransactionSequence>,
        evaluate: impl Fn(&TransactionSequence) -> f64,
    ) -> SearchResult {
        let mut beam: Vec<TransactionSequence> = initial_sequences;
        let mut all_sequences = beam.clone();
        let mut iterations = 0;

        for depth in 1..=self.config.max_depth {
            let mut candidates: Vec<TransactionSequence> = Vec::new();

            for seq in &beam {
                // Generate successor sequences by extending with possible actions
                let successors = self.expand(seq);
                for successor in successors {
                    let fitness = evaluate(&successor);
                    let mut scored = successor;
                    scored.fitness = fitness;
                    scored.total_profit = fitness;
                    candidates.push(scored);
                }
            }

            iterations += candidates.len();

            // Sort by fitness and keep top K
            candidates.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(std::cmp::Ordering::Equal));
            beam = candidates
                .into_iter()
                .take(self.config.beam_width)
                .collect();

            all_sequences.extend(beam.clone());
        }

        let best = all_sequences
            .iter()
            .max_by(|a, b| a.fitness.partial_cmp(&b.fitness).unwrap_or(std::cmp::Ordering::Equal))
            .cloned();

        SearchResult {
            best_sequence: best,
            all_sequences,
            iterations,
            time_taken_ms: 0,
            algorithm_used: SearchAlgorithm::BeamSearch,
        }
    }

    fn expand(&self, seq: &TransactionSequence) -> Vec<TransactionSequence> {
        let actions = vec![
            ActionType::SwapAForB,
            ActionType::SwapBForA,
            ActionType::FlashLoanBorrow,
            ActionType::FlashLoanRepay,
            ActionType::LargeSwap,
            ActionType::Borrow,
            ActionType::Repay,
            ActionType::Liquidate,
        ];

        actions
            .into_iter()
            .map(|action| {
                let mut new_seq = seq.clone();
                new_seq.transactions.push(TransactionStep {
                    action,
                    target_pool: "pool_default".to_string(),
                    target_oracle: None,
                    amount: 1000u128,
                    asset: "XLM".to_string(),
                });
                new_seq
            })
            .collect()
    }
}

// ── Genetic Algorithm ────────────────────────────────────────────

pub struct GeneticAlgorithm {
    config: SearchConfig,
}

impl GeneticAlgorithm {
    pub fn new(config: SearchConfig) -> Self {
        Self { config }
    }

    /// Evolve a population of transaction sequences.
    pub fn evolve(
        &self,
        initial_population: Vec<TransactionSequence>,
        evaluate: impl Fn(&TransactionSequence) -> f64,
    ) -> SearchResult {
        let mut population = initial_population;
        let mut all_sequences = population.clone();
        let mut iterations = 0;

        for gen in 0..self.config.generations {
            // Evaluate fitness
            let mut scored: Vec<(TransactionSequence, f64)> = population
                .into_iter()
                .map(|seq| {
                    let fitness = evaluate(&seq);
                    (seq, fitness)
                })
                .collect();

            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            let survivors: Vec<TransactionSequence> = scored
                .into_iter()
                .take(self.config.beam_width)
                .map(|(seq, _)| seq)
                .collect();

            // Crossover and mutate
            let mut next_generation = survivors.clone();
            while next_generation.len() < self.config.population_size {
                if survivors.len() < 2 {
                    break;
                }
                let parent_a = &survivors[gen % survivors.len()];
                let parent_b = &survivors[(gen + 1) % survivors.len()];
                let mut child = self.crossover(parent_a, parent_b);
                self.mutate(&mut child);
                next_generation.push(child);
            }

            iterations += next_generation.len();
            all_sequences.extend(next_generation.clone());
            population = next_generation;
        }

        let best = all_sequences
            .iter()
            .max_by(|a, b| a.fitness.partial_cmp(&b.fitness).unwrap_or(std::cmp::Ordering::Equal))
            .cloned();

        SearchResult {
            best_sequence: best,
            all_sequences,
            iterations,
            time_taken_ms: 0,
            algorithm_used: SearchAlgorithm::GeneticAlgorithm,
        }
    }

    fn crossover(
        &self,
        parent_a: &TransactionSequence,
        parent_b: &TransactionSequence,
    ) -> TransactionSequence {
        let min_len = parent_a.transactions.len().min(parent_b.transactions.len());
        let cut = if min_len > 0 { min_len / 2 } else { 0 };

        let mut txs = Vec::new();
        txs.extend(parent_a.transactions[..cut].to_vec());
        if cut < parent_b.transactions.len() {
            txs.extend(parent_b.transactions[cut..].to_vec());
        }

        TransactionSequence {
            transactions: txs,
            total_profit: 0.0,
            total_gas: 0,
            success_probability: 0.5,
            fitness: 0.0,
        }
    }

    fn mutate(&self, seq: &mut TransactionSequence) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        if rng.gen::<f64>() < self.config.mutation_rate {
            if !seq.transactions.is_empty() {
                let idx = rng.gen_range(0..seq.transactions.len());
                seq.transactions[idx].amount = rng.gen_range(1..100000);
            }
        }

        if rng.gen::<f64>() < self.config.mutation_rate {
            let action = if rng.gen::<bool>() {
                ActionType::SwapAForB
            } else {
                ActionType::SwapBForA
            };
            seq.transactions.push(TransactionStep {
                action,
                target_pool: "pool_default".to_string(),
                target_oracle: None,
                amount: rng.gen_range(1..10000),
                asset: "XLM".to_string(),
            });
        }
    }
}

// ── Monte Carlo Tree Search ──────────────────────────────────────

#[derive(Debug, Clone)]
struct MctsNode {
    state: TransactionSequence,
    visits: usize,
    total_reward: f64,
    children: Vec<MctsNode>,
}

pub struct MonteCarloTreeSearch {
    config: SearchConfig,
}

impl MonteCarloTreeSearch {
    pub fn new(config: SearchConfig) -> Self {
        Self { config }
    }

    /// Search for profitable sequences using MCTS.
    pub fn search(
        &self,
        root_sequence: TransactionSequence,
        evaluate: impl Fn(&TransactionSequence) -> f64,
    ) -> SearchResult {
        let mut root = MctsNode {
            state: root_sequence,
            visits: 0,
            total_reward: 0.0,
            children: Vec::new(),
        };

        let mut all_sequences = Vec::new();

        for _ in 0..self.config.mcts_iterations {
            // Selection + Expansion + Simulation + Backpropagation
            let reward = self.mcts_round(&mut root, &evaluate);
            // Store any promising sequences
            if reward > self.config.min_profit_threshold {
                all_sequences.push(root.state.clone());
            }
        }

        // Select best child based on average reward
        let best_child = root
            .children
            .iter()
            .max_by(|a, b| {
                let avg_a = if a.visits > 0 { a.total_reward / a.visits as f64 } else { 0.0 };
                let avg_b = if b.visits > 0 { b.total_reward / b.visits as f64 } else { 0.0 };
                avg_a.partial_cmp(&avg_b).unwrap_or(std::cmp::Ordering::Equal)
            });

        let best = best_child.map(|c| c.state.clone());

        for child in &root.children {
            all_sequences.push(child.state.clone());
        }

        SearchResult {
            best_sequence: best,
            all_sequences,
            iterations: self.config.mcts_iterations,
            time_taken_ms: 0,
            algorithm_used: SearchAlgorithm::MonteCarloTreeSearch,
        }
    }

    fn mcts_round(
        &self,
        node: &mut MctsNode,
        evaluate: &impl Fn(&TransactionSequence) -> f64,
    ) -> f64 {
        // Selection: UCB1
        if node.children.is_empty() {
            // Expansion
            if node.state.transactions.len() < self.config.max_depth {
                let actions = vec![ActionType::SwapAForB, ActionType::SwapBForA, ActionType::LargeSwap];
                for action in actions {
                    let mut new_state = node.state.clone();
                    new_state.transactions.push(TransactionStep {
                        action,
                        target_pool: "pool_default".to_string(),
                        target_oracle: None,
                        amount: 1000,
                        asset: "XLM".to_string(),
                    });
                    node.children.push(MctsNode {
                        state: new_state,
                        visits: 0,
                        total_reward: 0.0,
                        children: Vec::new(),
                    });
                }
            }

            // Simulation: evaluate current state
            let reward = evaluate(&node.state);
            node.visits += 1;
            node.total_reward += reward;
            return reward;
        }

        // UCB1 selection
        let total_visits = node.visits as f64;
        let selected = node
            .children
            .iter_mut()
            .max_by(|a, b| {
                let ucb_a = if a.visits == 0 {
                    f64::INFINITY
                } else {
                    (a.total_reward / a.visits as f64)
                        + 2.0_f64.sqrt() * (total_visits.ln() / a.visits as f64).sqrt()
                };
                let ucb_b = if b.visits == 0 {
                    f64::INFINITY
                } else {
                    (b.total_reward / b.visits as f64)
                        + 2.0_f64.sqrt() * (total_visits.ln() / b.visits as f64).sqrt()
                };
                ucb_a.partial_cmp(&ucb_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();

        let reward = self.mcts_round(selected, evaluate);

        // Backpropagation
        node.visits += 1;
        node.total_reward += reward;
        reward
    }
}
