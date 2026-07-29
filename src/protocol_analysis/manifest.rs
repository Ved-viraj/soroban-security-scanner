//! Phase 1 — Protocol Specification Format.
//!
//! Defines the `ProtocolManifest` YAML/JSON format that describes a multi-contract
//! protocol: contracts, interactions, and invariants.
//!
//! # Example YAML
//!
//! ```yaml
//! name: "SorobanDEX"
//! version: "1.0.0"
//! description: "A decentralized exchange on Soroban"
//! contracts:
//!   - name: pool_a
//!     address: "CA3D5K7FJ9..."
//!     wasm_path: "./pool.wasm"
//!     role: amm_pool
//!   - name: token_x
//!     address: "CB7F2M9N4..."
//!     wasm_path: "./token.wasm"
//!     role: token
//! interactions:
//!   - from_contract: pool_a
//!     from_function: swap
//!     to_contract: token_x
//!     to_function: transfer
//! invariants:
//!   - name: constant_product
//!     description: "reserve_x * reserve_y == k"
//!     expression:
//!       type: mul
//!       left:
//!         type: storage
//!         contract: pool_a
//!         key: reserve_x
//!       right:
//!         type: storage
//!         contract: pool_a
//!         key: reserve_y
//!     severity: critical
//! ```

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

// ── Manifest Types ──────────────────────────────────────────────────────────

/// The top-level protocol manifest describing a multi-contract system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolManifest {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub contracts: Vec<ContractSpec>,
    #[serde(default)]
    pub interactions: Vec<InteractionSpec>,
    #[serde(default)]
    pub invariants: Vec<InvariantSpec>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSpec {
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub wasm_path: String,
    #[serde(default)]
    pub role: ContractRole,
    #[serde(default)]
    pub functions: Vec<FunctionSig>,
    #[serde(default)]
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSig {
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub mutability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractRole {
    #[serde(rename = "amm_pool")]
    AmmPool,
    #[serde(rename = "token")]
    Token,
    #[serde(rename = "lending_pool")]
    LendingPool,
    #[serde(rename = "bridge")]
    Bridge,
    #[serde(rename = "governance")]
    Governance,
    #[serde(rename = "factory")]
    Factory,
    #[serde(rename = "oracle")]
    Oracle,
    #[serde(rename = "fee_distributor")]
    FeeDistributor,
    #[serde(rename = "treasury")]
    Treasury,
    #[serde(rename = "custom")]
    Custom(String),
}

impl Default for ContractRole {
    fn default() -> Self {
        Self::Custom("unknown".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionSpec {
    pub from_contract: String,
    pub from_function: String,
    pub to_contract: String,
    pub to_function: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub value_transfer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub expression: Expression,
    #[serde(default = "default_invariant_severity")]
    pub severity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub auto_inferred: bool,
}

fn default_invariant_severity() -> String {
    "high".to_string()
}

// ── Expression DSL ──────────────────────────────────────────────────────────

/// Simple DSL for expressing protocol-level invariants.
///
/// Serialized as an internally-tagged JSON/YAML map:
/// ```json
/// {"type": "eq", "left": {"type": "storage", ...}, "right": {"type": "literal", "value": 5.0}}
/// ```
#[derive(Debug, Clone)]
pub enum Expression {
    Literal(f64),
    String(String),
    Bool(bool),
    Storage {
        contract: Box<String>,
        key: Box<String>,
    },
    SumOver {
        contract: Box<String>,
        key_pattern: Box<String>,
        items: Vec<Expression>,
    },
    CountOver {
        contract: Box<String>,
        key_pattern: Box<String>,
    },
    Reserve {
        pool: Box<String>,
        token: Box<String>,
    },
    ConstantK {
        pool: Box<String>,
    },
    TotalSupply {
        token: Box<String>,
    },
    TotalDeposits {
        pool: Box<String>,
    },
    TotalLoans {
        pool: Box<String>,
    },
    LockedSoroban {
        bridge: Box<String>,
    },
    MintedCounterpart {
        bridge: Box<String>,
    },
    TotalVotingPower {
        gov: Box<String>,
    },
    SumDelegatedPower {
        gov: Box<String>,
    },
    CollateralValue {
        vault: Box<String>,
    },
    AvailableLiquidity {
        pool: Box<String>,
    },
    ProtocolFees {
        pool: Box<String>,
    },
    Add {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Sub {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Mul {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Div {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Sum(Vec<Expression>),
    Eq {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Neq {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Gte {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Lte {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Gt {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Lt {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Before {
        operation: Box<String>,
        expr: Box<Expression>,
    },
    After {
        operation: Box<String>,
        expr: Box<Expression>,
    },
    And {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Or {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Not(Box<Expression>),
    Implies {
        antecedent: Box<Expression>,
        consequent: Box<Expression>,
    },
    ForAll {
        variable: String,
        collection: Box<Expression>,
        condition: Box<Expression>,
    },
}

// ── Custom Serialize for Expression ─────────────────────────────────────────

impl Serialize for Expression {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Expression::Literal(val) => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "literal")?;
                s.serialize_field("value", val)?;
                s.end()
            }
            Expression::String(val) => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "string")?;
                s.serialize_field("value", val)?;
                s.end()
            }
            Expression::Bool(val) => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "bool")?;
                s.serialize_field("value", val)?;
                s.end()
            }
            Expression::Storage { contract, key } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "storage")?;
                s.serialize_field("contract", contract.as_str())?;
                s.serialize_field("key", key.as_str())?;
                s.end()
            }
            Expression::Reserve { pool, token } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "reserve")?;
                s.serialize_field("pool", pool.as_str())?;
                s.serialize_field("token", token.as_str())?;
                s.end()
            }
            Expression::ConstantK { pool } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "constant_k")?;
                s.serialize_field("pool", pool.as_str())?;
                s.end()
            }
            Expression::TotalSupply { token } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "total_supply")?;
                s.serialize_field("token", token.as_str())?;
                s.end()
            }
            Expression::TotalDeposits { pool } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "total_deposits")?;
                s.serialize_field("pool", pool.as_str())?;
                s.end()
            }
            Expression::TotalLoans { pool } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "total_loans")?;
                s.serialize_field("pool", pool.as_str())?;
                s.end()
            }
            Expression::LockedSoroban { bridge } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "locked_soroban")?;
                s.serialize_field("bridge", bridge.as_str())?;
                s.end()
            }
            Expression::MintedCounterpart { bridge } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "minted_counterpart")?;
                s.serialize_field("bridge", bridge.as_str())?;
                s.end()
            }
            Expression::TotalVotingPower { gov } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "total_voting_power")?;
                s.serialize_field("gov", gov.as_str())?;
                s.end()
            }
            Expression::SumDelegatedPower { gov } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "sum_delegated_power")?;
                s.serialize_field("gov", gov.as_str())?;
                s.end()
            }
            Expression::CollateralValue { vault } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "collateral_value")?;
                s.serialize_field("vault", vault.as_str())?;
                s.end()
            }
            Expression::AvailableLiquidity { pool } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "available_liquidity")?;
                s.serialize_field("pool", pool.as_str())?;
                s.end()
            }
            Expression::ProtocolFees { pool } => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "protocol_fees")?;
                s.serialize_field("pool", pool.as_str())?;
                s.end()
            }
            Expression::SumOver {
                contract,
                key_pattern,
                items,
            } => {
                let mut s = serializer.serialize_struct("Expression", 4)?;
                s.serialize_field("type", "sum_over")?;
                s.serialize_field("contract", contract.as_str())?;
                s.serialize_field("key_pattern", key_pattern.as_str())?;
                s.serialize_field("items", items)?;
                s.end()
            }
            Expression::CountOver {
                contract,
                key_pattern,
            } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "count_over")?;
                s.serialize_field("contract", contract.as_str())?;
                s.serialize_field("key_pattern", key_pattern.as_str())?;
                s.end()
            }
            Expression::Sum(items) => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "sum")?;
                s.serialize_field("items", items)?;
                s.end()
            }
            Expression::Before { operation, expr } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "before")?;
                s.serialize_field("operation", operation.as_str())?;
                s.serialize_field("expr", expr)?;
                s.end()
            }
            Expression::After { operation, expr } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "after")?;
                s.serialize_field("operation", operation.as_str())?;
                s.serialize_field("expr", expr)?;
                s.end()
            }
            Expression::ForAll {
                variable,
                collection,
                condition,
            } => {
                let mut s = serializer.serialize_struct("Expression", 4)?;
                s.serialize_field("type", "for_all")?;
                s.serialize_field("variable", variable)?;
                s.serialize_field("collection", collection)?;
                s.serialize_field("condition", condition)?;
                s.end()
            }
            Expression::Implies {
                antecedent,
                consequent,
            } => {
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", "implies")?;
                s.serialize_field("antecedent", antecedent)?;
                s.serialize_field("consequent", consequent)?;
                s.end()
            }
            Expression::Not(inner) => {
                let mut s = serializer.serialize_struct("Expression", 2)?;
                s.serialize_field("type", "not")?;
                s.serialize_field("inner", inner)?;
                s.end()
            }
            // Binary operations share the same structure: type + left + right
            _ => {
                let (t, l, r) = binary_op_fields(self);
                let mut s = serializer.serialize_struct("Expression", 3)?;
                s.serialize_field("type", t)?;
                s.serialize_field("left", l)?;
                s.serialize_field("right", r)?;
                s.end()
            }
        }
    }
}

/// Helper: returns (tag, left, right) for binary operations.
fn binary_op_fields(expr: &Expression) -> (&str, &Expression, &Expression) {
    match expr {
        Expression::Add { left, right } => ("add", left, right),
        Expression::Sub { left, right } => ("sub", left, right),
        Expression::Mul { left, right } => ("mul", left, right),
        Expression::Div { left, right } => ("div", left, right),
        Expression::Eq { left, right } => ("eq", left, right),
        Expression::Neq { left, right } => ("neq", left, right),
        Expression::Gte { left, right } => ("gte", left, right),
        Expression::Lte { left, right } => ("lte", left, right),
        Expression::Gt { left, right } => ("gt", left, right),
        Expression::Lt { left, right } => ("lt", left, right),
        Expression::And { left, right } => ("and", left, right),
        Expression::Or { left, right } => ("or", left, right),
        _ => panic!("not a binary operation"),
    }
}

// ── Custom Deserialize for Expression ───────────────────────────────────────

impl<'de> Deserialize<'de> for Expression {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct("Expression", &["type"], ExpressionVisitor)
    }
}

struct ExpressionVisitor;

impl<'de> Visitor<'de> for ExpressionVisitor {
    type Value = Expression;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map with a 'type' field identifying the expression variant")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        // Collect all fields into a JSON Value for flexible parsing
        let mut fields = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let val: serde_json::Value = map.next_value()?;
            fields.insert(key, val);
        }

        let expr_type: Option<String> = fields
            .get("type")
            .and_then(|v| v.as_str().map(String::from));

        let t = expr_type.ok_or_else(|| de::Error::missing_field("type"))?;

        Ok(match t.as_str() {
            "literal" => {
                let val = fields
                    .get("value")
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| de::Error::custom("literal requires a 'value' field"))?;
                Expression::Literal(val)
            }
            "string" => {
                let val = fields
                    .get("value")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("string requires a 'value' field"))?;
                Expression::String(val)
            }
            "bool" => {
                let val = fields
                    .get("value")
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| de::Error::custom("bool requires a 'value' field"))?;
                Expression::Bool(val)
            }
            "storage" => {
                let contract = fields
                    .get("contract")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("storage requires a 'contract' field"))?;
                let key = fields
                    .get("key")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("storage requires a 'key' field"))?;
                Expression::Storage {
                    contract: Box::new(contract),
                    key: Box::new(key),
                }
            }
            "reserve" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("reserve requires a 'pool' field"))?;
                let token = fields
                    .get("token")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("reserve requires a 'token' field"))?;
                Expression::Reserve {
                    pool: Box::new(pool),
                    token: Box::new(token),
                }
            }
            "constant_k" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("constant_k requires a 'pool' field"))?;
                Expression::ConstantK {
                    pool: Box::new(pool),
                }
            }
            "total_supply" => {
                let token = fields
                    .get("token")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("total_supply requires a 'token' field"))?;
                Expression::TotalSupply {
                    token: Box::new(token),
                }
            }
            "total_deposits" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("total_deposits requires a 'pool' field"))?;
                Expression::TotalDeposits {
                    pool: Box::new(pool),
                }
            }
            "total_loans" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("total_loans requires a 'pool' field"))?;
                Expression::TotalLoans {
                    pool: Box::new(pool),
                }
            }
            "locked_soroban" => {
                let bridge = fields
                    .get("bridge")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("locked_soroban requires a 'bridge' field"))?;
                Expression::LockedSoroban {
                    bridge: Box::new(bridge),
                }
            }
            "minted_counterpart" => {
                let bridge = fields
                    .get("bridge")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("minted_counterpart requires a 'bridge' field")
                    })?;
                Expression::MintedCounterpart {
                    bridge: Box::new(bridge),
                }
            }
            "total_voting_power" => {
                let gov = fields
                    .get("gov")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("total_voting_power requires a 'gov' field")
                    })?;
                Expression::TotalVotingPower { gov: Box::new(gov) }
            }
            "sum_delegated_power" => {
                let gov = fields
                    .get("gov")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("sum_delegated_power requires a 'gov' field")
                    })?;
                Expression::SumDelegatedPower { gov: Box::new(gov) }
            }
            "collateral_value" => {
                let vault = fields
                    .get("vault")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("collateral_value requires a 'vault' field")
                    })?;
                Expression::CollateralValue {
                    vault: Box::new(vault),
                }
            }
            "available_liquidity" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("available_liquidity requires a 'pool' field")
                    })?;
                Expression::AvailableLiquidity {
                    pool: Box::new(pool),
                }
            }
            "protocol_fees" => {
                let pool = fields
                    .get("pool")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("protocol_fees requires a 'pool' field"))?;
                Expression::ProtocolFees {
                    pool: Box::new(pool),
                }
            }
            "sum" => {
                let items: Vec<Expression> = serde_json::from_value(
                    fields
                        .get("items")
                        .cloned()
                        .unwrap_or(serde_json::Value::Array(vec![])),
                )
                .map_err(de::Error::custom)?;
                Expression::Sum(items)
            }
            "sum_over" => {
                let contract = fields
                    .get("contract")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("sum_over requires a 'contract' field"))?;
                let key_pattern = fields
                    .get("key_pattern")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("sum_over requires a 'key_pattern' field"))?;
                let items: Vec<Expression> = serde_json::from_value(
                    fields
                        .get("items")
                        .cloned()
                        .unwrap_or(serde_json::Value::Array(vec![])),
                )
                .map_err(de::Error::custom)?;
                Expression::SumOver {
                    contract: Box::new(contract),
                    key_pattern: Box::new(key_pattern),
                    items,
                }
            }
            "count_over" => {
                let contract = fields
                    .get("contract")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("count_over requires a 'contract' field"))?;
                let key_pattern = fields
                    .get("key_pattern")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("count_over requires a 'key_pattern' field")
                    })?;
                Expression::CountOver {
                    contract: Box::new(contract),
                    key_pattern: Box::new(key_pattern),
                }
            }
            "before" | "after" => {
                let operation = fields
                    .get("operation")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| {
                        de::Error::custom("before/after requires an 'operation' field")
                    })?;
                let expr: Expression =
                    serde_json::from_value(fields.get("expr").cloned().ok_or_else(|| {
                        de::Error::custom("before/after requires an 'expr' field")
                    })?)
                    .map_err(de::Error::custom)?;
                if t == "before" {
                    Expression::Before {
                        operation: Box::new(operation),
                        expr: Box::new(expr),
                    }
                } else {
                    Expression::After {
                        operation: Box::new(operation),
                        expr: Box::new(expr),
                    }
                }
            }
            "for_all" => {
                let variable = fields
                    .get("variable")
                    .and_then(|v| v.as_str().map(String::from))
                    .ok_or_else(|| de::Error::custom("for_all requires a 'variable' field"))?;
                let collection: Expression =
                    serde_json::from_value(fields.get("collection").cloned().ok_or_else(|| {
                        de::Error::custom("for_all requires a 'collection' field")
                    })?)
                    .map_err(de::Error::custom)?;
                let condition: Expression =
                    serde_json::from_value(fields.get("condition").cloned().ok_or_else(|| {
                        de::Error::custom("for_all requires a 'condition' field")
                    })?)
                    .map_err(de::Error::custom)?;
                Expression::ForAll {
                    variable,
                    collection: Box::new(collection),
                    condition: Box::new(condition),
                }
            }
            "implies" => {
                let antecedent: Expression =
                    serde_json::from_value(fields.get("antecedent").cloned().ok_or_else(|| {
                        de::Error::custom("implies requires an 'antecedent' field")
                    })?)
                    .map_err(de::Error::custom)?;
                let consequent: Expression =
                    serde_json::from_value(fields.get("consequent").cloned().ok_or_else(|| {
                        de::Error::custom("implies requires a 'consequent' field")
                    })?)
                    .map_err(de::Error::custom)?;
                Expression::Implies {
                    antecedent: Box::new(antecedent),
                    consequent: Box::new(consequent),
                }
            }
            "not" => {
                let inner: Expression = serde_json::from_value(
                    fields
                        .get("inner")
                        .cloned()
                        .ok_or_else(|| de::Error::custom("not requires an 'inner' field"))?,
                )
                .map_err(de::Error::custom)?;
                Expression::Not(Box::new(inner))
            }
            // Binary operations
            "add" | "sub" | "mul" | "div" | "eq" | "neq" | "gte" | "lte" | "gt" | "lt" | "and"
            | "or" => {
                let left: Expression =
                    serde_json::from_value(fields.get("left").cloned().ok_or_else(|| {
                        de::Error::custom(format!("{} requires a 'left' field", t))
                    })?)
                    .map_err(de::Error::custom)?;
                let right: Expression =
                    serde_json::from_value(fields.get("right").cloned().ok_or_else(|| {
                        de::Error::custom(format!("{} requires a 'right' field", t))
                    })?)
                    .map_err(de::Error::custom)?;
                match t.as_str() {
                    "add" => Expression::Add {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "sub" => Expression::Sub {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "mul" => Expression::Mul {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "div" => Expression::Div {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "eq" => Expression::Eq {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "neq" => Expression::Neq {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "gte" => Expression::Gte {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "lte" => Expression::Lte {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "gt" => Expression::Gt {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "lt" => Expression::Lt {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "and" => Expression::And {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    "or" => Expression::Or {
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    _ => unreachable!(),
                }
            }
            _ => {
                return Err(de::Error::unknown_variant(
                    &t,
                    &[
                        "literal",
                        "string",
                        "bool",
                        "storage",
                        "reserve",
                        "constant_k",
                        "total_supply",
                        "total_deposits",
                        "total_loans",
                        "locked_soroban",
                        "minted_counterpart",
                        "total_voting_power",
                        "sum_delegated_power",
                        "collateral_value",
                        "available_liquidity",
                        "protocol_fees",
                        "sum",
                        "sum_over",
                        "count_over",
                        "add",
                        "sub",
                        "mul",
                        "div",
                        "eq",
                        "neq",
                        "gte",
                        "lte",
                        "gt",
                        "lt",
                        "before",
                        "after",
                        "and",
                        "or",
                        "not",
                        "implies",
                        "for_all",
                    ],
                ))
            }
        })
    }
}

// ── Protocol Parser ─────────────────────────────────────────────────────────

/// Parses protocol manifests from YAML or JSON.
pub struct ProtocolParser;

impl ProtocolParser {
    pub fn from_yaml(yaml: &str) -> Result<ProtocolManifest, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("YAML parse error: {}", e))
    }

    pub fn from_json(json: &str) -> Result<ProtocolManifest, String> {
        serde_json::from_str(json).map_err(|e| format!("JSON parse error: {}", e))
    }

    pub fn from_file(path: &std::path::Path) -> Result<ProtocolManifest, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => Self::from_yaml(&content),
            Some("json") => Self::from_json(&content),
            _ => Self::from_yaml(&content).or_else(|_| Self::from_json(&content)),
        }
    }

    pub fn validate(manifest: &ProtocolManifest) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if manifest.contracts.is_empty() {
            errors.push("Protocol must have at least one contract".to_string());
        }
        let contract_names: HashSet<&str> =
            manifest.contracts.iter().map(|c| c.name.as_str()).collect();
        for (i, interaction) in manifest.interactions.iter().enumerate() {
            if !contract_names.contains(interaction.from_contract.as_str()) {
                errors.push(format!(
                    "Interaction {}: unknown from_contract '{}'",
                    i, interaction.from_contract
                ));
            }
            if !contract_names.contains(interaction.to_contract.as_str()) {
                errors.push(format!(
                    "Interaction {}: unknown to_contract '{}'",
                    i, interaction.to_contract
                ));
            }
        }
        for inv in manifest.invariants.iter() {
            let refs = Self::collect_contract_refs(&inv.expression);
            for r in refs {
                if !contract_names.contains(r.as_str()) {
                    errors.push(format!(
                        "Invariant '{}': unknown contract reference '{}'",
                        inv.name, r
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn collect_contract_refs(expr: &Expression) -> Vec<String> {
        let mut refs = Vec::new();
        Self::collect_refs_inner(expr, &mut refs);
        refs
    }

    fn collect_refs_inner(expr: &Expression, refs: &mut Vec<String>) {
        match expr {
            Expression::Storage { contract, .. } => refs.push((**contract).clone()),
            Expression::SumOver { contract, .. } => refs.push((**contract).clone()),
            Expression::CountOver { contract, .. } => refs.push((**contract).clone()),
            Expression::Reserve { pool, token } => {
                refs.push((**pool).clone());
                refs.push((**token).clone());
            }
            Expression::ConstantK { pool } => refs.push((**pool).clone()),
            Expression::TotalSupply { token } => refs.push((**token).clone()),
            Expression::TotalDeposits { pool } => refs.push((**pool).clone()),
            Expression::TotalLoans { pool } => refs.push((**pool).clone()),
            Expression::LockedSoroban { bridge } => refs.push((**bridge).clone()),
            Expression::MintedCounterpart { bridge } => refs.push((**bridge).clone()),
            Expression::TotalVotingPower { gov } => refs.push((**gov).clone()),
            Expression::SumDelegatedPower { gov } => refs.push((**gov).clone()),
            Expression::CollateralValue { vault } => refs.push((**vault).clone()),
            Expression::AvailableLiquidity { pool } => refs.push((**pool).clone()),
            Expression::ProtocolFees { pool } => refs.push((**pool).clone()),
            Expression::Add { left, right }
            | Expression::Sub { left, right }
            | Expression::Mul { left, right }
            | Expression::Div { left, right }
            | Expression::Eq { left, right }
            | Expression::Neq { left, right }
            | Expression::Gte { left, right }
            | Expression::Lte { left, right }
            | Expression::Gt { left, right }
            | Expression::Lt { left, right }
            | Expression::And { left, right }
            | Expression::Or { left, right } => {
                Self::collect_refs_inner(left, refs);
                Self::collect_refs_inner(right, refs);
            }
            Expression::Not(inner)
            | Expression::Before { expr: inner, .. }
            | Expression::After { expr: inner, .. } => {
                Self::collect_refs_inner(inner, refs);
            }
            Expression::Sum(items) => {
                for item in items {
                    Self::collect_refs_inner(item, refs);
                }
            }
            Expression::ForAll {
                condition,
                collection,
                ..
            } => {
                Self::collect_refs_inner(condition, refs);
                Self::collect_refs_inner(collection, refs);
            }
            Expression::Implies {
                antecedent,
                consequent,
            } => {
                Self::collect_refs_inner(antecedent, refs);
                Self::collect_refs_inner(consequent, refs);
            }
            Expression::Literal(_) | Expression::String(_) | Expression::Bool(_) => {}
        }
    }
}

// ── Convenience constructors for the DSL ────────────────────────────────────

impl Expression {
    pub fn storage(contract: &str, key: &str) -> Self {
        Expression::Storage {
            contract: Box::new(contract.to_string()),
            key: Box::new(key.to_string()),
        }
    }

    pub fn sum(items: Vec<Expression>) -> Self {
        Expression::Sum(items)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(left: Expression, right: Expression) -> Self {
        Expression::Add {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn mul(left: Expression, right: Expression) -> Self {
        Expression::Mul {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn eq(left: Expression, right: Expression) -> Self {
        Expression::Eq {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn gte(left: Expression, right: Expression) -> Self {
        Expression::Gte {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn before(operation: &str, expr: Expression) -> Self {
        Expression::Before {
            operation: Box::new(operation.to_string()),
            expr: Box::new(expr),
        }
    }

    pub fn after(operation: &str, expr: Expression) -> Self {
        Expression::After {
            operation: Box::new(operation.to_string()),
            expr: Box::new(expr),
        }
    }

    pub fn literal(val: f64) -> Self {
        Expression::Literal(val)
    }

    pub fn string(val: &str) -> Self {
        Expression::String(val.to_string())
    }

    pub fn bool(val: bool) -> Self {
        Expression::Bool(val)
    }
}

// ── Serialization helpers ───────────────────────────────────────────────────

impl ProtocolManifest {
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| format!("YAML serialization error: {}", e))
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("JSON serialization error: {}", e))
    }
}

// ── Display ─────────────────────────────────────────────────────────────────

impl std::fmt::Display for ContractRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractRole::AmmPool => write!(f, "amm_pool"),
            ContractRole::Token => write!(f, "token"),
            ContractRole::LendingPool => write!(f, "lending_pool"),
            ContractRole::Bridge => write!(f, "bridge"),
            ContractRole::Governance => write!(f, "governance"),
            ContractRole::Factory => write!(f, "factory"),
            ContractRole::Oracle => write!(f, "oracle"),
            ContractRole::FeeDistributor => write!(f, "fee_distributor"),
            ContractRole::Treasury => write!(f, "treasury"),
            ContractRole::Custom(s) => write!(f, "custom({})", s),
        }
    }
}
