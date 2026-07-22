//! Address Filtering and Management
//!
//! Provides whitelist/blacklist support for addresses, allowing users to:
//! - Whitelist trusted addresses to skip during scanning
//! - Blacklist known malicious addresses
//! - Configure address lists per project or globally
//! - Import/export address lists in multiple formats

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

/// Supported address formats on Stellar/Soroban
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddressFormat {
    /// Stellar Classic Address (G...)
    StellarClassic,
    /// Stellar Contract Address (C...)
    StellarContract,
    /// Soroban Contract Address
    SorobanContract,
    /// SHA256 Hash
    Sha256Hash,
    /// Public Key
    PublicKey,
    /// Secret Key (masked)
    SecretKey,
    /// Generic (any format)
    Generic,
}

/// Address category for classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AddressCategory {
    /// Known safe/trusted addresses
    Trusted,
    /// Known malicious addresses
    Malicious,
    /// Test/development addresses
    Test,
    /// Exchange addresses
    Exchange,
    /// Contract deployer addresses
    Deployer,
    /// Protocol treasury addresses
    Treasury,
    /// User/customer addresses
    User,
    /// Smart contract addresses
    Contract,
    /// Multi-signature wallet addresses
    MultiSig,
    /// Other/unknown category
    Other(String),
}

/// Address entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    /// The address value
    pub address: String,
    /// Address format type
    pub format: AddressFormat,
    /// Address category
    pub category: AddressCategory,
    /// Description of the address
    pub description: String,
    /// Source of this entry (e.g., "manual", "contract_scan", "import")
    pub source: String,
    /// Tags for custom classification
    pub tags: Vec<String>,
    /// When this entry was added
    pub added_at: DateTime<Utc>,
    /// Optional expiration date
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this entry is active
    pub active: bool,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
}

impl AddressEntry {
    /// Create a new address entry
    pub fn new(
        address: String,
        format: AddressFormat,
        category: AddressCategory,
        description: String,
    ) -> Self {
        Self {
            address,
            format,
            category,
            description,
            source: "manual".to_string(),
            tags: Vec::new(),
            added_at: Utc::now(),
            expires_at: None,
            active: true,
            metadata: HashMap::new(),
        }
    }

    /// Check if this entry is currently valid (not expired and active)
    pub fn is_valid(&self) -> bool {
        self.active && self.expires_at.map_or(true, |exp| exp > Utc::now())
    }

    /// Set expiration date
    pub fn set_expiration(&mut self, expires_at: DateTime<Utc>) {
        self.expires_at = Some(expires_at);
    }

    /// Add a tag to this entry
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Remove a tag from this entry
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }

    /// Update metadata
    pub fn update_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Configuration for a threat intelligence feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeedConfig {
    /// Unique name for this feed
    pub name: String,
    /// Feed type identifier (e.g., "stellar_expert", "stellar_guard")
    pub feed_type: String,
    /// Whether this feed is enabled
    pub enabled: bool,
    /// API endpoint URL for the feed
    pub endpoint_url: String,
    /// Optional API key for authenticated feeds
    pub api_key: Option<String>,
    /// Refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Whether to include trusted addresses from this feed
    pub include_trusted: bool,
    /// Whether to include malicious addresses from this feed
    pub include_malicious: bool,
    /// Maximum number of entries to fetch per refresh
    pub max_entries_per_fetch: usize,
    /// Custom headers for the feed request
    pub custom_headers: HashMap<String, String>,
}

impl Default for ThreatIntelFeedConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            feed_type: "stellar_expert".to_string(),
            enabled: false,
            endpoint_url: String::new(),
            api_key: None,
            refresh_interval_secs: 3600,
            include_trusted: false,
            include_malicious: true,
            max_entries_per_fetch: 5000,
            custom_headers: HashMap::new(),
        }
    }
}

/// Threat intelligence feed trait for fetching external address data
pub trait ThreatIntelFeed: Send + Sync {
    /// Get the unique name of this feed
    fn name(&self) -> &str;

    /// Get the feed type identifier
    fn feed_type(&self) -> &str;

    /// Fetch known malicious addresses from the feed
    fn fetch_malicious_addresses(&self, max_entries: usize) -> Result<Vec<AddressEntry>>;

    /// Fetch known trusted addresses from the feed
    fn fetch_trusted_addresses(&self, max_entries: usize) -> Result<Vec<AddressEntry>>;

    /// Check if the feed is reachable and healthy
    fn health_check(&self) -> Result<bool>;

    /// Get the last refresh timestamp
    fn last_refreshed(&self) -> Option<DateTime<Utc>>;

    /// Get the number of addresses fetched in the last refresh
    fn last_fetch_count(&self) -> usize;
}

/// StellarExpert threat intelligence feed
///
/// Integrates with StellarExpert's API to fetch known malicious addresses
/// from their public directory of flagged accounts.
pub struct StellarExpertFeed {
    config: ThreatIntelFeedConfig,
    client: reqwest::blocking::Client,
    last_refreshed: std::sync::Mutex<Option<DateTime<Utc>>>,
    last_fetch_count: std::sync::Mutex<usize>,
}

impl StellarExpertFeed {
    /// Create a new StellarExpert feed with the given configuration
    pub fn new(config: ThreatIntelFeedConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("SorobanSecurityScanner/1.0")
            .build()?;

        Ok(Self {
            config,
            client,
            last_refreshed: std::sync::Mutex::new(None),
            last_fetch_count: std::sync::Mutex::new(0),
        })
    }
}

impl ThreatIntelFeed for StellarExpertFeed {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn feed_type(&self) -> &str {
        &self.config.feed_type
    }

    fn fetch_malicious_addresses(&self, max_entries: usize) -> Result<Vec<AddressEntry>> {
        let url = format!(
            "{}/api/directory?tag=malicious&limit={}",
            self.config.endpoint_url.trim_end_matches('/'),
            max_entries.min(self.config.max_entries_per_fetch)
        );

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        for (key, value) in &self.config.custom_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request
            .send()
            .map_err(|e| anyhow!("StellarExpert API request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "StellarExpert API returned status: {}",
                response.status()
            ));
        }

        #[derive(Deserialize)]
        struct StellarExpertEntry {
            address: String,
            tag: Option<String>,
            name: Option<String>,
            #[serde(default)]
            domain: Option<String>,
        }

        #[derive(Deserialize)]
        struct StellarExpertResponse {
            #[serde(rename = "_embedded")]
            embedded: Option<StellarExpertEmbedded>,
        }

        #[derive(Deserialize)]
        struct StellarExpertEmbedded {
            records: Vec<StellarExpertEntry>,
        }

        let parsed: StellarExpertResponse = response.json().map_err(|e| {
            anyhow!("Failed to parse StellarExpert response: {}", e)
        })?;

        let records = parsed.embedded.map(|e| e.records).unwrap_or_default();

        let entries: Vec<AddressEntry> = records
            .into_iter()
            .map(|r| {
                let mut entry = AddressEntry::new(
                    r.address,
                    AddressFormat::StellarClassic,
                    AddressCategory::Malicious,
                    format!(
                        "StellarExpert flagged: {}",
                        r.tag.unwrap_or_else(|| "malicious".to_string())
                    ),
                );
                entry.source = format!("stellar_expert:{}", r.domain.unwrap_or_default());
                if let Some(tag) = r.tag {
                    entry.add_tag(tag);
                }
                entry
            })
            .collect();

        let count = entries.len();
        if let Ok(mut lfc) = self.last_fetch_count.lock() {
            *lfc = count;
        }
        if let Ok(mut lr) = self.last_refreshed.lock() {
            *lr = Some(Utc::now());
        }

        Ok(entries)
    }

    fn fetch_trusted_addresses(&self, max_entries: usize) -> Result<Vec<AddressEntry>> {
        let url = format!(
            "{}/api/directory?tag=trusted&limit={}",
            self.config.endpoint_url.trim_end_matches('/'),
            max_entries.min(self.config.max_entries_per_fetch)
        );

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        for (key, value) in &self.config.custom_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request
            .send()
            .map_err(|e| anyhow!("StellarExpert API request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "StellarExpert API returned status: {}",
                response.status()
            ));
        }

        #[derive(Deserialize)]
        struct StellarExpertEntry {
            address: String,
            tag: Option<String>,
            name: Option<String>,
            #[serde(default)]
            domain: Option<String>,
        }

        #[derive(Deserialize)]
        struct StellarExpertResponse {
            #[serde(rename = "_embedded")]
            embedded: Option<StellarExpertEmbedded>,
        }

        #[derive(Deserialize)]
        struct StellarExpertEmbedded {
            records: Vec<StellarExpertEntry>,
        }

        let parsed: StellarExpertResponse = response.json().map_err(|e| {
            anyhow!("Failed to parse StellarExpert response: {}", e)
        })?;

        let records = parsed.embedded.map(|e| e.records).unwrap_or_default();

        let entries: Vec<AddressEntry> = records
            .into_iter()
            .map(|r| {
                let mut entry = AddressEntry::new(
                    r.address,
                    AddressFormat::StellarClassic,
                    AddressCategory::Trusted,
                    format!(
                        "StellarExpert verified: {}",
                        r.tag.unwrap_or_else(|| "trusted".to_string())
                    ),
                );
                entry.source = format!("stellar_expert:{}", r.domain.unwrap_or_default());
                if let Some(tag) = r.tag {
                    entry.add_tag(tag);
                }
                entry
            })
            .collect();

        Ok(entries)
    }

    fn health_check(&self) -> Result<bool> {
        let url = format!("{}/api/", self.config.endpoint_url.trim_end_matches('/'));
        let response = self.client.get(&url).send()?;
        Ok(response.status().is_success())
    }

    fn last_refreshed(&self) -> Option<DateTime<Utc>> {
        self.last_refreshed.lock().ok().and_then(|lr| *lr)
    }

    fn last_fetch_count(&self) -> usize {
        self.last_fetch_count.lock().ok().map(|lfc| *lfc).unwrap_or(0)
    }
}

/// StellarGuard threat intelligence feed
///
/// Integrates with StellarGuard's known malicious address list
/// to import community-maintained threat data.
pub struct StellarGuardFeed {
    config: ThreatIntelFeedConfig,
    client: reqwest::blocking::Client,
    last_refreshed: std::sync::Mutex<Option<DateTime<Utc>>>,
    last_fetch_count: std::sync::Mutex<usize>,
}

impl StellarGuardFeed {
    /// Create a new StellarGuard feed with the given configuration
    pub fn new(config: ThreatIntelFeedConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("SorobanSecurityScanner/1.0")
            .build()?;

        Ok(Self {
            config,
            client,
            last_refreshed: std::sync::Mutex::new(None),
            last_fetch_count: std::sync::Mutex::new(0),
        })
    }
}

impl ThreatIntelFeed for StellarGuardFeed {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn feed_type(&self) -> &str {
        &self.config.feed_type
    }

    fn fetch_malicious_addresses(&self, max_entries: usize) -> Result<Vec<AddressEntry>> {
        let url = format!(
            "{}/malicious-addresses?limit={}",
            self.config.endpoint_url.trim_end_matches('/'),
            max_entries.min(self.config.max_entries_per_fetch)
        );

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("X-API-Key", api_key.as_str());
        }

        for (key, value) in &self.config.custom_headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request
            .send()
            .map_err(|e| anyhow!("StellarGuard API request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "StellarGuard API returned status: {}",
                response.status()
            ));
        }

        #[derive(Deserialize)]
        struct StellarGuardEntry {
            address: String,
            reason: Option<String>,
            #[serde(default)]
            reported_at: Option<String>,
        }

        #[derive(Deserialize)]
        struct StellarGuardResponse {
            addresses: Vec<StellarGuardEntry>,
        }

        let parsed: StellarGuardResponse = response.json().map_err(|e| {
            anyhow!("Failed to parse StellarGuard response: {}", e)
        })?;

        let entries: Vec<AddressEntry> = parsed
            .addresses
            .into_iter()
            .map(|r| {
                let mut entry = AddressEntry::new(
                    r.address,
                    AddressFormat::StellarClassic,
                    AddressCategory::Malicious,
                    format!(
                        "StellarGuard: {}",
                        r.reason.unwrap_or_else(|| "Community reported".to_string())
                    ),
                );
                entry.source = "stellar_guard".to_string();
                entry.add_tag("community_reported".to_string());
                entry
            })
            .collect();

        let count = entries.len();
        if let Ok(mut lfc) = self.last_fetch_count.lock() {
            *lfc = count;
        }
        if let Ok(mut lr) = self.last_refreshed.lock() {
            *lr = Some(Utc::now());
        }

        Ok(entries)
    }

    fn fetch_trusted_addresses(&self, _max_entries: usize) -> Result<Vec<AddressEntry>> {
        // StellarGuard primarily tracks malicious addresses, not trusted ones
        Ok(Vec::new())
    }

    fn health_check(&self) -> Result<bool> {
        let url = format!(
            "{}/health",
            self.config.endpoint_url.trim_end_matches('/')
        );
        match self.client.get(&url).send() {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    fn last_refreshed(&self) -> Option<DateTime<Utc>> {
        self.last_refreshed.lock().ok().and_then(|lr| *lr)
    }

    fn last_fetch_count(&self) -> usize {
        self.last_fetch_count.lock().ok().map(|lfc| *lfc).unwrap_or(0)
    }
}

/// Status information for a threat intelligence feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeedStatus {
    /// Feed name
    pub name: String,
    /// Feed type
    pub feed_type: String,
    /// Whether the feed is enabled
    pub enabled: bool,
    /// Whether the feed is currently healthy
    pub is_healthy: bool,
    /// When the feed was last refreshed
    pub last_refreshed: Option<DateTime<Utc>>,
    /// Number of entries fetched in the last refresh
    pub last_fetch_count: usize,
    /// Number of malicious addresses currently in the filter from this feed
    pub malicious_count: usize,
    /// Number of trusted addresses currently in the filter from this feed
    pub trusted_count: usize,
}

/// Address filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressFilterConfig {
    /// Whether to enable address filtering
    pub enabled: bool,
    /// Whitelist of addresses to always allow
    pub whitelist_paths: Vec<PathBuf>,
    /// Blacklist of addresses to always block
    pub blacklist_paths: Vec<PathBuf>,
    /// Default action for addresses not in lists
    pub default_action: FilterAction,
    /// Whether to log filtered addresses
    pub log_filtered: bool,
    /// Whether to validate Stellar addresses
    pub validate_stellar_addresses: bool,
    /// Categories to whitelist automatically
    pub auto_whitelist_categories: Vec<AddressCategory>,
    /// Categories to blacklist automatically
    pub auto_blacklist_categories: Vec<AddressCategory>,
    /// Threat intelligence feed configurations
    pub threat_intel_feeds: Vec<ThreatIntelFeedConfig>,
    /// Whether to enable automatic background refresh of threat intel feeds
    pub auto_refresh_feeds: bool,
    /// Interval in seconds between automatic feed refreshes (default: 3600)
    pub auto_refresh_interval_secs: u64,
}

impl Default for AddressFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            whitelist_paths: vec![],
            blacklist_paths: vec![],
            default_action: FilterAction::Skip,
            log_filtered: true,
            validate_stellar_addresses: true,
            auto_whitelist_categories: vec![AddressCategory::Test],
            auto_blacklist_categories: vec![AddressCategory::Malicious],
            threat_intel_feeds: vec![],
            auto_refresh_feeds: false,
            auto_refresh_interval_secs: 3600,
        }
    }
}

/// Action to take when an address matches a filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterAction {
    /// Allow/skip scanning this address
    Allow,
    /// Block/flag this address
    Block,
    /// Skip this address entirely
    Skip,
    /// Require manual review
    Review,
}

/// Result of address filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterResult {
    /// The address that was checked
    pub address: String,
    /// The action taken
    pub action: FilterAction,
    /// The list type that matched (whitelist/blacklist)
    pub list_type: ListType,
    /// The matching entry (if any)
    pub matching_entry: Option<AddressEntry>,
    /// Timestamp of the check
    pub checked_at: DateTime<Utc>,
}

/// Type of list that matched
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ListType {
    /// Matched whitelist
    Whitelist,
    /// Matched blacklist
    Blacklist,
    /// No match found
    None,
}

/// Main address filter manager
pub struct AddressFilter {
    /// Whitelisted addresses
    whitelist: HashSet<String>,
    /// Blacklisted addresses
    blacklist: HashSet<String>,
    /// Full address entries with metadata
    entries: HashMap<String, AddressEntry>,
    /// Filter configuration
    config: AddressFilterConfig,
    /// Address patterns for regex matching
    patterns: Vec<(Regex, FilterAction)>,
    /// Active threat intelligence feeds
    feeds: Vec<Box<dyn ThreatIntelFeed>>,
    /// Track feed source counts for deduplication
    feed_entry_counts: HashMap<String, usize>,
}

impl AddressFilter {
    /// Create a new address filter with default config
    pub fn new() -> Self {
        Self {
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
            entries: HashMap::new(),
            config: AddressFilterConfig::default(),
            patterns: Vec::new(),
            feeds: Vec::new(),
            feed_entry_counts: HashMap::new(),
        }
    }

    /// Create a new address filter with custom config
    pub fn with_config(config: AddressFilterConfig) -> Self {
        Self {
            whitelist: HashSet::new(),
            blacklist: HashSet::new(),
            entries: HashMap::new(),
            config,
            patterns: Vec::new(),
            feeds: Vec::new(),
            feed_entry_counts: HashMap::new(),
        }
    }

    /// Add an address to the whitelist
    pub fn add_to_whitelist(&mut self, entry: AddressEntry) -> Result<()> {
        if !entry.is_valid() {
            return Err(anyhow!("Cannot add expired address to whitelist"));
        }
        self.whitelist.insert(entry.address.clone());
        self.entries.insert(entry.address.clone(), entry);
        Ok(())
    }

    /// Add an address to the blacklist
    pub fn add_to_blacklist(&mut self, entry: AddressEntry) -> Result<()> {
        if !entry.is_valid() {
            return Err(anyhow!("Cannot add expired address to blacklist"));
        }
        self.blacklist.insert(entry.address.clone());
        self.entries.insert(entry.address.clone(), entry);
        Ok(())
    }

    /// Remove an address from all lists
    pub fn remove_address(&mut self, address: &str) -> bool {
        let removed = self.whitelist.remove(address) | self.blacklist.remove(address);
        if removed {
            self.entries.remove(address);
        }
        removed
    }

    /// Check if an address is whitelisted
    pub fn is_whitelisted(&self, address: &str) -> bool {
        self.whitelist.contains(address)
    }

    /// Check if an address is blacklisted
    pub fn is_blacklisted(&self, address: &str) -> bool {
        self.blacklist.contains(address)
    }

    /// Get address entry by address
    pub fn get_entry(&self, address: &str) -> Option<&AddressEntry> {
        self.entries.get(address)
    }

    /// Add a regex pattern for address matching
    pub fn add_pattern(&mut self, pattern: &str, action: FilterAction) -> Result<()> {
        let regex = Regex::new(pattern)?;
        self.patterns.push((regex, action));
        Ok(())
    }

    /// Filter a single address
    pub fn filter_address(&self, address: &str) -> FilterResult {
        // Check blacklist first (higher priority)
        if self.blacklist.contains(address) {
            return FilterResult {
                address: address.to_string(),
                action: FilterAction::Block,
                list_type: ListType::Blacklist,
                matching_entry: self.entries.get(address).cloned(),
                checked_at: Utc::now(),
            };
        }

        // Check whitelist
        if self.whitelist.contains(address) {
            return FilterResult {
                address: address.to_string(),
                action: FilterAction::Allow,
                list_type: ListType::Whitelist,
                matching_entry: self.entries.get(address).cloned(),
                checked_at: Utc::now(),
            };
        }

        // Check regex patterns
        for (pattern, action) in &self.patterns {
            if pattern.is_match(address) {
                return FilterResult {
                    address: address.to_string(),
                    action: action.clone(),
                    list_type: ListType::None,
                    matching_entry: None,
                    checked_at: Utc::now(),
                };
            }
        }

        // Default action
        FilterResult {
            address: address.to_string(),
            action: self.config.default_action.clone(),
            list_type: ListType::None,
            matching_entry: None,
            checked_at: Utc::now(),
        }
    }

    /// Filter multiple addresses
    pub fn filter_addresses(&self, addresses: &[String]) -> Vec<FilterResult> {
        addresses
            .iter()
            .map(|addr| self.filter_address(addr))
            .collect()
    }

    /// Validate a Stellar address format
    pub fn validate_stellar_address(&self, address: &str) -> bool {
        if !self.config.validate_stellar_addresses {
            return true;
        }

        // Stellar addresses start with 'G' and are 56 chars
        let re = Regex::new(r"^G[0-9A-Z]{55}$").unwrap();
        re.is_match(address)
    }

    /// Validate a Stellar contract address format
    pub fn validate_contract_address(&self, address: &str) -> bool {
        // Contract addresses start with 'C'
        let re = Regex::new(r"^C[0-9A-Z]{55}$").unwrap();
        re.is_match(address)
    }

    /// Load addresses from a file
    pub fn load_from_file(&self, path: &PathBuf) -> Result<Vec<AddressEntry>> {
        let content = fs::read_to_string(path)?;

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let entries: Vec<AddressEntry> = serde_json::from_str(&content)?;
            Ok(entries)
        } else {
            // Assume CSV format
            let mut entries = Vec::new();
            for line in content.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    let address = parts[0].trim().to_string();
                    let format = match parts[1].trim() {
                        "stellar" => AddressFormat::StellarClassic,
                        "contract" => AddressFormat::StellarContract,
                        "soroban" => AddressFormat::SorobanContract,
                        "hash" => AddressFormat::Sha256Hash,
                        "pubkey" => AddressFormat::PublicKey,
                        "secret" => AddressFormat::SecretKey,
                        _ => AddressFormat::Generic,
                    };
                    let category = match parts[2].trim() {
                        "trusted" => AddressCategory::Trusted,
                        "malicious" => AddressCategory::Malicious,
                        "test" => AddressCategory::Test,
                        "exchange" => AddressCategory::Exchange,
                        "deployer" => AddressCategory::Deployer,
                        "treasury" => AddressCategory::Treasury,
                        "user" => AddressCategory::User,
                        "contract" => AddressCategory::Contract,
                        "multisig" => AddressCategory::MultiSig,
                        other => AddressCategory::Other(other.to_string()),
                    };
                    let description = if parts.len() > 3 {
                        parts[3].trim().to_string()
                    } else {
                        String::new()
                    };

                    entries.push(AddressEntry::new(address, format, category, description));
                }
            }
            Ok(entries)
        }
    }

    /// Load addresses from multiple files
    pub fn load_from_files(&mut self, paths: &[PathBuf]) -> Result<()> {
        for path in paths {
            let entries = self.load_from_file(path)?;
            for entry in entries {
                if entry.active {
                    match entry.category {
                        AddressCategory::Malicious => {
                            self.add_to_blacklist(entry)?;
                        }
                        _ => {
                            self.add_to_whitelist(entry)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Export addresses to a JSON file
    pub fn export_to_json(&self, path: &PathBuf) -> Result<()> {
        let entries: Vec<&AddressEntry> = self.entries.values().collect();
        let json = serde_json::to_string_pretty(&entries)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Export addresses to a CSV file
    pub fn export_to_csv(&self, path: &PathBuf) -> Result<()> {
        let mut csv = String::new();
        csv.push_str(
            "address,format,category,description,source,tags,added_at,expires_at,active\n",
        );

        for entry in self.entries.values() {
            let format_str = match entry.format {
                AddressFormat::StellarClassic => "stellar",
                AddressFormat::StellarContract => "contract",
                AddressFormat::SorobanContract => "soroban",
                AddressFormat::Sha256Hash => "hash",
                AddressFormat::PublicKey => "pubkey",
                AddressFormat::SecretKey => "secret",
                AddressFormat::Generic => "generic",
            };

            let category_str = match &entry.category {
                AddressCategory::Trusted => "trusted",
                AddressCategory::Malicious => "malicious",
                AddressCategory::Test => "test",
                AddressCategory::Exchange => "exchange",
                AddressCategory::Deployer => "deployer",
                AddressCategory::Treasury => "treasury",
                AddressCategory::User => "user",
                AddressCategory::Contract => "contract",
                AddressCategory::MultiSig => "multisig",
                AddressCategory::Other(s) => s,
            };

            let tags_str = entry.tags.join(";");
            let expires_str = entry
                .expires_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();

            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                entry.address,
                format_str,
                category_str,
                entry.description.replace(',', ";"),
                entry.source,
                tags_str,
                entry.added_at.to_rfc3339(),
                expires_str,
                entry.active
            ));
        }

        fs::write(path, csv)?;
        Ok(())
    }

    /// Add a threat intelligence feed to the filter
    pub fn add_feed(&mut self, feed: Box<dyn ThreatIntelFeed>) {
        self.feeds.push(feed);
    }

    /// Get the number of registered threat intelligence feeds
    pub fn feed_count(&self) -> usize {
        self.feeds.len()
    }

    /// Refresh addresses from all configured threat intelligence feeds
    ///
    /// This method fetches malicious and trusted addresses from each enabled feed,
    /// deduplicates entries, and adds them to the appropriate lists.
    pub fn refresh_from_feeds(&mut self) -> Result<ThreatIntelRefreshSummary> {
        let mut summary = ThreatIntelRefreshSummary {
            feeds_contacted: 0,
            feeds_failed: 0,
            total_malicious_fetched: 0,
            total_trusted_fetched: 0,
            new_malicious_added: 0,
            new_trusted_added: 0,
            duplicates_skipped: 0,
            errors: Vec::new(),
        };

        let feed_count = self.feeds.len();
        summary.feeds_contacted = feed_count;

        // Collect all new entries from feeds
        let mut all_malicious: Vec<AddressEntry> = Vec::new();
        let mut all_trusted: Vec<AddressEntry> = Vec::new();

        for feed in &self.feeds {
            // Resolve feed config for this feed
            let feed_config = self.config.threat_intel_feeds
                .iter()
                .find(|fc| fc.name == feed.name())
                .cloned();
            let max_entries = feed_config.as_ref()
                .map(|fc| fc.max_entries_per_fetch)
                .unwrap_or(5000);
            let include_malicious = feed_config.as_ref()
                .map(|fc| fc.include_malicious)
                .unwrap_or(true);
            let include_trusted = feed_config.as_ref()
                .map(|fc| fc.include_trusted)
                .unwrap_or(false);

            let mut feed_failed = false;

            // Refresh malicious addresses if enabled
            if include_malicious {
                match feed.fetch_malicious_addresses(max_entries) {
                    Ok(entries) => {
                        summary.total_malicious_fetched += entries.len();
                        all_malicious.extend(entries);
                    }
                    Err(e) => {
                        feed_failed = true;
                        summary.errors.push(format!(
                            "Feed '{}' failed to fetch malicious addresses: {}",
                            feed.name(),
                            e
                        ));
                    }
                }
            }

            // Refresh trusted addresses if enabled
            if include_trusted {
                match feed.fetch_trusted_addresses(max_entries) {
                    Ok(entries) => {
                        summary.total_trusted_fetched += entries.len();
                        all_trusted.extend(entries);
                    }
                    Err(e) => {
                        feed_failed = true;
                        summary.errors.push(format!(
                            "Feed '{}' failed to fetch trusted addresses: {}",
                            feed.name(),
                            e
                        ));
                    }
                }
            }

            if feed_failed {
                summary.feeds_failed += 1;
            }
        }

        // Deduplicate and add malicious addresses
        for entry in all_malicious {
            if self.blacklist.contains(&entry.address) {
                summary.duplicates_skipped += 1;
                continue;
            }
            if self.whitelist.contains(&entry.address) {
                // Don't override whitelist entries
                summary.duplicates_skipped += 1;
                continue;
            }
            self.blacklist.insert(entry.address.clone());
            self.entries.insert(entry.address.clone(), entry);
            summary.new_malicious_added += 1;
        }

        // Deduplicate and add trusted addresses
        for entry in all_trusted {
            if self.whitelist.contains(&entry.address) {
                summary.duplicates_skipped += 1;
                continue;
            }
            if self.blacklist.contains(&entry.address) {
                // Don't override blacklist entries
                summary.duplicates_skipped += 1;
                continue;
            }
            self.whitelist.insert(entry.address.clone());
            self.entries.insert(entry.address.clone(), entry);
            summary.new_trusted_added += 1;
        }

        // Update feed entry counts
        for feed in &self.feeds {
            let feed_name = feed.name().to_string();
            if feed_name.is_empty() {
                continue;
            }
            let count = self.entries.values()
                .filter(|e| e.source.starts_with(&feed_name))
                .count();
            self.feed_entry_counts.insert(feed_name, count);
        }

        Ok(summary)
    }

    /// Get status for all threat intelligence feeds
    pub fn get_all_feed_statuses(&self) -> Vec<ThreatIntelFeedStatus> {
        self.feeds
            .iter()
            .map(|feed| {
                let feed_name = feed.name().to_string();
                if feed_name.is_empty() {
                    return ThreatIntelFeedStatus {
                        name: String::new(),
                        feed_type: feed.feed_type().to_string(),
                        enabled: true,
                        is_healthy: false,
                        last_refreshed: None,
                        last_fetch_count: 0,
                        malicious_count: 0,
                        trusted_count: 0,
                    };
                }
                let source_prefix = format!("{}:", feed_name);

                let malicious_count = self
                    .entries
                    .values()
                    .filter(|e| {
                        e.source.starts_with(&source_prefix)
                            && e.category == AddressCategory::Malicious
                    })
                    .count();

                let trusted_count = self
                    .entries
                    .values()
                    .filter(|e| {
                        e.source.starts_with(&source_prefix)
                            && e.category == AddressCategory::Trusted
                    })
                    .count();

                let is_healthy = feed.health_check().unwrap_or(false);

                ThreatIntelFeedStatus {
                    name: feed_name,
                    feed_type: feed.feed_type().to_string(),
                    enabled: true,
                    is_healthy,
                    last_refreshed: feed.last_refreshed(),
                    last_fetch_count: feed.last_fetch_count(),
                    malicious_count,
                    trusted_count,
                }
            })
            .collect()
    }

    /// Start a background refresh loop for threat intelligence feeds
    ///
    /// Spawns a background thread that periodically refreshes addresses
    /// from all configured feeds at the configured interval.
    ///
    /// **Note:** This is a placeholder implementation. The background thread
    /// sleeps but does not perform actual refreshes because `AddressFilter`
    /// is not `Send` + `Sync`. For production use, wrap `AddressFilter` in
    /// `Arc<Mutex<AddressFilter>>` and pass it to the thread.
    #[allow(dead_code)]
    pub fn start_background_refresh(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();

        if !self.config.auto_refresh_feeds || self.feeds.is_empty() {
            return running;
        }

        let interval = self.config.auto_refresh_interval_secs;

        std::thread::spawn(move || {
            while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        });

        running
    }
    /// Get the number of entries contributed by each feed
    pub fn get_feed_entry_counts(&self) -> &HashMap<String, usize> {
        &self.feed_entry_counts
    }

    /// Get statistics about the address filter
    pub fn get_stats(&self) -> AddressFilterStats {
        let feed_sourced = self.entries.values()
            .filter(|e| {
                e.source.starts_with("stellar_expert") || e.source.starts_with("stellar_guard")
            })
            .count();

        AddressFilterStats {
            total_entries: self.entries.len(),
            whitelisted_count: self.whitelist.len(),
            blacklisted_count: self.blacklist.len(),
            active_count: self.entries.values().filter(|e| e.is_valid()).count(),
            expired_count: self.entries.values().filter(|e| !e.is_valid()).count(),
            patterns_count: self.patterns.len(),
            feed_count: self.feeds.len(),
            feed_sourced_entries: feed_sourced,
        }
    }

    /// Update address filter configuration
    pub fn update_config(&mut self, config: AddressFilterConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &AddressFilterConfig {
        &self.config
    }

    /// List all addresses with their categories
    pub fn list_addresses(&self) -> Vec<&AddressEntry> {
        self.entries.values().collect()
    }

    /// List addresses by category
    pub fn list_addresses_by_category(&self, category: &AddressCategory) -> Vec<&AddressEntry> {
        self.entries
            .values()
            .filter(|e| &e.category == category)
            .collect()
    }

    /// Check if any address filter is configured
    pub fn has_filters(&self) -> bool {
        !self.whitelist.is_empty() || !self.blacklist.is_empty() || !self.patterns.is_empty()
    }
}

/// Summary of a threat intelligence feed refresh operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRefreshSummary {
    /// Number of feeds contacted
    pub feeds_contacted: usize,
    /// Number of feeds that failed
    pub feeds_failed: usize,
    /// Total malicious addresses fetched
    pub total_malicious_fetched: usize,
    /// Total trusted addresses fetched
    pub total_trusted_fetched: usize,
    /// New malicious addresses added to blacklist
    pub new_malicious_added: usize,
    /// New trusted addresses added to whitelist
    pub new_trusted_added: usize,
    /// Duplicate entries skipped during deduplication
    pub duplicates_skipped: usize,
    /// Errors encountered during refresh
    pub errors: Vec<String>,
}

/// Statistics about the address filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressFilterStats {
    /// Total number of address entries
    pub total_entries: usize,
    /// Number of whitelisted addresses
    pub whitelisted_count: usize,
    /// Number of blacklisted addresses
    pub blacklisted_count: usize,
    /// Number of active (non-expired) addresses
    pub active_count: usize,
    /// Number of expired addresses
    pub expired_count: usize,
    /// Number of regex patterns
    pub patterns_count: usize,
    /// Number of configured threat intelligence feeds
    pub feed_count: usize,
    /// Number of entries sourced from threat intel feeds
    pub feed_sourced_entries: usize,
}

impl Default for AddressFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(address: &str, category: AddressCategory) -> AddressEntry {
        AddressEntry::new(
            address.to_string(),
            AddressFormat::StellarClassic,
            category,
            "Test entry".to_string(),
        )
    }

    #[test]
    fn test_whitelist_address() {
        let mut filter = AddressFilter::new();
        let entry = create_test_entry("GABC123", AddressCategory::Trusted);

        assert!(filter.add_to_whitelist(entry).is_ok());
        assert!(filter.is_whitelisted("GABC123"));
        assert!(!filter.is_blacklisted("GABC123"));
    }

    #[test]
    fn test_blacklist_address() {
        let mut filter = AddressFilter::new();
        let entry = create_test_entry("GMALICIOUS", AddressCategory::Malicious);

        assert!(filter.add_to_blacklist(entry).is_ok());
        assert!(filter.is_blacklisted("GMALICIOUS"));
        assert!(!filter.is_whitelisted("GMALICIOUS"));
    }

    #[test]
    fn test_filter_address_whitelisted() {
        let mut filter = AddressFilter::new();
        let entry = create_test_entry("GWHITELIST", AddressCategory::Trusted);
        filter.add_to_whitelist(entry).unwrap();

        let result = filter.filter_address("GWHITELIST");
        assert_eq!(result.action, FilterAction::Allow);
        assert_eq!(result.list_type, ListType::Whitelist);
    }

    #[test]
    fn test_filter_address_blacklisted() {
        let mut filter = AddressFilter::new();
        let entry = create_test_entry("GBLACKLIST", AddressCategory::Malicious);
        filter.add_to_blacklist(entry).unwrap();

        let result = filter.filter_address("GBLACKLIST");
        assert_eq!(result.action, FilterAction::Block);
        assert_eq!(result.list_type, ListType::Blacklist);
    }

    #[test]
    fn test_filter_address_default() {
        let filter = AddressFilter::new();
        let result = filter.filter_address("GUNKNOWN");
        assert_eq!(result.action, FilterAction::Skip);
        assert_eq!(result.list_type, ListType::None);
    }

    #[test]
    fn test_remove_address() {
        let mut filter = AddressFilter::new();
        let entry = create_test_entry("GREMOVE", AddressCategory::Trusted);
        filter.add_to_whitelist(entry).unwrap();

        assert!(filter.is_whitelisted("GREMOVE"));
        assert!(filter.remove_address("GREMOVE"));
        assert!(!filter.is_whitelisted("GREMOVE"));
        assert!(filter.get_entry("GREMOVE").is_none());
    }

    #[test]
    fn test_address_stats() {
        let mut filter = AddressFilter::new();
        filter
            .add_to_whitelist(create_test_entry("G1", AddressCategory::Trusted))
            .unwrap();
        filter
            .add_to_whitelist(create_test_entry("G2", AddressCategory::Trusted))
            .unwrap();
        filter
            .add_to_blacklist(create_test_entry("G3", AddressCategory::Malicious))
            .unwrap();

        let stats = filter.get_stats();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.whitelisted_count, 2);
        assert_eq!(stats.blacklisted_count, 1);
        assert_eq!(stats.feed_count, 0);
        assert_eq!(stats.feed_sourced_entries, 0);
    }

    #[test]
    fn test_address_pattern_matching() {
        let mut filter = AddressFilter::new();
        filter.add_pattern(r"^MALICIOUS", FilterAction::Block).unwrap();

        let result = filter.filter_address("MALICIOUS_ADDR");
        assert_eq!(result.action, FilterAction::Block);
        assert_eq!(result.list_type, ListType::None);
    }

    // ── Threat Intelligence Feed Tests ─────────────────────────────────────────

    /// A mock feed implementation for unit testing without network calls
    struct MockThreatIntelFeed {
        name: String,
        malicious_addresses: Vec<AddressEntry>,
        trusted_addresses: Vec<AddressEntry>,
        is_healthy: bool,
        last_refreshed: std::sync::Mutex<Option<DateTime<Utc>>>,
        last_fetch_count: std::sync::Mutex<usize>,
    }

    impl MockThreatIntelFeed {
        fn new(name: &str, malicious: Vec<AddressEntry>, trusted: Vec<AddressEntry>) -> Self {
            Self {
                name: name.to_string(),
                malicious_addresses: malicious,
                trusted_addresses: trusted,
                is_healthy: true,
                last_refreshed: std::sync::Mutex::new(None),
                last_fetch_count: std::sync::Mutex::new(0),
            }
        }
    }

    impl ThreatIntelFeed for MockThreatIntelFeed {
        fn name(&self) -> &str {
            &self.name
        }

        fn feed_type(&self) -> &str {
            "mock"
        }

        fn fetch_malicious_addresses(&self, _max_entries: usize) -> Result<Vec<AddressEntry>> {
            let count = self.malicious_addresses.len();
            if let Ok(mut lfc) = self.last_fetch_count.lock() {
                *lfc = count;
            }
            if let Ok(mut lr) = self.last_refreshed.lock() {
                *lr = Some(Utc::now());
            }
            Ok(self.malicious_addresses.clone())
        }

        fn fetch_trusted_addresses(&self, _max_entries: usize) -> Result<Vec<AddressEntry>> {
            Ok(self.trusted_addresses.clone())
        }

        fn health_check(&self) -> Result<bool> {
            Ok(self.is_healthy)
        }

        fn last_refreshed(&self) -> Option<DateTime<Utc>> {
            self.last_refreshed.lock().ok().and_then(|lr| *lr)
        }

        fn last_fetch_count(&self) -> usize {
            self.last_fetch_count.lock().ok().map(|lfc| *lfc).unwrap_or(0)
        }
    }

    #[test]
    fn test_add_feed_to_filter() {
        let mut filter = AddressFilter::new();
        assert_eq!(filter.feed_count(), 0);

        let mock_feed = Box::new(MockThreatIntelFeed::new(
            "test_feed",
            vec![],
            vec![],
        ));
        filter.add_feed(mock_feed);
        assert_eq!(filter.feed_count(), 1);
    }

    #[test]
    fn test_refresh_from_feeds_adds_malicious_addresses() {
        let mut filter = AddressFilter::new();

        let malicious_entry = AddressEntry::new(
            "GTHREAT12345678901234567890123456789012345678901234567890".to_string(),
            AddressFormat::StellarClassic,
            AddressCategory::Malicious,
            "Known threat from mock feed".to_string(),
        );

        let mock_feed = Box::new(MockThreatIntelFeed::new(
            "test_feed",
            vec![malicious_entry.clone()],
            vec![],
        ));
        filter.add_feed(mock_feed);

        let summary = filter.refresh_from_feeds().unwrap();
        assert_eq!(summary.feeds_contacted, 1);
        assert_eq!(summary.feeds_failed, 0);
        assert_eq!(summary.total_malicious_fetched, 1);
        assert_eq!(summary.new_malicious_added, 1);
        assert_eq!(summary.duplicates_skipped, 0);

        assert!(filter.is_blacklisted(&malicious_entry.address));
    }

    #[test]
    fn test_refresh_from_feeds_deduplicates_existing() {
        let mut filter = AddressFilter::new();

        let malicious_entry = AddressEntry::new(
            "GTHREAT12345678901234567890123456789012345678901234567890".to_string(),
            AddressFormat::StellarClassic,
            AddressCategory::Malicious,
            "Known threat from mock feed".to_string(),
        );

        // Add the entry manually first
        filter.add_to_blacklist(malicious_entry.clone()).unwrap();

        // Now add a mock feed that returns the same entry
        let mock_feed = Box::new(MockThreatIntelFeed::new(
            "test_feed",
            vec![malicious_entry.clone()],
            vec![],
        ));
        filter.add_feed(mock_feed);

        let summary = filter.refresh_from_feeds().unwrap();
        assert_eq!(summary.total_malicious_fetched, 1);
        assert_eq!(summary.new_malicious_added, 0);
        assert_eq!(summary.duplicates_skipped, 1);
    }

    #[test]
    fn test_refresh_from_feeds_respects_whitelist_priority() {
        let mut filter = AddressFilter::new();

        let trusted_entry = AddressEntry::new(
            "GTRUSTED1234567890123456789012345678901234567890123456789".to_string(),
            AddressFormat::StellarClassic,
            AddressCategory::Trusted,
            "Trusted address".to_string(),
        );

        // Whitelist the trusted address first
        filter.add_to_whitelist(trusted_entry.clone()).unwrap();

        // Mock feed returns it as malicious
        let mut malicious_clone = trusted_entry.clone();
        malicious_clone.category = AddressCategory::Malicious;

        let mock_feed = Box::new(MockThreatIntelFeed::new(
            "test_feed",
            vec![malicious_clone],
            vec![],
        ));
        filter.add_feed(mock_feed);

        let summary = filter.refresh_from_feeds().unwrap();
        // Should be skipped because address is already whitelisted
        assert_eq!(summary.duplicates_skipped, 1);
        assert!(filter.is_whitelisted(&trusted_entry.address));
        assert!(!filter.is_blacklisted(&trusted_entry.address));
    }

    #[test]
    fn test_get_all_feed_statuses() {
        let mut filter = AddressFilter::new();

        let mock_feed = Box::new(MockThreatIntelFeed::new(
            "status_test_feed",
            vec![],
            vec![],
        ));
        filter.add_feed(mock_feed);

        let statuses = filter.get_all_feed_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].name, "status_test_feed");
        assert_eq!(statuses[0].feed_type, "mock");
        assert!(statuses[0].enabled);
        assert!(statuses[0].is_healthy);
    }

    #[test]
    fn test_threat_intel_feed_config_default() {
        let config = ThreatIntelFeedConfig::default();
        assert_eq!(config.feed_type, "stellar_expert");
        assert!(!config.enabled);
        assert!(config.include_malicious);
        assert!(!config.include_trusted);
        assert_eq!(config.refresh_interval_secs, 3600);
        assert_eq!(config.max_entries_per_fetch, 5000);
    }

    #[test]
    fn test_address_filter_config_includes_feed_settings() {
        let config = AddressFilterConfig::default();
        assert!(config.threat_intel_feeds.is_empty());
        assert!(!config.auto_refresh_feeds);
        assert_eq!(config.auto_refresh_interval_secs, 3600);
    }
}
