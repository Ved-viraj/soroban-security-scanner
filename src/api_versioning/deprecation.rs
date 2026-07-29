//! API version deprecation policy and version registry
//!
//! Implements the deprecation lifecycle with minimum 6-month notice period,
//! automated sunset tracking, and client notification support.

use crate::api_versioning::version::{ApiVersion, VersionInfo, VersionLifecycle};
use chrono::{DateTime, Duration, Utc};
use hmac::Mac;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// Deprecation policy configuration
#[derive(Debug, Clone)]
pub struct DeprecationPolicy {
    /// Minimum notice period before sunset (in days)
    pub min_notice_days: i64,
    /// Whether to automatically notify clients via response headers
    pub auto_notify_clients: bool,
    /// Whether to send email notifications for upcoming sunsets
    pub email_notifications: bool,
    /// Days before sunset to start sending urgency notifications
    pub urgency_notification_days: Vec<i64>,
}

impl Default for DeprecationPolicy {
    fn default() -> Self {
        Self {
            min_notice_days: 180, // 6 months minimum
            auto_notify_clients: true,
            email_notifications: false,
            urgency_notification_days: vec![90, 60, 30, 14, 7, 1],
        }
    }
}

impl DeprecationPolicy {
    /// Create a strict policy with longer notice period
    pub fn strict() -> Self {
        Self {
            min_notice_days: 365, // 1 year
            auto_notify_clients: true,
            email_notifications: true,
            urgency_notification_days: vec![180, 90, 60, 30, 14, 7, 1],
        }
    }

    /// Check if a proposed sunset date meets the minimum notice requirement
    pub fn validate_sunset_date(&self, sunset_date: DateTime<Utc>) -> Result<(), String> {
        let min_sunset = Utc::now() + Duration::days(self.min_notice_days);
        if sunset_date < min_sunset {
            Err(format!(
                "Sunset date must be at least {} days from now. Minimum: {}, Proposed: {}",
                self.min_notice_days,
                min_sunset.format("%Y-%m-%d"),
                sunset_date.format("%Y-%m-%d"),
            ))
        } else {
            Ok(())
        }
    }

    /// Get the minimum allowed sunset date
    pub fn min_sunset_date(&self) -> DateTime<Utc> {
        Utc::now() + Duration::days(self.min_notice_days)
    }
}

/// Registry tracking all API versions and their lifecycle states
#[derive(Debug)]
pub struct VersionRegistry {
    versions: RwLock<HashMap<ApiVersion, VersionInfo>>,
    deprecation_policy: DeprecationPolicy,
}

impl Default for VersionRegistry {
    fn default() -> Self {
        let mut versions = HashMap::new();

        // Initialize with V1 as the current stable version
        let mut v1 = VersionInfo::new_stable(
            ApiVersion::V1,
            "Initial API version. Provides core security scanning, authentication, \
             and transaction processing endpoints.",
        );
        v1.add_non_breaking_change("Initial API release with all core endpoints");
        versions.insert(ApiVersion::V1, v1);

        // Pre-register V2 as alpha (future version)
        let v2 = VersionInfo::new_alpha(
            ApiVersion::V2,
            "Next-generation API with improved performance and new features.",
        );
        versions.insert(ApiVersion::V2, v2);

        Self {
            versions: RwLock::new(versions),
            deprecation_policy: DeprecationPolicy::default(),
        }
    }
}

impl VersionRegistry {
    /// Create a new registry with a custom deprecation policy
    pub fn with_policy(policy: DeprecationPolicy) -> Self {
        let default = Self::default();
        Self {
            deprecation_policy: policy,
            ..default
        }
    }

    /// Register a new version
    pub fn register_version(&self, info: VersionInfo) -> Result<(), String> {
        let mut versions = self.versions.write().map_err(|e| e.to_string())?;
        if versions.contains_key(&info.version) {
            return Err(format!(
                "Version {} is already registered",
                info.version.as_path()
            ));
        }
        versions.insert(info.version, info);
        Ok(())
    }

    /// Get version info
    pub fn get_version(&self, version: ApiVersion) -> Option<VersionInfo> {
        self.versions
            .read()
            .ok()
            .and_then(|v| v.get(&version).cloned())
    }

    /// List all registered versions
    pub fn list_versions(&self) -> Vec<VersionInfo> {
        self.versions
            .read()
            .ok()
            .map(|v| {
                let mut versions: Vec<_> = v.values().cloned().collect();
                versions.sort_by_key(|v| v.version);
                versions
            })
            .unwrap_or_default()
    }

    /// List only served (non-sunset) versions
    pub fn list_active_versions(&self) -> Vec<VersionInfo> {
        self.list_versions()
            .into_iter()
            .filter(|v| v.lifecycle.is_served())
            .collect()
    }

    /// Get the current stable version
    pub fn current_stable(&self) -> Option<VersionInfo> {
        self.versions.read().ok().and_then(|v| {
            v.values()
                .find(|info| info.lifecycle == VersionLifecycle::Stable)
                .cloned()
        })
    }
    /// Deprecate a version with minimum notice enforcement.
    ///
    /// Computes `sunset_date` from a single `now` snapshot so the
    /// minimum-notice window is satisfied by construction — no second
    /// `Utc::now()` call that could observe clock drift and falsely
    /// reject the deprecation.
    pub fn deprecate_version(&self, version: ApiVersion) -> Result<(), String> {
        let mut versions = self.versions.write().map_err(|e| e.to_string())?;
        let info = versions
            .get_mut(&version)
            .ok_or_else(|| format!("Version {} not found", version.as_path()))?;

        if info.lifecycle == VersionLifecycle::Sunset {
            return Err(format!("Version {} is already sunset", version.as_path()));
        }

        let now = Utc::now();
        info.lifecycle = VersionLifecycle::Deprecated;
        info.deprecation_date = Some(now);
        info.sunset_date = Some(now + Duration::days(self.deprecation_policy.min_notice_days));

        Ok(())
    }

    /// Sunset a deprecated version (stop serving it)
    pub fn sunset_version(&self, version: ApiVersion) -> Result<(), String> {
        let mut versions = self.versions.write().map_err(|e| e.to_string())?;
        let info = versions
            .get_mut(&version)
            .ok_or_else(|| format!("Version {} not found", version.as_path()))?;

        if info.lifecycle != VersionLifecycle::Deprecated {
            return Err(format!(
                "Version {} must be deprecated before sunsetting (current: {})",
                version.as_path(),
                info.lifecycle.as_str()
            ));
        }

        info.sunset();
        Ok(())
    }

    /// Promote a version to stable (typically from beta)
    pub fn promote_to_stable(&self, version: ApiVersion) -> Result<(), String> {
        let mut versions = self.versions.write().map_err(|e| e.to_string())?;

        // Check the version exists and its lifecycle is not sunset
        {
            let info = versions
                .get(&version)
                .ok_or_else(|| format!("Version {} not found", version.as_path()))?;

            if info.lifecycle == VersionLifecycle::Sunset {
                return Err(format!(
                    "Cannot promote sunset version {}",
                    version.as_path()
                ));
            }
        }

        // Demote previous stable version(s) to deprecated if they exist
        for other_info in versions.values_mut() {
            if other_info.lifecycle == VersionLifecycle::Stable && other_info.version != version {
                other_info.deprecate();
            }
        }

        // Now promote the target version
        if let Some(info) = versions.get_mut(&version) {
            info.lifecycle = VersionLifecycle::Stable;
        }

        Ok(())
    }

    /// Add a change to a version's changelog
    pub fn add_change(
        &self,
        version: ApiVersion,
        change: &str,
        is_breaking: bool,
    ) -> Result<(), String> {
        let mut versions = self.versions.write().map_err(|e| e.to_string())?;
        let info = versions
            .get_mut(&version)
            .ok_or_else(|| format!("Version {} not found", version.as_path()))?;

        if is_breaking {
            if !info.lifecycle.allows_breaking_changes() {
                return Err(format!(
                    "Breaking changes not allowed for version {} in {} phase",
                    version.as_path(),
                    info.lifecycle.as_str()
                ));
            }
            info.add_breaking_change(change);
        } else {
            info.add_non_breaking_change(change);
        }

        Ok(())
    }

    /// Get deprecation policy
    pub fn deprecation_policy(&self) -> &DeprecationPolicy {
        &self.deprecation_policy
    }

    /// Check which versions need urgency notifications based on sunset proximity
    pub fn get_urgency_notifications(&self) -> Vec<UrgencyNotification> {
        let policy = &self.deprecation_policy;
        let mut notifications = Vec::new();

        if let Ok(versions) = self.versions.read() {
            for (version, info) in versions.iter() {
                if info.lifecycle == VersionLifecycle::Deprecated {
                    if let Some(sunset) = info.sunset_date {
                        let days_remaining = (sunset - Utc::now()).num_days();
                        for &threshold in &policy.urgency_notification_days {
                            if days_remaining <= threshold && days_remaining > threshold - 1 {
                                notifications.push(UrgencyNotification {
                                    version: *version,
                                    days_until_sunset: days_remaining,
                                    sunset_date: sunset,
                                    threshold,
                                });
                            }
                        }
                    }
                }
            }
        }

        notifications
    }
}

/// Notification for upcoming version sunset
#[derive(Debug, Clone)]
pub struct UrgencyNotification {
    pub version: ApiVersion,
    pub days_until_sunset: i64,
    pub sunset_date: DateTime<Utc>,
    pub threshold: i64,
}

// ---------------------------------------------------------------------------
// Webhook subscriber management with HMAC signature verification
// ---------------------------------------------------------------------------

/// A registered webhook subscriber with a signing secret for payload verification.
#[derive(Debug, Clone)]
pub struct WebhookSubscriber {
    /// Unique subscriber ID
    pub id: String,
    /// Webhook URL to send notifications to
    pub url: String,
    /// HMAC-SHA256 signing secret (returned once at creation time)
    pub signing_secret: String,
    /// API version the subscriber is watching
    pub version: ApiVersion,
    /// Whether the subscriber is active
    pub active: bool,
    /// When the subscription was created
    pub created_at: DateTime<Utc>,
    /// Set of delivered webhook IDs for replay prevention
    pub delivered_webhook_ids: Vec<String>,
}

impl WebhookSubscriber {
    /// Create a new webhook subscriber with a cryptographically random signing secret.
    pub fn new(url: String, version: ApiVersion) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            url,
            signing_secret: Self::generate_secret(),
            version,
            active: true,
            created_at: Utc::now(),
            delivered_webhook_ids: Vec::new(),
        }
    }

    /// Generate a cryptographically random signing secret (hex-encoded 32 bytes).
    fn generate_secret() -> String {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        hex::encode(key)
    }

    /// Mark a webhook ID as delivered (for replay prevention).
    pub fn record_delivery(&mut self, webhook_id: &str) {
        self.delivered_webhook_ids.push(webhook_id.to_string());
        // Keep only the last 1000 IDs to bound memory
        if self.delivered_webhook_ids.len() > 1000 {
            self.delivered_webhook_ids.drain(0..200);
        }
    }

    /// Check if a webhook ID has already been delivered (replay detection).
    pub fn has_been_delivered(&self, webhook_id: &str) -> bool {
        self.delivered_webhook_ids.contains(&webhook_id.to_string())
    }
}

/// A signed webhook payload ready for delivery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedWebhookPayload {
    /// Unique webhook delivery ID (for replay prevention)
    pub webhook_id: String,
    /// The JSON body of the webhook notification
    pub body: serde_json::Value,
    /// Signature header value: "t=<timestamp>,v1=<hex-encoded HMAC-SHA256>"
    pub signature_header: String,
    /// Unix timestamp used in the signature
    pub timestamp: i64,
}

/// Compute an HMAC-SHA256 signature for a webhook payload.
///
/// The signature format follows the Stripe/GitHub convention:
/// `t=<unix_timestamp>,v1=<hex-encoded HMAC-SHA256(timestamp.body)>`
///
/// # Arguments
/// * `body` - The raw JSON body bytes to sign
/// * `secret` - The subscriber's signing secret
/// * `timestamp` - Unix timestamp (typically Utc::now().timestamp())
///
/// # Returns
/// The signature header value string.
pub fn sign_webhook_payload(body: &[u8], secret: &str, timestamp: i64) -> String {
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(body));
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    hmac::Mac::update(&mut mac, signed_payload.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());
    format!("t={},v1={}", timestamp, signature)
}

/// Verify an HMAC-SHA256 webhook signature.
///
/// This is the verification function that subscribers use to validate
/// incoming webhook payloads. It:
/// 1. Parses the `X-Soroban-Signature` header to extract timestamp and signature
/// 2. Recomputes the HMAC-SHA256 with the same algorithm used for signing
/// 3. Compares the computed signature with the one in the header
/// 4. Optionally checks timestamp tolerance to prevent replay of old payloads
///
/// # Arguments
/// * `body` - The raw JSON body bytes received from the webhook
/// * `signature_header` - Value of the `X-Soroban-Signature` header
/// * `secret` - The subscriber's signing secret
/// * `timestamp_tolerance_seconds` - Max age of the timestamp (default 300 = 5 min)
///
/// # Returns
/// `true` if the signature is valid and timestamp is within tolerance.
pub fn verify_webhook_signature(
    body: &[u8],
    signature_header: &str,
    secret: &str,
    timestamp_tolerance_seconds: i64,
) -> bool {
    // Parse the signature header: "t=<timestamp>,v1=<hex-sig>"
    let parts: HashMap<&str, &str> = signature_header
        .split(',')
        .filter_map(|part| {
            let mut kv = part.splitn(2, '=');
            Some((kv.next()?, kv.next()?))
        })
        .collect();

    let timestamp_str = match parts.get("t") {
        Some(t) => t,
        None => return false,
    };

    let provided_signature = match parts.get("v1") {
        Some(s) => s,
        None => return false,
    };

    // Parse timestamp and check tolerance
    let timestamp: i64 = match timestamp_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > timestamp_tolerance_seconds {
        return false;
    }

    // Recompute the expected signature
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(body));
    let mut mac = match hmac::Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    hmac::Mac::update(&mut mac, signed_payload.as_bytes());
    let result = mac.finalize();
    let expected_signature = hex::encode(result.into_bytes());

    // Constant-time comparison to prevent timing attacks
    // Convert both to lowercase bytes for case-insensitive comparison
    let expected_bytes = expected_signature.as_bytes();
    let provided_bytes = provided_signature.as_bytes();

    if expected_bytes.len() != provided_bytes.len() {
        return false;
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected_bytes.iter().zip(provided_bytes.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Create a signed webhook payload for a subscriber.
///
/// Generates a unique webhook ID, signs the body with the subscriber's secret,
/// and returns the complete signed payload.
pub fn create_signed_webhook(body: serde_json::Value, secret: &str) -> SignedWebhookPayload {
    let webhook_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().timestamp();
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let signature_header = sign_webhook_payload(&body_bytes, secret, timestamp);

    SignedWebhookPayload {
        webhook_id,
        body,
        signature_header,
        timestamp,
    }
}

/// Registry for webhook subscribers.
#[derive(Debug, Default)]
pub struct WebhookRegistry {
    subscribers: RwLock<HashMap<String, WebhookSubscriber>>,
}

impl WebhookRegistry {
    /// Create a new empty webhook registry.
    pub fn new() -> Self {
        Self {
            subscribers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new webhook subscriber. Returns the subscriber (with signing secret).
    /// The secret is only returned at creation time; it is not retrievable later.
    pub fn register(&self, url: String, version: ApiVersion) -> Result<WebhookSubscriber, String> {
        let subscriber = WebhookSubscriber::new(url, version);
        let mut subs = self.subscribers.write().map_err(|e| e.to_string())?;
        subs.insert(subscriber.id.clone(), subscriber.clone());
        Ok(subscriber)
    }

    /// Get a subscriber by ID (without exposing the secret).
    /// Returns the subscriber metadata but redacts the signing secret.
    pub fn get_subscriber(&self, id: &str) -> Option<WebhookSubscriber> {
        self.subscribers.read().ok().and_then(|s| {
            s.get(id).map(|sub| {
                let mut redacted = sub.clone();
                redacted.signing_secret = "[REDACTED]".to_string();
                redacted
            })
        })
    }

    /// Get a subscriber by ID including the signing secret (for signing outbound webhooks).
    /// This should only be used internally when dispatching webhooks.
    pub fn get_subscriber_with_secret(&self, id: &str) -> Option<WebhookSubscriber> {
        self.subscribers
            .read()
            .ok()
            .and_then(|s| s.get(id).cloned())
    }

    /// List all subscribers for a given API version.
    pub fn list_for_version(&self, version: ApiVersion) -> Vec<WebhookSubscriber> {
        self.subscribers
            .read()
            .ok()
            .map(|s| {
                s.values()
                    .filter(|sub| sub.version == version && sub.active)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record a webhook delivery for a subscriber (replay prevention).
    pub fn record_delivery(&self, subscriber_id: &str, webhook_id: &str) -> Result<(), String> {
        let mut subs = self.subscribers.write().map_err(|e| e.to_string())?;
        if let Some(sub) = subs.get_mut(subscriber_id) {
            sub.record_delivery(webhook_id);
        }
        Ok(())
    }

    /// Deactivate a subscriber.
    pub fn deactivate(&self, id: &str) -> Result<(), String> {
        let mut subs = self.subscribers.write().map_err(|e| e.to_string())?;
        if let Some(sub) = subs.get_mut(id) {
            sub.active = false;
            Ok(())
        } else {
            Err(format!("Subscriber {} not found", id))
        }
    }
}

/// Sunset procedures documentation
pub struct SunsetProcedures;

impl SunsetProcedures {
    /// Get the sunset procedure checklist
    pub fn checklist() -> Vec<&'static str> {
        vec![
            "1. Announce deprecation with minimum 6-month notice",
            "2. Add deprecation warnings via HTTP headers (X-API-Deprecated, X-API-Sunset)",
            "3. Document migration path to the current stable version",
            "4. Monitor deprecated version usage metrics",
            "5. Send urgency notifications at 90, 60, 30, 14, 7, and 1 days before sunset",
            "6. Verify zero production traffic before sunset date",
            "7. Archive deprecated version documentation",
            "8. Return 410 Gone for sunset version endpoints",
            "9. Update API version listing to mark version as sunset",
            "10. Update client SDKs and documentation to remove references",
        ]
    }

    /// Get the client migration guide template
    pub fn migration_guide_template(from_version: ApiVersion, to_version: ApiVersion) -> String {
        format!(
            r#"# API Migration Guide: {} to {}

## Overview
This guide helps you migrate your integration from API {} to {}.

## Timeline
- **Deprecation announced**: [DATE]
- **Sunset date**: [DATE]
- **Migration deadline**: [DATE]

## Breaking Changes
The following changes require updates to your code:
[List breaking changes here]

## Non-Breaking Changes
The following new features are available:
[List non-breaking changes here]

## Step-by-Step Migration

### 1. Update API Base URL
```
Old: /api/{}/
New: /api/{}/
```

### 2. Update Request Headers
```
Old: Accept: application/vnd.soroban.{}+json
New: Accept: application/vnd.soroban.{}+json
```

### 3. Update Response Handling
[Describe response format changes]

## Testing Your Migration
Use the version compatibility test suite:
```bash
cargo test api_versioning::compatibility
```

## Support
If you encounter issues, please file an issue at:
https://github.com/connect-boiz/soroban-security-scanner/issues
"#,
            from_version.as_path(),
            to_version.as_path(),
            from_version.as_path(),
            to_version.as_path(),
            from_version.as_path(),
            to_version.as_path(),
            from_version.as_path(),
            to_version.as_path(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deprecation_policy_default_six_months() {
        let policy = DeprecationPolicy::default();
        assert_eq!(policy.min_notice_days, 180);
    }

    #[test]
    fn test_deprecation_policy_validate_minimum() {
        let policy = DeprecationPolicy::default();
        let too_soon = Utc::now() + Duration::days(30);
        assert!(policy.validate_sunset_date(too_soon).is_err());
        let far_enough = Utc::now() + Duration::days(200);
        assert!(policy.validate_sunset_date(far_enough).is_ok());
    }

    #[test]
    fn test_version_registry_default() {
        let registry = VersionRegistry::default();
        assert!(registry.get_version(ApiVersion::V1).is_some());
        assert_eq!(
            registry.get_version(ApiVersion::V1).unwrap().lifecycle,
            VersionLifecycle::Stable
        );
    }

    #[test]
    fn test_deprecate_version() {
        let registry = VersionRegistry::default();
        assert!(registry.deprecate_version(ApiVersion::V1).is_ok());
        let info = registry.get_version(ApiVersion::V1).unwrap();
        assert_eq!(info.lifecycle, VersionLifecycle::Deprecated);
        assert!(info.should_warn());
    }

    #[test]
    fn test_promote_to_stable() {
        let registry = VersionRegistry::default();
        assert!(registry.promote_to_stable(ApiVersion::V2).is_ok());
        let v2_info = registry.get_version(ApiVersion::V2).unwrap();
        assert_eq!(v2_info.lifecycle, VersionLifecycle::Stable);
        let v1_info = registry.get_version(ApiVersion::V1).unwrap();
        assert_eq!(v1_info.lifecycle, VersionLifecycle::Deprecated);
    }

    #[test]
    fn test_sunset_version() {
        let registry = VersionRegistry::default();
        registry.deprecate_version(ApiVersion::V1).unwrap();
        assert!(registry.sunset_version(ApiVersion::V1).is_ok());
        let info = registry.get_version(ApiVersion::V1).unwrap();
        assert_eq!(info.lifecycle, VersionLifecycle::Sunset);
    }

    #[test]
    fn test_cannot_sunset_non_deprecated() {
        let registry = VersionRegistry::default();
        assert!(registry.sunset_version(ApiVersion::V1).is_err());
    }

    #[test]
    fn test_breaking_change_not_allowed_in_stable() {
        let registry = VersionRegistry::default();
        let result = registry.add_change(ApiVersion::V1, "Removed endpoint", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_breaking_change_allowed_in_alpha() {
        let registry = VersionRegistry::default();
        let result = registry.add_change(ApiVersion::V2, "Changed API", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sunset_procedures_checklist() {
        let checklist = SunsetProcedures::checklist();
        assert_eq!(checklist.len(), 10);
    }

    #[test]
    fn test_migration_guide_template() {
        let guide = SunsetProcedures::migration_guide_template(ApiVersion::V1, ApiVersion::V2);
        assert!(guide.contains("v1 to v2"));
        assert!(guide.contains("/api/v1/"));
        assert!(guide.contains("/api/v2/"));
    }

    // ------------------------------------------------------------------
    // Webhook signature verification tests
    // ------------------------------------------------------------------

    #[test]
    fn test_webhook_sign_and_verify_correctly() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let body = b"{\"version\":\"v1\",\"days_until_sunset\":30}";
        let timestamp = Utc::now().timestamp();

        let signature_header = sign_webhook_payload(body, secret, timestamp);
        assert!(signature_header.starts_with(&format!("t={},v1=", timestamp)));

        // Correct signature must verify
        let valid = verify_webhook_signature(body, &signature_header, secret, 300);
        assert!(valid, "correctly signed payload must verify");
    }

    #[test]
    fn test_webhook_tampered_body_fails_verification() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let body = b"{\"version\":\"v1\",\"days_until_sunset\":30}";
        let timestamp = Utc::now().timestamp();

        let signature_header = sign_webhook_payload(body, secret, timestamp);

        // Tamper with the body
        let tampered_body = b"{\"version\":\"v1\",\"days_until_sunset\":999}";
        let valid = verify_webhook_signature(tampered_body, &signature_header, secret, 300);
        assert!(!valid, "tampered body must fail verification");
    }

    #[test]
    fn test_webhook_wrong_secret_fails_verification() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let wrong_secret = "whsec_different_secret_32_bytes_here_cd";
        let body = b"{\"version\":\"v1\",\"days_until_sunset\":30}";
        let timestamp = Utc::now().timestamp();

        let signature_header = sign_webhook_payload(body, secret, timestamp);
        let valid = verify_webhook_signature(body, &signature_header, wrong_secret, 300);
        assert!(!valid, "wrong secret must fail verification");
    }

    #[test]
    fn test_webhook_expired_timestamp_fails_verification() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let body = b"{\"version\":\"v1\",\"days_until_sunset\":30}";

        // Create a signature with a timestamp 10 minutes in the past
        let old_timestamp = Utc::now().timestamp() - 600;
        let signature_header = sign_webhook_payload(body, secret, old_timestamp);

        // With 5-minute tolerance, this should fail
        let valid = verify_webhook_signature(body, &signature_header, secret, 300);
        assert!(!valid, "expired timestamp must fail within 5-min tolerance");
    }

    #[test]
    fn test_webhook_replay_with_same_webhook_id_detected() {
        let registry = WebhookRegistry::new();

        // Register a subscriber
        let sub = registry
            .register(
                "https://hooks.example.com/deprecation".to_string(),
                ApiVersion::V1,
            )
            .unwrap();

        let webhook_id = "replay-webhook-id-001";

        // First delivery should be fine
        assert!(!sub.has_been_delivered(webhook_id));
        registry.record_delivery(&sub.id, webhook_id).unwrap();

        // Same ID should now be detected as delivered (replay)
        let updated_sub = registry.get_subscriber(&sub.id).unwrap();
        assert!(updated_sub.has_been_delivered(webhook_id));
    }

    #[test]
    fn test_webhook_subscriber_registration_generates_secret() {
        let registry = WebhookRegistry::new();
        let sub = registry
            .register(
                "https://hooks.example.com/deprecation".to_string(),
                ApiVersion::V2,
            )
            .unwrap();

        // Secret should be 64 hex chars (32 bytes)
        assert_eq!(sub.signing_secret.len(), 64);
        assert!(sub.active);
        assert_eq!(sub.version, ApiVersion::V2);
        assert_eq!(sub.url, "https://hooks.example.com/deprecation");
    }

    #[test]
    fn test_webhook_subscriber_secrets_are_unique() {
        let registry = WebhookRegistry::new();
        let sub1 = registry
            .register("https://hooks1.example.com".to_string(), ApiVersion::V1)
            .unwrap();
        let sub2 = registry
            .register("https://hooks2.example.com".to_string(), ApiVersion::V1)
            .unwrap();

        assert_ne!(sub1.signing_secret, sub2.signing_secret);
        assert_ne!(sub1.id, sub2.id);
    }

    #[test]
    fn test_webhook_subscriber_deactivation() {
        let registry = WebhookRegistry::new();
        let sub = registry
            .register("https://hooks.example.com".to_string(), ApiVersion::V1)
            .unwrap();

        assert!(sub.active);
        registry.deactivate(&sub.id).unwrap();

        let deactivated = registry.get_subscriber(&sub.id).unwrap();
        assert!(!deactivated.active);
    }

    #[test]
    fn test_webhook_list_for_version() {
        let registry = WebhookRegistry::new();
        registry
            .register("https://hooks1.example.com".to_string(), ApiVersion::V1)
            .unwrap();
        registry
            .register("https://hooks2.example.com".to_string(), ApiVersion::V1)
            .unwrap();
        registry
            .register("https://hooks3.example.com".to_string(), ApiVersion::V2)
            .unwrap();

        let v1_subs = registry.list_for_version(ApiVersion::V1);
        let v2_subs = registry.list_for_version(ApiVersion::V2);

        assert_eq!(v1_subs.len(), 2);
        assert_eq!(v2_subs.len(), 1);
    }

    #[test]
    fn test_webhook_create_signed_payload() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let body = serde_json::json!({
            "version": "v1",
            "event": "deprecation_urgency",
            "days_until_sunset": 30,
            "sunset_date": "2027-01-01T00:00:00Z"
        });

        let signed = create_signed_webhook(body.clone(), secret);

        assert!(!signed.webhook_id.is_empty());
        assert_eq!(signed.body, body);
        assert!(signed.signature_header.starts_with("t="));
        assert!(signed.signature_header.contains(",v1="));
        assert!(signed.timestamp > 0);

        // Verify the created signature can be verified
        let body_bytes = serde_json::to_vec(&signed.body).unwrap();
        let valid = verify_webhook_signature(&body_bytes, &signed.signature_header, secret, 300);
        assert!(valid, "created signed payload must be verifiable");
    }

    #[test]
    fn test_webhook_invalid_signature_header_format() {
        let secret = "whsec_test_secret_32_bytes_minimum_here_ab";
        let body = b"{}";

        // Malformed headers should fail safely
        assert!(!verify_webhook_signature(body, "", secret, 300));
        assert!(!verify_webhook_signature(body, "t=123", secret, 300));
        assert!(!verify_webhook_signature(body, "v1=abc", secret, 300));
        assert!(!verify_webhook_signature(body, "garbage", secret, 300));
        assert!(!verify_webhook_signature(
            body,
            "t=notanumber,v1=abc",
            secret,
            300
        ));
    }
}
