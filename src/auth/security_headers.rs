use axum::{
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspViolation {
    pub directive: String,
    pub blocked_uri: String,
    pub document_uri: String,
    pub source_file: Option<String>,
    pub line_number: Option<i32>,
    pub violated_at: DateTime<Utc>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CspViolationFilter {
    pub directive: Option<String>,
    pub blocked_uri: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspViolationListResponse {
    pub data: Vec<CspViolation>,
    pub page: usize,
    pub per_page: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CspDashboardSummary {
    pub violations_by_directive: Vec<DirectiveBreakdown>,
    pub top_blocked_uris: Vec<BlockedUriBreakdown>,
    pub violations_over_time: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectiveBreakdown {
    pub directive: String,
    pub count: usize,
    pub trend: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedUriBreakdown {
    pub blocked_uri: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    pub date: String,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct CspPolicyGraduationRecommendation {
    pub safe_to_enforce: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CspPolicyGraduationCheck {
    violations: Vec<CspViolation>,
    window_days: i64,
}

impl CspPolicyGraduationCheck {
    pub fn new(violations: Vec<CspViolation>, window_days: i64) -> Self {
        Self {
            violations,
            window_days,
        }
    }

    pub fn evaluate(&self, now: DateTime<Utc>) -> CspPolicyGraduationRecommendation {
        let cutoff = now - Duration::days(self.window_days);
        let recent = self
            .violations
            .iter()
            .filter(|violation| violation.violated_at >= cutoff)
            .cloned()
            .collect::<Vec<_>>();

        let directive_counts = recent
            .iter()
            .fold(HashMap::new(), |mut map, violation| {
                *map.entry(violation.directive.clone()).or_insert(0usize) += 1;
                map
            });

        let safe_to_enforce = recent.is_empty() || (recent.len() <= 2 && directive_counts.len() <= 1);
        let reason = if safe_to_enforce {
            "Recent CSP violations are limited and stable; the policy appears ready for enforcement.".to_string()
        } else {
            format!(
                "CSP violations detected across {} directives over the last {} days; keep report-only until the underlying issues are resolved.",
                directive_counts.len(),
                self.window_days
            )
        };

        CspPolicyGraduationRecommendation {
            safe_to_enforce,
            reason,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LogAlert {
    pub directive: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Default, Clone)]
pub struct LogAlerter;

impl LogAlerter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze_alerts(&self, current: &[CspViolation], previous: &[CspViolation], _now: DateTime<Utc>) -> Vec<LogAlert> {
        let previous_directives: HashSet<_> = previous.iter().map(|violation| violation.directive.clone()).collect();
        let current_directives: HashSet<_> = current.iter().map(|violation| violation.directive.clone()).collect();
        let mut alerts = Vec::new();

        if let Some(new_directive) = current_directives.difference(&previous_directives).next() {
            alerts.push(LogAlert {
                directive: new_directive.clone(),
                severity: "warning".to_string(),
                message: format!("New CSP directive {} appears in the latest violations.", new_directive),
            });
        }

        if current.len() as i64 > previous.len() as i64 + 1 {
            alerts.push(LogAlert {
                directive: "overall".to_string(),
                severity: "warning".to_string(),
                message: "CSP violations spiked sharply compared with the previous window.".to_string(),
            });
        }

        alerts
    }
}

#[async_trait::async_trait]
pub trait CspViolationStore: Send + Sync {
    async fn record_csp_violation(&self, violation: CspViolation) -> anyhow::Result<()>;
    async fn query_csp_violations(&self, filter: &CspViolationFilter) -> anyhow::Result<Vec<CspViolation>>;
    async fn get_csp_dashboard(&self, filter: Option<CspViolationFilter>) -> anyhow::Result<CspDashboardSummary>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryCspViolationStore {
    violations: Arc<RwLock<Vec<CspViolation>>>,
}

impl InMemoryCspViolationStore {
    pub async fn record_violation(&self, violation: CspViolation) -> anyhow::Result<()> {
        self.record_csp_violation(violation).await
    }

    pub async fn list_violations(&self, filter: &CspViolationFilter) -> anyhow::Result<Vec<CspViolation>> {
        self.query_csp_violations(filter).await
    }

    pub async fn get_dashboard_aggregations(&self, filter: Option<CspViolationFilter>) -> anyhow::Result<CspDashboardSummary> {
        self.get_csp_dashboard(filter).await
    }
}

#[async_trait::async_trait]
impl CspViolationStore for InMemoryCspViolationStore {
    async fn record_csp_violation(&self, violation: CspViolation) -> anyhow::Result<()> {
        let mut violations = self
            .violations
            .write()
            .map_err(|_| anyhow::anyhow!("Unable to write CSP violation store"))?;
        violations.push(violation);
        Ok(())
    }

    async fn query_csp_violations(&self, filter: &CspViolationFilter) -> anyhow::Result<Vec<CspViolation>> {
        let violations = self
            .violations
            .read()
            .map_err(|_| anyhow::anyhow!("Unable to read CSP violation store"))?;
        let mut filtered: Vec<CspViolation> = violations
            .iter()
            .filter(|violation| {
                if let Some(directive) = &filter.directive {
                    if !violation.directive.eq_ignore_ascii_case(directive) {
                        return false;
                    }
                }
                if let Some(blocked_uri) = &filter.blocked_uri {
                    if !violation.blocked_uri.contains(blocked_uri) {
                        return false;
                    }
                }
                if let Some(start_date) = filter.start_date {
                    if violation.violated_at < start_date {
                        return false;
                    }
                }
                if let Some(end_date) = filter.end_date {
                    if violation.violated_at > end_date {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        filtered.sort_by(|left, right| right.violated_at.cmp(&left.violated_at));

        let page = filter.page.unwrap_or(1).max(1);
        let per_page = filter.per_page.unwrap_or(20).max(1);
        let start = (page - 1) * per_page;
        let end = start + per_page;
        Ok(filtered.into_iter().skip(start).take(end.saturating_sub(start)).collect())
    }

    async fn get_csp_dashboard(&self, filter: Option<CspViolationFilter>) -> anyhow::Result<CspDashboardSummary> {
        let filter = filter.unwrap_or_default();
        let violations = self.query_csp_violations(&filter).await?;
        let mut directives: HashMap<String, usize> = HashMap::new();
        let mut blocked_uris: HashMap<String, usize> = HashMap::new();
        let mut time_series: HashMap<String, usize> = HashMap::new();

        let now = Utc::now();
        for violation in &violations {
            *directives.entry(violation.directive.clone()).or_insert(0) += 1;
            *blocked_uris.entry(violation.blocked_uri.clone()).or_insert(0) += 1;
            let bucket = violation.violated_at.date_naive().format("%Y-%m-%d").to_string();
            *time_series.entry(bucket).or_insert(0) += 1;
            let _ = now;
        }

        let mut violations_by_directive = directives
            .into_iter()
            .map(|(directive, count)| {
                let recent = violations.iter().filter(|item| item.directive == directive).count();
                let trend = if recent > 1 { "up".to_string() } else { "flat".to_string() };
                DirectiveBreakdown { directive, count, trend }
            })
            .collect::<Vec<_>>();
        violations_by_directive.sort_by(|left, right| right.count.cmp(&left.count));

        let mut top_blocked_uris = blocked_uris
            .into_iter()
            .map(|(blocked_uri, count)| BlockedUriBreakdown { blocked_uri, count })
            .collect::<Vec<_>>();
        top_blocked_uris.sort_by(|left, right| right.count.cmp(&left.count));

        let mut violations_over_time = time_series
            .into_iter()
            .map(|(date, count)| TimeSeriesPoint { date, count })
            .collect::<Vec<_>>();
        violations_over_time.sort_by(|left, right| left.date.cmp(&right.date));

        Ok(CspDashboardSummary {
            violations_by_directive,
            top_blocked_uris,
            violations_over_time,
        })
    }
}

pub fn build_csp_routes<S>(store: Arc<S>) -> Router
where
    S: CspViolationStore + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/api/v1/security/csp-violations",
            get(list_csp_violations::<S>).post(create_csp_violation::<S>),
        )
        .route("/api/v1/security/csp-dashboard", get(get_csp_dashboard::<S>))
        .with_state(store)
}

async fn list_csp_violations<S>(
    State(store): State<Arc<S>>,
    query: Option<Query<CspViolationFilter>>,
) -> Result<Json<CspViolationListResponse>, StatusCode>
where
    S: CspViolationStore + Send + Sync + 'static,
{
    let filter = query.map(|Query(filter)| filter).unwrap_or_default();
    let data = store
        .query_csp_violations(&filter)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CspViolationListResponse {
        data,
        page: filter.page.unwrap_or(1),
        per_page: filter.per_page.unwrap_or(20),
    }))
}

async fn create_csp_violation<S>(
    State(store): State<Arc<S>>,
    Json(violation): Json<CspViolation>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode>
where
    S: CspViolationStore + Send + Sync + 'static,
{
    store
        .record_csp_violation(violation)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "ok": true }))))
}

async fn get_csp_dashboard<S>(
    State(store): State<Arc<S>>,
    query: Option<Query<CspViolationFilter>>,
) -> Result<Json<CspDashboardSummary>, StatusCode>
where
    S: CspViolationStore + Send + Sync + 'static,
{
    let filter = query.map(|Query(filter)| filter).unwrap_or_default();
    let dashboard = store
        .get_csp_dashboard(Some(filter))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(dashboard))
}

#[derive(Debug, Error)]
pub enum SecurityHeaderError {
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(String),
    #[error("Header configuration error: {0}")]
    ConfigError(String),
}

#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    pub content_security_policy: Option<String>,
    pub strict_transport_security: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cross_origin_embedder_policy: Option<String>,
    pub cross_origin_opener_policy: Option<String>,
    pub cross_origin_resource_policy: Option<String>,
    pub x_dns_prefetch_control: Option<String>,
    pub x_download_options: Option<String>,
    pub x_permitted_cross_domain_policies: Option<String>,
    pub expect_ct: Option<String>,
    pub origin_agent_cluster: Option<String>,
    pub custom_headers: HashMap<String, String>,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: Some(
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';".to_string()
            ),
            strict_transport_security: Some("max-age=31536000; includeSubDomains; preload".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some(
                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), sync-xhr=()".to_string()
            ),
            cross_origin_embedder_policy: Some("require-corp".to_string()),
            cross_origin_opener_policy: Some("same-origin".to_string()),
            cross_origin_resource_policy: Some("same-origin".to_string()),
            x_dns_prefetch_control: Some("off".to_string()),
            x_download_options: Some("noopen".to_string()),
            x_permitted_cross_domain_policies: Some("none".to_string()),
            expect_ct: Some("max-age=86400, enforce".to_string()),
            origin_agent_cluster: Some("?1".to_string()),
            custom_headers: HashMap::new(),
        }
    }
}

impl SecurityHeadersConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn development() -> Self {
        Self {
            content_security_policy: Some(
                "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; font-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none';".to_string()
            ),
            strict_transport_security: None, // Disabled in development
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some(
                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=()".to_string()
            ),
            cross_origin_embedder_policy: None, // Can cause issues in development
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: Some("cross-origin".to_string()),
            x_dns_prefetch_control: Some("off".to_string()),
            x_download_options: Some("noopen".to_string()),
            x_permitted_cross_domain_policies: Some("none".to_string()),
            expect_ct: None,
            origin_agent_cluster: Some("?1".to_string()),
            custom_headers: HashMap::new(),
        }
    }

    pub fn minimal() -> Self {
        Self {
            content_security_policy: None,
            strict_transport_security: Some("max-age=31536000".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: None,
            cross_origin_embedder_policy: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            x_dns_prefetch_control: None,
            x_download_options: None,
            x_permitted_cross_domain_policies: None,
            expect_ct: None,
            origin_agent_cluster: None,
            custom_headers: HashMap::new(),
        }
    }

    pub fn with_csp(mut self, csp: &str) -> Self {
        self.content_security_policy = Some(csp.to_string());
        self
    }

    pub fn with_hsts(mut self, hsts: &str) -> Self {
        self.strict_transport_security = Some(hsts.to_string());
        self
    }

    pub fn with_custom_header(mut self, name: &str, value: &str) -> Self {
        self.custom_headers.insert(name.to_string(), value.to_string());
        self
    }

    pub fn without_csp(mut self) -> Self {
        self.content_security_policy = None;
        self
    }

    pub fn without_hsts(mut self) -> Self {
        self.strict_transport_security = None;
        self
    }

    // CSP builders
    pub fn csp_builder() -> CspBuilder {
        CspBuilder::new()
    }
}

pub struct CspBuilder {
    directives: HashMap<String, Vec<String>>,
}

impl CspBuilder {
    pub fn new() -> Self {
        Self {
            directives: HashMap::new(),
        }
    }

    pub fn default_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("default-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn script_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("script-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn style_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("style-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn img_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("img-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn connect_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("connect-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn font_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("font-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn frame_ancestors(mut self, sources: &[&str]) -> Self {
        self.directives.insert("frame-ancestors".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn base_uri(mut self, sources: &[&str]) -> Self {
        self.directives.insert("base-uri".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn form_action(mut self, sources: &[&str]) -> Self {
        self.directives.insert("form-action".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn frame_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("frame-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn media_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("media-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn object_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("object-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn worker_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("worker-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn manifest_src(mut self, sources: &[&str]) -> Self {
        self.directives.insert("manifest-src".to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives.insert("upgrade-insecure-requests".to_string(), vec![]);
        self
    }

    pub fn block_all_mixed_content(mut self) -> Self {
        self.directives.insert("block-all-mixed-content".to_string(), vec![]);
        self
    }

    pub fn custom_directive(mut self, name: &str, sources: &[&str]) -> Self {
        self.directives.insert(name.to_string(), sources.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn build(self) -> String {
        let mut directives = Vec::new();
        
        for (name, values) in self.directives {
            if values.is_empty() {
                directives.push(name);
            } else {
                directives.push(format!("{} {}", name, values.join(" ")));
            }
        }
        
        directives.join("; ")
    }
}

impl Default for CspBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SecurityHeadersMiddleware {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersMiddleware {
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }

    pub fn from_config(config: SecurityHeadersConfig) -> Self {
        Self::new(config)
    }

    pub fn default() -> Self {
        Self::new(SecurityHeadersConfig::default())
    }

    pub fn development() -> Self {
        Self::new(SecurityHeadersConfig::development())
    }

    pub fn minimal() -> Self {
        Self::new(SecurityHeadersConfig::minimal())
    }

    pub async fn apply_security_headers(
        &self,
        request: Request,
        next: Next,
    ) -> Result<Response, StatusCode> {
        let mut response = next.run(request).await;

        // Apply security headers
        self.add_security_headers(&mut response.headers_mut());

        Ok(response)
    }

    fn add_security_headers(&self, headers: &mut HeaderMap) {
        // Content Security Policy
        if let Some(csp) = &self.config.content_security_policy {
            if let Ok(value) = HeaderValue::from_str(csp) {
                headers.insert("Content-Security-Policy", value);
            }
        }

        // Strict Transport Security (HSTS)
        if let Some(hsts) = &self.config.strict_transport_security {
            if let Ok(value) = HeaderValue::from_str(hsts) {
                headers.insert("Strict-Transport-Security", value);
            }
        }

        // X-Frame-Options
        if let Some(xfo) = &self.config.x_frame_options {
            if let Ok(value) = HeaderValue::from_str(xfo) {
                headers.insert("X-Frame-Options", value);
            }
        }

        // X-Content-Type-Options
        if let Some(xcto) = &self.config.x_content_type_options {
            if let Ok(value) = HeaderValue::from_str(xcto) {
                headers.insert("X-Content-Type-Options", value);
            }
        }

        // X-XSS-Protection
        if let Some(xxssp) = &self.config.x_xss_protection {
            if let Ok(value) = HeaderValue::from_str(xxssp) {
                headers.insert("X-XSS-Protection", value);
            }
        }

        // Referrer Policy
        if let Some(rp) = &self.config.referrer_policy {
            if let Ok(value) = HeaderValue::from_str(rp) {
                headers.insert("Referrer-Policy", value);
            }
        }

        // Permissions Policy
        if let Some(pp) = &self.config.permissions_policy {
            if let Ok(value) = HeaderValue::from_str(pp) {
                headers.insert("Permissions-Policy", value);
            }
        }

        // Cross-Origin Embedder Policy
        if let Some(coep) = &self.config.cross_origin_embedder_policy {
            if let Ok(value) = HeaderValue::from_str(coep) {
                headers.insert("Cross-Origin-Embedder-Policy", value);
            }
        }

        // Cross-Origin Opener Policy
        if let Some(coop) = &self.config.cross_origin_opener_policy {
            if let Ok(value) = HeaderValue::from_str(coop) {
                headers.insert("Cross-Origin-Opener-Policy", value);
            }
        }

        // Cross-Origin Resource Policy
        if let Some(corp) = &self.config.cross_origin_resource_policy {
            if let Ok(value) = HeaderValue::from_str(corp) {
                headers.insert("Cross-Origin-Resource-Policy", value);
            }
        }

        // X-DNS-Prefetch-Control
        if let Some(xdpc) = &self.config.x_dns_prefetch_control {
            if let Ok(value) = HeaderValue::from_str(xdpc) {
                headers.insert("X-DNS-Prefetch-Control", value);
            }
        }

        // X-Download-Options
        if let Some(xdo) = &self.config.x_download_options {
            if let Ok(value) = HeaderValue::from_str(xdo) {
                headers.insert("X-Download-Options", value);
            }
        }

        // X-Permitted-Cross-Domain-Policies
        if let Some(xpcdp) = &self.config.x_permitted_cross_domain_policies {
            if let Ok(value) = HeaderValue::from_str(xpcdp) {
                headers.insert("X-Permitted-Cross-Domain-Policies", value);
            }
        }

        // Expect-CT
        if let Some(ect) = &self.config.expect_ct {
            if let Ok(value) = HeaderValue::from_str(ect) {
                headers.insert("Expect-CT", value);
            }
        }

        // Origin-Agent-Cluster
        if let Some(oac) = &self.config.origin_agent_cluster {
            if let Ok(value) = HeaderValue::from_str(oac) {
                headers.insert("Origin-Agent-Cluster", value);
            }
        }

        // Custom headers
        for (name, value) in &self.config.custom_headers {
            if let Ok(header_value) = HeaderValue::from_str(value) {
                if let Ok(header_name) = axum::http::header::HeaderName::from_str(name) {
                    headers.insert(header_name, header_value);
                }
            }
        }
    }
}

// Axum middleware function
pub async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let middleware = SecurityHeadersMiddleware::default();
    middleware.apply_security_headers(request, next).await
}

// Custom middleware with config
pub fn create_security_headers_middleware(config: SecurityHeadersConfig) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> {
    let middleware = SecurityHeadersMiddleware::new(config);
    
    move |request: Request, next: Next| {
        let middleware = middleware.clone();
        Box::pin(async move {
            middleware.apply_security_headers(request, next).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Method, routing::get, Router};
    use chrono::{Duration, Utc};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_csp_violation_store_records_and_dashboard_aggregations() {
        let store = InMemoryCspViolationStore::default();
        let now = Utc::now();

        store
            .record_violation(CspViolation {
                directive: "script-src".to_string(),
                blocked_uri: "https://cdn.example.net/app.js".to_string(),
                document_uri: "https://app.example.com".to_string(),
                source_file: Some("/src/app.tsx".to_string()),
                line_number: Some(27),
                violated_at: now - Duration::days(1),
                user_agent: Some("Mozilla/5.0".to_string()),
            })
            .await
            .unwrap();

        store
            .record_violation(CspViolation {
                directive: "script-src".to_string(),
                blocked_uri: "https://cdn.example.net/app.js".to_string(),
                document_uri: "https://app.example.com/checkout".to_string(),
                source_file: Some("/src/checkout.tsx".to_string()),
                line_number: Some(44),
                violated_at: now - Duration::hours(3),
                user_agent: Some("Mozilla/5.0".to_string()),
            })
            .await
            .unwrap();

        store
            .record_violation(CspViolation {
                directive: "img-src".to_string(),
                blocked_uri: "https://images.example.com/logo.png".to_string(),
                document_uri: "https://app.example.com".to_string(),
                source_file: Some("/src/header.tsx".to_string()),
                line_number: Some(15),
                violated_at: now - Duration::hours(1),
                user_agent: Some("Mozilla/5.0".to_string()),
            })
            .await
            .unwrap();

        let violations = store.list_violations(&CspViolationFilter::default()).await.unwrap();
        assert_eq!(violations.len(), 3);

        let dashboard = store.get_dashboard_aggregations(None).await.unwrap();
        assert!(dashboard.violations_by_directive.iter().any(|entry| entry.directive == "script-src" && entry.count == 2));
        assert!(dashboard.top_blocked_uris.iter().any(|entry| entry.blocked_uri == "https://cdn.example.net/app.js"));
        assert!(!dashboard.violations_over_time.is_empty());
    }

    #[test]
    fn test_csp_policy_graduation_check_recommends_caution_for_spiky_policy() {
        let now = Utc::now();
        let violations = vec![
            CspViolation {
                directive: "script-src".to_string(),
                blocked_uri: "https://cdn.example.net/app.js".to_string(),
                document_uri: "https://app.example.com".to_string(),
                source_file: Some("/src/app.tsx".to_string()),
                line_number: Some(27),
                violated_at: now - Duration::days(1),
                user_agent: Some("Mozilla/5.0".to_string()),
            },
            CspViolation {
                directive: "script-src".to_string(),
                blocked_uri: "https://cdn.example.net/app.js".to_string(),
                document_uri: "https://app.example.com/checkout".to_string(),
                source_file: Some("/src/checkout.tsx".to_string()),
                line_number: Some(44),
                violated_at: now - Duration::hours(3),
                user_agent: Some("Mozilla/5.0".to_string()),
            },
            CspViolation {
                directive: "style-src".to_string(),
                blocked_uri: "https://fonts.example.com/font.css".to_string(),
                document_uri: "https://app.example.com".to_string(),
                source_file: Some("/src/styles.css".to_string()),
                line_number: Some(4),
                violated_at: now - Duration::hours(2),
                user_agent: Some("Mozilla/5.0".to_string()),
            },
        ];

        let recommendation = CspPolicyGraduationCheck::new(violations, 30).evaluate(now);
        assert!(!recommendation.safe_to_enforce);
        assert!(recommendation.reason.contains("CSP violations"));
    }

    #[tokio::test]
    async fn test_csp_routes_accept_violation_reports() {
        let store = Arc::new(InMemoryCspViolationStore::default());
        let app = build_csp_routes(store.clone());

        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/v1/security/csp-violations")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"directive":"script-src","blocked_uri":"https://cdn.example.net/app.js","document_uri":"https://app.example.com","source_file":"/src/app.tsx","line_number":27,"violated_at":"2026-07-25T10:00:00Z","user_agent":"Mozilla/5.0"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let violations = store.list_violations(&CspViolationFilter::default()).await.unwrap();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_log_alerter_emits_spike_alerts() {
        let now = Utc::now();
        let previous = vec![CspViolation {
            directive: "img-src".to_string(),
            blocked_uri: "https://images.example.com/logo.png".to_string(),
            document_uri: "https://app.example.com".to_string(),
            source_file: Some("/src/header.tsx".to_string()),
            line_number: Some(15),
            violated_at: now - Duration::days(10),
            user_agent: Some("Mozilla/5.0".to_string()),
        }];
        let current = vec![
            previous[0].clone(),
            CspViolation {
                directive: "script-src".to_string(),
                blocked_uri: "https://cdn.example.net/app.js".to_string(),
                document_uri: "https://app.example.com".to_string(),
                source_file: Some("/src/app.tsx".to_string()),
                line_number: Some(27),
                violated_at: now - Duration::days(1),
                user_agent: Some("Mozilla/5.0".to_string()),
            },
        ];

        let alerts = LogAlerter::new().analyze_alerts(&current, &previous, now);
        assert!(alerts.iter().any(|alert| alert.severity == "warning"));
    }

    #[tokio::test]
    async fn test_default_security_headers() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, World!" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Check that security headers are present
        assert!(response.headers().contains_key("Content-Security-Policy"));
        assert!(response.headers().contains_key("X-Frame-Options"));
        assert!(response.headers().contains_key("X-Content-Type-Options"));
        assert!(response.headers().contains_key("X-XSS-Protection"));
        assert!(response.headers().contains_key("Referrer-Policy"));
    }

    #[test]
    fn test_csp_builder() {
        let csp = CspBuilder::new()
            .default_src(&["'self'"])
            .script_src(&["'self'", "'unsafe-inline'"])
            .style_src(&["'self'", "'unsafe-inline'"])
            .img_src(&["'self'", "data:", "https:"])
            .connect_src(&["'self'"])
            .frame_ancestors(&["'none'"])
            .build();

        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_security_headers_config() {
        let config = SecurityHeadersConfig::development();
        assert!(config.content_security_policy.is_some());
        assert!(config.strict_transport_security.is_none()); // Disabled in development

        let minimal = SecurityHeadersConfig::minimal();
        assert!(minimal.content_security_policy.is_none());
        assert!(minimal.strict_transport_security.is_some());
    }

    #[test]
    fn test_custom_headers() {
        let config = SecurityHeadersConfig::new()
            .with_custom_header("X-Custom-Header", "custom-value")
            .with_csp("default-src 'self'");

        assert_eq!(config.custom_headers.get("X-Custom-Header"), Some(&"custom-value".to_string()));
        assert_eq!(config.content_security_policy, Some("default-src 'self'".to_string()));
    }

    #[test]
    fn test_csp_builder_complex() {
        let csp = CspBuilder::new()
            .default_src(&["'self'"])
            .script_src(&["'self'", "https://cdn.example.com"])
            .style_src(&["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"])
            .font_src(&["'self'", "https://fonts.gstatic.com"])
            .img_src(&["'self'", "data:", "https:", "blob:"])
            .connect_src(&["'self'", "https://api.example.com"])
            .frame_ancestors(&["'none'"])
            .base_uri(&["'self'"])
            .form_action(&["'self'"])
            .upgrade_insecure_requests()
            .block_all_mixed_content()
            .custom_directive("report-uri", &["/csp-report"])
            .build();

        assert!(csp.contains("upgrade-insecure-requests"));
        assert!(csp.contains("block-all-mixed-content"));
        assert!(csp.contains("report-uri /csp-report"));
        assert!(csp.contains("font-src 'self' https://fonts.gstatic.com"));
    }
}
