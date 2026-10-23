//! # Smart Response Analyzer & Payload Injection Engine
//!
//! This module implements two cooperating subsystems:
//!
//! ## 1. Response Anomaly Analyzer
//! Inspects every HTTP response for known vulnerability signatures:
//! - SQL / NoSQL / ORM error messages leaking from backends
//! - Server-side template injection (SSTI) indicators
//! - Stack traces and debug output
//! - Sensitive file exposure (`.env`, `.git`, `wp-config`, etc.)
//! - Security-header absence on 200 responses
//! - Unexpected 2xx on probed sensitive paths
//!
//! ## 2. Payload Injection Engine
//! Dynamically mutates outgoing request URLs with probing payloads:
//! - Path traversal sequences
//! - SQLi / XSS canary strings (detection-only — not destructive)
//! - Common sensitive path probing (`/.env`, `/.git/HEAD`, `/admin`, …)
//! - Header injection canaries (`X-Forwarded-For`, `X-Original-URL`)
//!
//! All findings are accumulated in a lock-free concurrent sink and written
//! to `scan_results.json` at process exit.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use reqwest::Url;
use tokio_util::sync::CancellationToken;

use crate::client::ClientPool;

// ─────────────────────────────────────────────────────────────────────────────
// Signature tables (compiled at startup as plain string slices)
// ─────────────────────────────────────────────────────────────────────────────

/// SQL / DB error patterns — presence in a response body indicates a potential
/// SQL injection sink or misconfigured error handling.
static SQL_ERRORS: &[&str] = &[
    // MySQL / MariaDB
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "warning: mysql_",
    "supplied argument is not a valid mysql",
    "call to a member function",
    // PostgreSQL
    "pg_query(): query failed",
    "pg_exec() query failed",
    "pgsql error",
    "psql error",
    // Oracle
    "ora-00933",
    "ora-01756",
    "ora-00907",
    "ora-00942",
    "oracle error",
    "oci_",
    // MSSQL
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft jet database engine",
    "microsoft ole db provider",
    "microsoft odbc",
    "mssql_",
    "sqlsrv_",
    // SQLite
    "sqlite_",
    "sqlite error",
    "sqlite3_",
    "[sqlite]",
    // Generic
    "sql syntax.*mysql",
    "unrecognized token",
    "syntax error in",
    "pdoexception",
    "odbc_exec()",
    "db2_",
    "jdbc error",
    "java.sql.sqlexception",
    "org.hibernate",
    "javax.persistence",
];

/// Server-side template injection indicators.
static SSTI_INDICATORS: &[&str] = &[
    "{{7*7}}",
    "${7*7}",
    "freemarker template error",
    "velocity error",
    "twig_error",
    "jinja2 exceptions",
    "smartyexception",
    "template compilation failed",
    "mako template",
];

/// Stack trace / debug output patterns.
static STACKTRACE_PATTERNS: &[&str] = &[
    "at java.",
    "at org.",
    "at com.",
    "at sun.",
    "traceback (most recent call last)",
    "file \".py\", line",
    "syntaxerror:",
    "nameerror:",
    "attributeerror:",
    "runtimeerror:",
    "panic: runtime error",
    "goroutine ",
    "runtime error: index out of range",
    "fatal error: runtime",
    "#0  0x", // GDB / C++ stack frame
    "segmentation fault",
    "null pointer exception",
    "nullpointerexception",
    "system.nullreferenceexception",
    "unhandled exception",
    "application error",
    "laravel framework error",
    "whoops! there was an error",
    "symfony exception",
    "rails application error",
    "activerecord::",
    "actionview::template::error",
];

/// Sensitive content that should never appear in a response body.
static SENSITIVE_CONTENT: &[&str] = &[
    // Environment / config leaks
    "db_password",
    "database_url",
    "secret_key",
    "aws_access_key_id",
    "aws_secret_access_key",
    "s3_bucket",
    "private_key",
    "api_key=",
    "apikey=",
    "password=",
    "passwd=",
    "secret=",
    // Git / VCS internals
    "ref: refs/heads/", // .git/HEAD content
    "[core]",           // .git/config section
    "repositoryformatversion",
    // PHP source / config leaks
    "<?php",
    "define('db_password'",
    "define('db_name'",
    // AWS metadata
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    // JWT / token patterns
    "eyj", // base64 JWT header prefix
];

// ─────────────────────────────────────────────────────────────────────────────
// Probe payload tables
// ─────────────────────────────────────────────────────────────────────────────

/// Sensitive path probes appended to the base URL.
pub static SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.git/HEAD",
    "/.git/config",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/database.yml",
    "/settings.py",
    "/local_settings.py",
    "/secrets.yml",
    "/application.yml",
    "/app/config/parameters.yml",
    "/web.config",
    "/appsettings.json",
    "/phpinfo.php",
    "/info.php",
    "/admin",
    "/admin/",
    "/administrator",
    "/phpmyadmin",
    "/adminer.php",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/beans",
    "/.DS_Store",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/site.tar.gz",
    "/backup.zip",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/serverinfo",
    "/server-status",
    "/server-info",
    "/_profiler",
    "/__debug__/",
    "/graphql",
    "/graphiql",
    "/.well-known/security.txt",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v1/swagger.json",
    "/api/swagger.json",
];

/// Path traversal sequences for query parameter injection.
static PATH_TRAVERSAL: &[&str] = &[
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "..%2fetc%2fpasswd",
    "..%5cetc%5cpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "%2fetc%2fpasswd",
];

/// SQLi canary strings — designed to trigger error responses, not damage data.
static SQLI_CANARIES: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT SLEEP(0)--",
    "' AND SLEEP(0)--",
];

/// XSS canary strings — non-destructive detection only.
static XSS_CANARIES: &[&str] = &[
    "<script>astra</script>",
    "\"><script>astra</script>",
    "';alert('astra');//",
    "<img src=x onerror=void(0)>",
    "{{astra}}", // template injection probe
    "${astra}",
];

// ─────────────────────────────────────────────────────────────────────────────
// Finding types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Finding {
    /// Full URL that produced this finding.
    pub url: String,
    /// HTTP status code of the response.
    pub status: u16,
    /// Category of finding.
    pub category: FindingCategory,
    /// Human-readable description.
    pub detail: String,
    /// Snippet of matching content (truncated to 200 chars).
    pub evidence: String,
    /// UTC epoch second when finding was recorded.
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone)]
pub enum FindingCategory {
    SqlError,
    SstiIndicator,
    StackTrace,
    SensitiveContent,
    SensitivePath,
    PathTraversal,
    SqlInjectionReflected,
    XssReflected,
    MissingSecurityHeaders,
    UnexpectedSuccess,
}

impl FindingCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SqlError => "SQL_ERROR",
            Self::SstiIndicator => "SSTI_INDICATOR",
            Self::StackTrace => "STACK_TRACE",
            Self::SensitiveContent => "SENSITIVE_CONTENT",
            Self::SensitivePath => "SENSITIVE_PATH",
            Self::PathTraversal => "PATH_TRAVERSAL",
            Self::SqlInjectionReflected => "SQLI_REFLECTED",
            Self::XssReflected => "XSS_REFLECTED",
            Self::MissingSecurityHeaders => "MISSING_SECURITY_HEADERS",
            Self::UnexpectedSuccess => "UNEXPECTED_SUCCESS",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe descriptor — a single mutated request variant to fire
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Probe {
    /// The URL to request (base URL + injected path or parameters).
    pub url: Url,
    /// Optional extra headers to attach (e.g. header injection).
    pub extra_headers: Vec<(String, String)>,
    /// The probe payload string for reflection matching.
    pub payload: String,
    /// Category expected if a match is found.
    pub category: ProbeKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProbeKind {
    SensitivePath,
    PathTraversal,
    SqliCanary,
    XssCanary,
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner config
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Enable passive response analysis (signature matching on every response).
    pub passive_scan: bool,
    /// Enable active probe injection (path traversal, SQLi canaries, etc.).
    pub active_probe: bool,
    /// Probe sensitive paths (/.env, /.git/HEAD, etc.).
    pub probe_paths: bool,
    /// Inject SQLi canaries in query parameters.
    pub probe_sqli: bool,
    /// Inject XSS canaries in query parameters.
    pub probe_xss: bool,
    /// Check for missing security headers (CSP, X-Frame-Options, etc.).
    pub check_headers: bool,
    /// Output file path for the JSON report.
    pub output_path: String,
    /// Maximum body bytes to scan (to avoid scanning huge binary downloads).
    pub max_body_scan_bytes: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            passive_scan: false,
            active_probe: false,
            probe_paths: false,
            probe_sqli: false,
            probe_xss: false,
            check_headers: false,
            output_path: "scan_results.json".into(),
            max_body_scan_bytes: 128 * 1024, // 128 KB
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Concurrent finding sink
// ─────────────────────────────────────────────────────────────────────────────

pub struct ScanSink {
    findings: Mutex<Vec<Finding>>,
    pub total_analyzed: AtomicU64,
    pub total_findings: AtomicU64,
}

impl ScanSink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            findings: Mutex::new(Vec::new()),
            total_analyzed: AtomicU64::new(0),
            total_findings: AtomicU64::new(0),
        })
    }

    /// Record a finding (lock is held only briefly for Vec push).
    pub fn record(&self, finding: Finding) {
        self.total_findings.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.findings.lock() {
            guard.push(finding);
        }
    }

    /// Return a snapshot of all findings sorted by timestamp.
    pub fn get_findings_sorted(&self) -> Vec<Finding> {
        let guard = self.findings.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = guard.clone();
        v.sort_by_key(|f| f.timestamp_secs);
        v
    }

    /// Drain all findings sorted by timestamp for writing.
    #[allow(dead_code)]
    pub fn drain_sorted(&self) -> Vec<Finding> {
        let mut guard = self.findings.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = std::mem::take(&mut *guard);
        v.sort_by_key(|f| f.timestamp_secs);
        v
    }

    pub fn finding_count(&self) -> u64 {
        self.total_findings.load(Ordering::Relaxed)
    }
}

impl Default for ScanSink {
    fn default() -> Self {
        Self {
            findings: Mutex::new(Vec::new()),
            total_analyzed: AtomicU64::new(0),
            total_findings: AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core analysis API
// ─────────────────────────────────────────────────────────────────────────────

/// Perform passive signature analysis on a completed response.
///
/// `url`         — the request URL  
/// `status`      — HTTP status code  
/// `body`        — raw response body bytes (may be truncated by caller)  
/// `resp_headers`— response header map for security-header checks  
/// `cfg`         — scanner configuration  
/// `sink`        — thread-safe finding collector  
pub fn analyze_response(
    url: &str,
    status: u16,
    body: &[u8],
    resp_headers: &reqwest::header::HeaderMap,
    cfg: &ScannerConfig,
    sink: &Arc<ScanSink>,
) {
    sink.total_analyzed.fetch_add(1, Ordering::Relaxed);

    let body_str = String::from_utf8_lossy(&body[..body.len().min(cfg.max_body_scan_bytes)]);
    let body_lower = body_str.to_lowercase();
    let now = epoch_secs();

    // ── SQL error detection ─────────────────────────────────────────────────
    for &sig in SQL_ERRORS {
        if body_lower.contains(sig) {
            let evidence = extract_context(&body_str, sig, 200);
            sink.record(Finding {
                url: url.to_string(),
                status,
                category: FindingCategory::SqlError,
                detail: format!("SQL error signature matched: '{sig}'"),
                evidence,
                timestamp_secs: now,
            });
            break; // one finding per response for this category
        }
    }

    // ── SSTI indicators ─────────────────────────────────────────────────────
    for &sig in SSTI_INDICATORS {
        if body_lower.contains(sig) {
            let evidence = extract_context(&body_str, sig, 200);
            sink.record(Finding {
                url: url.to_string(),
                status,
                category: FindingCategory::SstiIndicator,
                detail: format!("SSTI indicator matched: '{sig}'"),
                evidence,
                timestamp_secs: now,
            });
            break;
        }
    }

    // ── Stack trace / debug leak ─────────────────────────────────────────────
    for &sig in STACKTRACE_PATTERNS {
        if body_lower.contains(sig) {
            let evidence = extract_context(&body_str, sig, 200);
            sink.record(Finding {
                url: url.to_string(),
                status,
                category: FindingCategory::StackTrace,
                detail: format!("Stack trace / debug output detected: '{sig}'"),
                evidence,
                timestamp_secs: now,
            });
            break;
        }
    }

    // ── Sensitive content leak ───────────────────────────────────────────────
    for &sig in SENSITIVE_CONTENT {
        if body_lower.contains(sig) {
            let evidence = extract_context(&body_str, sig, 200);
            sink.record(Finding {
                url: url.to_string(),
                status,
                category: FindingCategory::SensitiveContent,
                detail: format!("Sensitive content pattern detected: '{sig}'"),
                evidence,
                timestamp_secs: now,
            });
            break;
        }
    }

    // ── Security header audit (passive, only on 200 responses) ───────────────
    if cfg.check_headers && status == 200 {
        check_security_headers(url, resp_headers, sink, now);
    }

    // ── Unexpected 2xx on anomalous content types or very small bodies ───────
    if (200..=299).contains(&status) && body.len() < 64 && body.len() > 0 {
        // Very small 200 body — might be a leak / sentinel file
        sink.record(Finding {
            url: url.to_string(),
            status,
            category: FindingCategory::UnexpectedSuccess,
            detail: format!(
                "Unexpectedly small 2xx response ({} bytes) — possible sentinel file",
                body.len()
            ),
            evidence: body_str.chars().take(200).collect(),
            timestamp_secs: now,
        });
    }
}

/// Analyse a probe response — checks for payload reflection and expected-path surprises.
pub fn analyze_probe_response(
    probe: &Probe,
    status: u16,
    body: &[u8],
    resp_headers: &reqwest::header::HeaderMap,
    cfg: &ScannerConfig,
    sink: &Arc<ScanSink>,
) {
    sink.total_analyzed.fetch_add(1, Ordering::Relaxed);
    let url_str = probe.url.as_str();
    let body_str = String::from_utf8_lossy(&body[..body.len().min(cfg.max_body_scan_bytes)]);
    let body_lower = body_str.to_lowercase();
    let now = epoch_secs();

    match probe.category {
        ProbeKind::SensitivePath => {
            // Any 2xx on a sensitive path is a finding
            if (200..=299).contains(&status) {
                sink.record(Finding {
                    url: url_str.to_string(),
                    status,
                    category: FindingCategory::SensitivePath,
                    detail: format!("Sensitive path returned HTTP {status}: '{}'", probe.payload),
                    evidence: body_str.chars().take(300).collect(),
                    timestamp_secs: now,
                });
            }
        }
        ProbeKind::PathTraversal => {
            // Successful traversal — look for /etc/passwd or Windows hosts markers
            if body_lower.contains("root:")
                || body_lower.contains("localhost") && body_lower.contains("127.0.0.1")
            {
                sink.record(Finding {
                    url: url_str.to_string(),
                    status,
                    category: FindingCategory::PathTraversal,
                    detail: format!("Path traversal succeeded with payload: '{}'", probe.payload),
                    evidence: body_str.chars().take(200).collect(),
                    timestamp_secs: now,
                });
            }
        }
        ProbeKind::SqliCanary => {
            // Check for SQL errors in response (payload was reflected into query)
            let found_sql = SQL_ERRORS.iter().any(|sig| body_lower.contains(sig));
            if found_sql || (status == 500 && body.len() < 4096) {
                let evidence = body_str.chars().take(300).collect();
                sink.record(Finding {
                    url: url_str.to_string(),
                    status,
                    category: FindingCategory::SqlInjectionReflected,
                    detail: format!(
                        "SQLi canary '{payload}' produced error response (HTTP {status})",
                        payload = probe.payload
                    ),
                    evidence,
                    timestamp_secs: now,
                });
            }
        }
        ProbeKind::XssCanary => {
            // Check if our canary string was reflected unescaped
            if body_str.contains(&probe.payload) {
                let evidence = extract_context(&body_str, &probe.payload, 200);
                sink.record(Finding {
                    url: url_str.to_string(),
                    status,
                    category: FindingCategory::XssReflected,
                    detail: format!(
                        "XSS canary '{}' reflected unescaped in response",
                        probe.payload
                    ),
                    evidence,
                    timestamp_secs: now,
                });
            }
        }
    }

    // Always run passive analysis on probe responses too
    if cfg.passive_scan {
        analyze_response(url_str, status, body, resp_headers, cfg, sink);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a list of probes to fire for a given base URL, based on config.
pub fn generate_probes(base_url: &Url, cfg: &ScannerConfig) -> Vec<Probe> {
    let mut probes = Vec::new();

    if cfg.probe_paths {
        for &path in SENSITIVE_PATHS {
            if let Ok(url) = build_path_url(base_url, path) {
                probes.push(Probe {
                    url,
                    extra_headers: vec![],
                    payload: path.to_string(),
                    category: ProbeKind::SensitivePath,
                });
            }
        }
    }

    if cfg.active_probe {
        // Path traversal via common query parameters
        for &traversal in PATH_TRAVERSAL {
            for &param in &["file", "path", "page", "include", "doc", "load", "q", "url"] {
                if let Ok(url) = inject_query_param(base_url, param, traversal) {
                    probes.push(Probe {
                        url,
                        extra_headers: vec![],
                        payload: traversal.to_string(),
                        category: ProbeKind::PathTraversal,
                    });
                }
            }
        }

        // SQLi canaries on common parameters
        if cfg.probe_sqli {
            for &canary in SQLI_CANARIES {
                for &param in &["id", "q", "search", "query", "user", "name", "cat", "page"] {
                    if let Ok(url) = inject_query_param(base_url, param, canary) {
                        probes.push(Probe {
                            url,
                            extra_headers: vec![],
                            payload: canary.to_string(),
                            category: ProbeKind::SqliCanary,
                        });
                    }
                }
            }
        }

        // XSS canaries
        if cfg.probe_xss {
            for &canary in XSS_CANARIES {
                for &param in &["q", "search", "name", "msg", "comment", "input"] {
                    if let Ok(url) = inject_query_param(base_url, param, canary) {
                        probes.push(Probe {
                            url,
                            extra_headers: vec![],
                            payload: canary.to_string(),
                            category: ProbeKind::XssCanary,
                        });
                    }
                }
            }
        }
    }

    probes
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON report writer
// ─────────────────────────────────────────────────────────────────────────────

/// Write all findings to a JSON file at `output_path`.
/// Uses hand-rolled JSON serialisation to avoid pulling in `serde`.
pub fn write_report(sink: &Arc<ScanSink>, output_path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let findings = sink.get_findings_sorted();
    let total = findings.len();

    let path = Path::new(output_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = std::fs::File::create(path)?;

    // Build summary stats
    let mut by_category: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        *by_category.entry(f.category.as_str()).or_default() += 1;
    }

    writeln!(file, "{{")?;
    writeln!(file, "  \"generated_at\": \"{}\",", iso8601(epoch_secs()))?;
    writeln!(file, "  \"total_findings\": {},", total)?;
    writeln!(
        file,
        "  \"total_analyzed\": {},",
        sink.total_analyzed.load(Ordering::Relaxed)
    )?;

    // Category summary
    writeln!(file, "  \"by_category\": {{")?;
    let cats: Vec<_> = by_category.iter().collect();
    for (i, (cat, count)) in cats.iter().enumerate() {
        let comma = if i + 1 < cats.len() { "," } else { "" };
        writeln!(file, "    \"{cat}\": {count}{comma}")?;
    }
    writeln!(file, "  }},")?;

    // Full findings array
    writeln!(file, "  \"findings\": [")?;
    for (i, f) in findings.iter().enumerate() {
        let comma = if i + 1 < total { "," } else { "" };
        writeln!(file, "    {{")?;
        writeln!(file, "      \"url\": \"{}\",", json_escape(&f.url))?;
        writeln!(file, "      \"status\": {},", f.status)?;
        writeln!(file, "      \"category\": \"{}\",", f.category.as_str())?;
        writeln!(file, "      \"detail\": \"{}\",", json_escape(&f.detail))?;
        writeln!(
            file,
            "      \"evidence\": \"{}\",",
            json_escape(&f.evidence)
        )?;
        writeln!(
            file,
            "      \"timestamp\": \"{}\"",
            iso8601(f.timestamp_secs)
        )?;
        writeln!(file, "    }}{comma}")?;
    }
    writeln!(file, "  ]")?;
    writeln!(file, "}}")?;

    Ok(())
}

/// Print a formatted terminal summary of vulnerability findings.
pub fn print_scan_summary(sink: &Arc<ScanSink>, output_path: &str) {
    use colored::Colorize;
    let findings = sink.get_findings_sorted();
    let n = sink.finding_count();
    let analyzed = sink.total_analyzed.load(Ordering::Relaxed);

    println!(
        "\n{}",
        "── Security & Vulnerability Scan Report ─────────────────────────────".bright_black()
    );
    println!(
        "  {:<24} {}",
        "Responses Analyzed:".bright_white().bold(),
        format!("{analyzed}").bright_cyan()
    );
    println!(
        "  {:<24} {}",
        "Findings Detected:".bright_white().bold(),
        if n > 0 {
            format!("{n} issue(s)").bright_red().bold()
        } else {
            "0 (clean)".bright_green().bold()
        }
    );
    println!(
        "  {:<24} {}",
        "Report File:".bright_white().bold(),
        output_path.bright_yellow()
    );

    if n > 0 {
        let mut by_cat: HashMap<&str, usize> = HashMap::new();
        for f in &findings {
            *by_cat.entry(f.category.as_str()).or_default() += 1;
        }
        println!("\n  {}", "Findings Breakdown:".bright_white().bold());
        let mut sorted_cats: Vec<_> = by_cat.into_iter().collect();
        sorted_cats.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        for (cat, count) in sorted_cats {
            println!(
                "    • {:<26} {}",
                cat.bright_red(),
                count.to_string().bright_white().bold()
            );
        }
    }
    println!();
}

/// Execute all active probes against the target using the client pool.
pub async fn run_active_probes(
    base_url: &Url,
    cfg: &Arc<ScannerConfig>,
    sink: &Arc<ScanSink>,
    client_pool: &Arc<ClientPool>,
    cancel_token: &CancellationToken,
) {
    let probes = generate_probes(base_url, cfg);
    if probes.is_empty() {
        return;
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(16));
    let mut handles = Vec::with_capacity(probes.len());

    for probe in probes {
        if cancel_token.is_cancelled() {
            break;
        }

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };

        let (client, _) = client_pool.get_client_for_request(None);
        let cfg_clone = Arc::clone(cfg);
        let sink_clone = Arc::clone(sink);
        let cancel = cancel_token.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if cancel.is_cancelled() {
                return;
            }

            let mut req = client.get(probe.url.clone());
            for (k, v) in &probe.extra_headers {
                req = req.header(k, v);
            }

            if let Ok(resp) = req.send().await {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
                analyze_probe_response(&probe, status, &body, &headers, &cfg_clone, &sink_clone);
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Check for commonly expected security response headers and flag absences.
fn check_security_headers(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    sink: &Arc<ScanSink>,
    now: u64,
) {
    let required = [
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-xss-protection", "X-XSS-Protection"),
        (
            "strict-transport-security",
            "Strict-Transport-Security (HSTS)",
        ),
        ("content-security-policy", "Content-Security-Policy (CSP)"),
    ];

    let mut missing = Vec::new();
    for (header_name, display_name) in &required {
        if !headers.contains_key(*header_name) {
            missing.push(*display_name);
        }
    }

    if !missing.is_empty() {
        sink.record(Finding {
            url: url.to_string(),
            status: 200,
            category: FindingCategory::MissingSecurityHeaders,
            detail: format!("Missing security headers: {}", missing.join(", ")),
            evidence: String::new(),
            timestamp_secs: now,
        });
    }
}

/// Build a URL by replacing the path component.
fn build_path_url(base: &Url, new_path: &str) -> Result<Url, ()> {
    let mut url = base.clone();
    url.set_path(new_path);
    url.set_query(None);
    Ok(url)
}

/// Build a URL by appending/replacing a single query parameter.
fn inject_query_param(base: &Url, param: &str, value: &str) -> Result<Url, ()> {
    let mut url = base.clone();
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair(param, value);
    }
    Ok(url)
}

/// Extract a short context window around the first occurrence of `needle`.
fn extract_context(haystack: &str, needle: &str, window: usize) -> String {
    let lower = haystack.to_lowercase();
    let lower_needle = needle.to_lowercase();
    if let Some(pos) = lower.find(lower_needle.as_str()) {
        let start = pos.saturating_sub(40);
        let end = (pos + needle.len() + window).min(haystack.len());
        haystack[start..end].chars().take(window).collect()
    } else {
        haystack.chars().take(window).collect()
    }
}

/// Escape a string for embedding in a JSON string value.
fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c if (c as u32) < 0x20 => vec![],
            c => vec![c],
        })
        .collect()
}

/// Current UTC epoch in seconds (no external deps).
fn epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format epoch seconds as ISO-8601 UTC string (approximate Gregorian calendar).
fn iso8601(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let total_days = secs / 86400;
    let mut year = 1970u64;
    let mut remaining = total_days;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if remaining < dy {
            break;
        }
        remaining -= dy;
        year += 1;
    }
    let mdays: [u64; 12] = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for d in mdays {
        if remaining < d {
            break;
        }
        remaining -= d;
        month += 1;
    }
    let day = remaining + 1;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[inline]
fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
