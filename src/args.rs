use clap::Parser;
use std::path::PathBuf;

/// Astra - Extreme-Performance HTTP Load Generator & Benchmarking Tool.
///
/// Designed to generate up to 1,000,000+ requests per second with
/// microsecond precision, lock-free metrics, and low resource overhead.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "astra",
    author = "Astra Contributors",
    version,
    about = "High-performance HTTP load tester and benchmarking engine.",
    long_about = "Astra is an extreme-performance HTTP load tester built in Rust.\n\
                  Supports millions of requests per second, multi-thousand concurrent connections,\n\
                  accurate HDR latency distribution, automatic system tuning, and real-time live monitoring."
)]
pub struct Args {
    /// Target URL to test (e.g. http://127.0.0.1:8080/health).
    #[arg(long, value_name = "URL")]
    pub url: String,

    /// Target requests per second (0 = unlimited / maximum possible throughput).
    #[arg(long, default_value_t = 0, value_name = "COUNT")]
    pub rps: u64,

    /// Test duration in seconds (0 = unlimited when --requests is specified).
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    pub duration: u64,

    /// Total number of requests to execute (e.g. -n 1000000). Benchmark stops when reached.
    #[arg(long, short = 'n', value_name = "COUNT")]
    pub requests: Option<u64>,

    /// Number of concurrent workers / connections.
    #[arg(long, short = 'c', default_value_t = 50, value_name = "NUM")]
    pub concurrency: usize,

    /// Number of Tokio runtime worker threads (0 = one per available CPU core).
    /// Uses a work-stealing multi-threaded scheduler.
    #[arg(long, default_value_t = 0, value_name = "NUM")]
    pub threads: usize,

    /// Pin every Tokio worker thread to a dedicated CPU core (Linux/Unix).
    /// Disabled by default; may improve cache locality on isolated benchmark hosts.
    #[arg(long)]
    pub pin_cores: bool,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub timeout: u64,

    /// HTTP request method (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS).
    #[arg(long, short = 'X', default_value = "GET", value_name = "METHOD")]
    pub method: String,

    /// Custom HTTP header to include (can be specified multiple times, e.g. -H "Authorization: Bearer xyz").
    #[arg(long = "header", short = 'H', value_name = "KEY:VALUE")]
    pub headers: Vec<String>,

    /// HTTP request body content.
    #[arg(long, short = 'd', value_name = "STRING")]
    pub body: Option<String>,

    /// Read HTTP request body from a file.
    #[arg(long, value_name = "PATH")]
    pub body_file: Option<PathBuf>,

    /// Force/prefer HTTP/2 connections.
    #[arg(long)]
    pub http2: bool,

    /// Disable HTTP Keep-Alive (force closing connections).
    #[arg(long)]
    pub disable_keepalive: bool,

    /// Allow insecure / untrusted SSL certificates.
    #[arg(long, short = 'k')]
    pub insecure: bool,

    /// Disable the interactive real-time TUI progress display (useful for CI/scripting).
    #[arg(long)]
    pub no_tui: bool,

    /// Warmup duration in seconds before recording statistics.
    #[arg(long, default_value_t = 0, value_name = "SECS")]
    pub warmup: u64,

    /// Number of pipelined in-flight requests per worker.
    /// Total effective concurrency = workers × pipeline depth.
    /// Use values 10-1000 for extreme throughput against fast servers (e.g. localhost).
    #[arg(long, default_value_t = 1, value_name = "NUM")]
    pub pipeline: usize,

    /// Skip reading HTTP response bodies for maximum request throughput.
    /// Measures time-to-headers only. Best for stress-testing connection handling.
    #[arg(long)]
    pub no_body: bool,

    /// Custom proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080). Can be specified multiple times for rotation.
    #[arg(long = "proxy", value_name = "URL")]
    pub proxies: Vec<String>,

    /// Read proxy URLs from a file (one URL per line) for automatic round-robin rotation.
    /// If omitted, Astra automatically checks and loads 'proxies.txt' from the current directory if present.
    #[arg(long, value_name = "PATH")]
    pub proxy_file: Option<PathBuf>,

    /// Maximum automatic retries on connection timeout or network failure before marking as failed.
    #[arg(long, default_value_t = 3, value_name = "COUNT")]
    pub retries: usize,

    /// Base backoff time in milliseconds for exponential retry backoff (e.g. 25ms -> 50ms -> 100ms).
    #[arg(long = "retry-backoff", default_value_t = 25, value_name = "MS")]
    pub retry_backoff: u64,

    /// Socket connection timeout in seconds (helps quickly detect and skip dead proxies).
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    pub connect_timeout: u64,

    /// Cooldown duration in seconds before re-testing an unresponsive proxy.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub proxy_cooldown: u64,

    /// Number of consecutive connection failures before marking a proxy as unhealthy and skipping it.
    #[arg(long, default_value_t = 2, value_name = "COUNT")]
    pub proxy_fail_threshold: u32,

    /// Maximum request burst limit when pacing with --rps (0 = auto-smooth over 100ms window).
    #[arg(long, default_value_t = 0, value_name = "COUNT")]
    pub burst_limit: u64,

    /// Global maximum in-flight requests cap across all workers (0 = auto, based on concurrency × pipeline).
    #[arg(long, default_value_t = 0, value_name = "COUNT")]
    pub max_in_flight: usize,

    /// Maximum cap for exponential backoff in milliseconds.
    #[arg(long, default_value_t = 2000, value_name = "MS")]
    pub retry_max_backoff: u64,

    /// Comma-separated HTTP status codes to treat as transient errors and automatically retry via alternate proxies.
    #[arg(long, default_value = "429,403,500,502,503,504", value_name = "CODES")]
    pub retry_statuses: String,

    /// Disable random jitter on retry backoff (jitter is enabled by default to prevent thundering herds).
    #[arg(long)]
    pub no_jitter: bool,

    /// Fetch fresh open-source proxy lists from GitHub before starting the benchmark.
    /// Downloads from multiple public repositories, deduplicates, and writes to the proxy
    /// output file (see --proxy-output). Falls back to the existing local file on failure.
    #[arg(long)]
    pub fetch_proxies: bool,

    /// Output file path for the fetched proxy list (used with --fetch-proxies).
    /// Defaults to 'proxies.txt' in the current working directory.
    #[arg(long, default_value = "proxies.txt", value_name = "PATH")]
    pub proxy_output: std::path::PathBuf,

    // ── Evasion / Fingerprint Randomisation ─────────────────────────────────
    /// Enable polymorphic traffic mode: randomise User-Agent, Accept-Language,
    /// Accept-Encoding, Referer, Sec-CH-UA and other browser fingerprint headers
    /// on every request to defeat static-signature WAF and rate-limit detection.
    #[arg(long)]
    pub evasion: bool,

    /// Enable polymorphic payload mode (requires --evasion): randomly distribute
    /// requests across GET, POST (JSON/form-data), and OPTIONS methods to confuse
    /// server-side traffic-analysis heuristics.
    #[arg(long)]
    pub polymorphic: bool,

    /// Probability (0–100) that a request is sent as POST when --polymorphic is active.
    #[arg(long, default_value_t = 20, value_name = "PERCENT")]
    pub post_ratio: u64,

    /// Probability (0–100) that a POST payload uses JSON format (vs form-data).
    #[arg(long, default_value_t = 60, value_name = "PERCENT")]
    pub json_ratio: u64,

    /// Probability (0–100) that a request is sent as OPTIONS when --polymorphic is active.
    #[arg(long, default_value_t = 5, value_name = "PERCENT")]
    pub options_ratio: u64,

    // ── Scanner / Vulnerability Detection ───────────────────────────────────
    /// Enable passive response analysis: scan every response body for SQL errors,
    /// stack traces, sensitive data leaks, SSTI indicators, and security header absence.
    #[arg(long)]
    pub scan: bool,

    /// Enable active probe injection: fire additional mutated requests with path
    /// traversal sequences, SQLi canaries, and XSS canaries against the target.
    /// Implies --scan. Use responsibly and only against systems you own or have permission to test.
    #[arg(long)]
    pub scan_active: bool,

    /// Probe common sensitive paths (/.env, /.git/HEAD, /admin, /actuator, etc.)
    /// Requires --scan-active.
    #[arg(long)]
    pub probe_paths: bool,

    /// Inject SQL injection canary strings into common query parameters.
    /// Requires --scan-active.
    #[arg(long)]
    pub probe_sqli: bool,

    /// Inject XSS canary strings into common query parameters.
    /// Requires --scan-active.
    #[arg(long)]
    pub probe_xss: bool,

    /// Audit response headers for missing security headers (CSP, HSTS, X-Frame-Options, etc.).
    /// Works with both passive (--scan) and active (--scan-active) modes.
    #[arg(long)]
    pub check_headers: bool,

    /// Output file path for the vulnerability scan report (JSON format).
    #[arg(long, default_value = "scan_results.json", value_name = "PATH")]
    pub scan_output: String,

    /// Maximum response body size in bytes to scan for signatures (default 128 KB).
    #[arg(long, default_value_t = 131072, value_name = "BYTES")]
    pub scan_max_body: usize,
}
