use anyhow::{Context, Result, bail};
use reqwest::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Client, Method, Proxy, Url};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::args::Args;

pub struct RequestSpec {
    pub url: Url,
    pub method: Method,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}

/// Representation of an individual proxy with dynamic health tracking,
/// adaptive blacklisting, and status-code telemetry.
pub struct ProxyEntry {
    pub id: usize,
    pub url: String,
    pub client: Client,
    pub healthy: AtomicBool,
    pub consecutive_failures: AtomicU32,
    pub total_requests: AtomicU64,
    pub total_successes: AtomicU64,
    pub total_failures: AtomicU64,
    pub status_429: AtomicU64,
    pub status_403: AtomicU64,
    pub status_5xx: AtomicU64,
    pub last_failure_at: parking_lot::RwLock<Option<Instant>>,
}

impl ProxyEntry {
    /// Determines whether the proxy is currently eligible to receive traffic.
    /// If marked unhealthy (Cooldown / Blacklist), it allows a probe request after the cooldown duration expires.
    #[inline]
    pub fn is_available(&self, cooldown: Duration, now: Instant) -> bool {
        if self.healthy.load(Ordering::Relaxed) {
            return true;
        }

        let last_fail = *self.last_failure_at.read();
        match last_fail {
            Some(t) => now.duration_since(t) >= cooldown,
            None => true,
        }
    }

    /// Record a successful 2xx request through this proxy.
    /// Resets consecutive failures and restores proxy health.
    #[inline]
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Release);
        self.total_successes.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a network connection error or timeout through this proxy.
    /// Trips the circuit breaker if consecutive failures reach the threshold.
    #[inline]
    pub fn record_network_failure(&self, threshold: u32, now: Instant) {
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        *self.last_failure_at.write() = Some(now);

        if fails >= threshold {
            self.healthy.store(false, Ordering::Release);
        }
    }

    /// Record an intercepted transient status code (429 Rate Limit, 403 Forbidden, 5xx).
    /// Tracks error categories and blacklists the proxy if repeated.
    #[inline]
    pub fn record_status_failure(&self, status: u16, threshold: u32, now: Instant) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure_at.write() = Some(now);

        match status {
            429 => {
                self.status_429.fetch_add(1, Ordering::Relaxed);
            }
            403 => {
                self.status_403.fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.status_5xx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        if fails >= threshold {
            self.healthy.store(false, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyStat {
    pub id: usize,
    pub url: String,
    pub is_healthy: bool,
    pub total_requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub status_429: u64,
    pub status_403: u64,
    pub status_5xx: u64,
}

pub struct ClientPool {
    direct_clients: Vec<Client>,
    proxies: Vec<Arc<ProxyEntry>>,
    pub spec: Arc<RequestSpec>,
    rr_counter: AtomicUsize,
    pub proxy_cooldown: Duration,
    pub proxy_fail_threshold: u32,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub retry_statuses: Vec<u16>,
    pub no_jitter: bool,
}

impl ClientPool {
    pub fn new(args: &Args, cpu_cores: usize) -> Result<Self> {
        let parsed_url =
            Url::parse(&args.url).context(format!("Failed to parse target URL '{}'", args.url))?;

        if !matches!(parsed_url.scheme(), "http" | "https") {
            bail!("Only HTTP and HTTPS target URLs are supported");
        }

        let method = Method::from_str(&args.method.to_uppercase())
            .context(format!("Invalid HTTP method '{}'", args.method))?;

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("astra/0.1.0"));

        if !args.disable_keepalive {
            headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        } else {
            headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }

        for h in &args.headers {
            if let Some((k, v)) = h.split_once(':') {
                let name = HeaderName::from_str(k.trim())
                    .context(format!("Invalid header name: '{}'", k))?;
                let val = HeaderValue::from_str(v.trim())
                    .context(format!("Invalid header value: '{}'", v))?;
                headers.insert(name, val);
            } else {
                bail!("Header must be in 'Key: Value' format: '{}'", h);
            }
        }

        let body = if let Some(ref path) = args.body_file {
            let data = std::fs::read(path)
                .context(format!("Failed to read body file '{}'", path.display()))?;
            Some(data)
        } else {
            args.body.as_ref().map(|b| b.as_bytes().to_vec())
        };

        // Parse retry status codes (e.g. 429, 403, 500, 502, 503, 504)
        let retry_statuses: Vec<u16> = args
            .retry_statuses
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();

        // Collect proxies from command line arguments and proxy file
        let mut proxy_list = Vec::new();
        for p in &args.proxies {
            let formatted = if !p.contains("://") {
                format!("http://{}", p)
            } else {
                p.clone()
            };
            proxy_list.push(formatted);
        }

        if let Some(ref path) = args.proxy_file {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            let formatted = if !trimmed.contains("://") {
                                format!("http://{}", trimmed)
                            } else {
                                trimmed.to_string()
                            };
                            proxy_list.push(formatted);
                        }
                    }
                    if proxy_list.is_empty() {
                        eprintln!(
                            "⚠️  Proxy file '{}' contains no active proxies. Proceeding with direct connection.\n",
                            path.display()
                        );
                    } else {
                        eprintln!(
                            "✓ Loaded {} proxies from '{}'.\n",
                            proxy_list.len(),
                            path.display()
                        );
                    }
                }
                Err(_) => {
                    eprintln!(
                        "⚠️  Proxy file '{}' not found. Proceeding with direct connection.\n",
                        path.display()
                    );
                }
            }
        } else if proxy_list.is_empty() {
            // Auto-detect and read 'proxies.txt' from current working directory if present
            let default_proxy_file = std::path::Path::new("proxies.txt");
            if default_proxy_file.exists() {
                if let Ok(content) = std::fs::read_to_string(default_proxy_file) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            let formatted = if !trimmed.contains("://") {
                                format!("http://{}", trimmed)
                            } else {
                                trimmed.to_string()
                            };
                            proxy_list.push(formatted);
                        }
                    }
                    if proxy_list.is_empty() {
                        eprintln!(
                            "ℹ️  'proxies.txt' found but contains no active proxies (all lines commented). Running in Direct Connection mode.\n"
                        );
                    } else {
                        eprintln!(
                            "✓ Loaded {} proxies from 'proxies.txt' for dynamic rotation & failover.\n",
                            proxy_list.len()
                        );
                    }
                }
            }
        }

        // Total in-flight requests = workers × pipeline depth
        let total_in_flight = args.concurrency.saturating_mul(args.pipeline.max(1));

        let mut direct_clients = Vec::new();
        let mut proxies = Vec::new();

        if proxy_list.is_empty() {
            // Determine optimal number of partitioned HTTP clients to avoid mutex contention.
            let pool_shards = if total_in_flight <= cpu_cores {
                1
            } else {
                ((total_in_flight + 24) / 25).clamp(2, 64.min(cpu_cores.saturating_mul(8).max(2)))
            };

            for _ in 0..pool_shards {
                direct_clients.push(build_http_client(args, None)?);
            }
        } else {
            // Create a dedicated, high-performance client for each proxy in the pool.
            for (id, proxy_str) in proxy_list.iter().enumerate() {
                let proxy = Proxy::all(proxy_str)
                    .context(format!("Failed to configure proxy '{}'", proxy_str))?;

                let client = build_http_client(args, Some(proxy)).context(format!(
                    "Failed to construct HTTP client for proxy '{}'",
                    proxy_str
                ))?;

                proxies.push(Arc::new(ProxyEntry {
                    id,
                    url: proxy_str.clone(),
                    client,
                    healthy: AtomicBool::new(true),
                    consecutive_failures: AtomicU32::new(0),
                    total_requests: AtomicU64::new(0),
                    total_successes: AtomicU64::new(0),
                    total_failures: AtomicU64::new(0),
                    status_429: AtomicU64::new(0),
                    status_403: AtomicU64::new(0),
                    status_5xx: AtomicU64::new(0),
                    last_failure_at: parking_lot::RwLock::new(None),
                }));
            }
        }

        Ok(Self {
            direct_clients,
            proxies,
            spec: Arc::new(RequestSpec {
                url: parsed_url,
                method,
                headers,
                body,
            }),
            rr_counter: AtomicUsize::new(0),
            proxy_cooldown: Duration::from_secs(args.proxy_cooldown),
            proxy_fail_threshold: args.proxy_fail_threshold,
            max_retries: args.retries,
            retry_backoff_ms: args.retry_backoff,
            max_backoff_ms: args.retry_max_backoff,
            retry_statuses,
            no_jitter: args.no_jitter,
        })
    }

    /// Check if an HTTP status code is classified as a retryable transient failure
    /// (e.g. 429 Too Many Requests, 403 Forbidden, 5xx Server Error).
    #[inline]
    pub fn is_retryable_status(&self, status: u16) -> bool {
        self.retry_statuses.contains(&status)
    }

    /// Dynamically retrieve a client for the next HTTP request.
    ///
    /// Implements dynamic round-robin load balancing. Automatically skips
    /// blacklisted/cooldown proxies and redirects retried requests to an alternate
    /// healthy proxy from the pool.
    #[inline]
    pub fn get_client_for_request(
        &self,
        exclude_proxy_id: Option<usize>,
    ) -> (Client, Option<Arc<ProxyEntry>>) {
        if self.proxies.is_empty() {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % self.direct_clients.len();
            (self.direct_clients[idx].clone(), None)
        } else {
            let len = self.proxies.len();
            let start = self.rr_counter.fetch_add(1, Ordering::Relaxed);
            let now = Instant::now();
            let mut fallback: Option<Arc<ProxyEntry>> = None;

            for step in 0..len {
                let idx = (start + step) % len;
                let candidate = &self.proxies[idx];

                // If retrying, skip the proxy that just failed to ensure an alternate address is tried
                if let Some(excluded) = exclude_proxy_id {
                    if candidate.id == excluded && len > 1 {
                        continue;
                    }
                }

                if candidate.is_available(self.proxy_cooldown, now) {
                    return (candidate.client.clone(), Some(Arc::clone(candidate)));
                }

                if fallback.is_none() {
                    fallback = Some(Arc::clone(candidate));
                }
            }

            // If all proxies are currently in cooldown, fallback to probing one rather than deadlocking
            let chosen = fallback.unwrap_or_else(|| Arc::clone(&self.proxies[start % len]));
            (chosen.client.clone(), Some(chosen))
        }
    }

    #[inline]
    pub fn has_proxies(&self) -> bool {
        !self.proxies.is_empty()
    }

    #[inline]
    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    #[allow(dead_code)]
    pub fn healthy_proxy_count(&self) -> usize {
        let now = Instant::now();
        self.proxies
            .iter()
            .filter(|p| p.is_available(self.proxy_cooldown, now))
            .count()
    }

    pub fn client_count(&self) -> usize {
        if self.proxies.is_empty() {
            self.direct_clients.len()
        } else {
            self.proxies.len()
        }
    }

    pub fn get_proxy_stats(&self) -> Vec<ProxyStat> {
        let now = Instant::now();
        self.proxies
            .iter()
            .map(|p| ProxyStat {
                id: p.id,
                url: p.url.clone(),
                is_healthy: p.is_available(self.proxy_cooldown, now),
                total_requests: p.total_requests.load(Ordering::Relaxed),
                successes: p.total_successes.load(Ordering::Relaxed),
                failures: p.total_failures.load(Ordering::Relaxed),
                status_429: p.status_429.load(Ordering::Relaxed),
                status_403: p.status_403.load(Ordering::Relaxed),
                status_5xx: p.status_5xx.load(Ordering::Relaxed),
            })
            .collect()
    }
}

/// Build a client optimized for maximum sustained request throughput.
///
/// Key settings:
/// * `TCP_NODELAY` removes Nagle-induced latency (zero-delay pacing).
/// * Idle connections are never evicted and the per-host idle cap is removed,
///   so TLS handshakes and TCP slow-starts are paid only once per connection.
/// * HTTP/2 uses adaptive flow-control windows to keep the pipe full.
/// * `--disable-keepalive` explicitly disables connection reuse.
fn build_http_client(args: &Args, proxy: Option<Proxy>) -> Result<Client> {
    let mut builder = Client::builder()
        .tcp_nodelay(true)
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .pool_idle_timeout(None)
        .pool_max_idle_per_host(if args.disable_keepalive {
            0
        } else {
            usize::MAX
        })
        .timeout(Duration::from_secs(args.timeout))
        .connect_timeout(Duration::from_secs(args.connect_timeout))
        .danger_accept_invalid_certs(args.insecure);

    if args.http2 {
        builder = builder.http2_prior_knowledge().http2_adaptive_window(true);
    }

    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    }

    builder.build().context("Failed to construct HTTP client")
}
