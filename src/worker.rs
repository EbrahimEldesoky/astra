use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::client::{ClientPool, RequestSpec};
use crate::evasion::{EvasionConfig, generate_fingerprint};
use crate::metrics::MetricsCollector;
use crate::pacer::Pacer;
use crate::scanner::{ScanSink, ScannerConfig, analyze_response};

const LATENCY_BATCH_SIZE: usize = 64;

thread_local! {
    static RNG: Cell<u64> = Cell::new(0x853c49e6748fea9b ^ (std::process::id() as u64));
}

/// Fast thread-local Xorshift64* pseudo-random number generator for uniform jitter.
fn fast_rand_range(min: u64, max: u64) -> u64 {
    if min >= max {
        return min;
    }
    RNG.with(|cell| {
        let mut x = cell.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let val = x.wrapping_mul(0x2545F4914F6CDD1D);
        cell.set(x);
        min + (val % (max - min + 1))
    })
}

/// Compute Full Jitter for Exponential Backoff: uniformly distributed in [base, cap].
fn compute_full_jitter(base: u64, cap: u64) -> u64 {
    fast_rand_range(base.max(1), cap.max(base + 1))
}

/// Outcome of a single HTTP request: (latency_microseconds, result).
/// Ok variant: (status_code, response_bytes_len)
/// Err variant: (is_timeout, is_connect_error)
type RequestOutcome = (u64, Result<(u16, usize), (bool, bool)>);

// Boxed response metadata captured for the scanner (URL, status, headers, body)
type ScanCapture = Option<(String, u16, reqwest::header::HeaderMap, Vec<u8>)>;

/// Execute an HTTP request with smart status classification, automatic retries,
/// alternate proxy redirection, jittered exponential backoff, and optional
/// per-request fingerprint randomisation via the evasion module.
async fn execute_request_with_retries(
    client_pool: &Arc<ClientPool>,
    spec: &Arc<RequestSpec>,
    pacer: &Arc<Pacer>,
    metrics: &Arc<MetricsCollector>,
    cancel_token: &CancellationToken,
    no_body: bool,
    evasion: &EvasionConfig,
    scan_cfg: &ScannerConfig,
) -> (RequestOutcome, ScanCapture) {
    let t0 = Instant::now();
    let max_retries = client_pool.max_retries;
    let mut last_failed_proxy_id: Option<usize> = None;
    let mut last_err = (false, false);
    let mut last_status: Option<u16> = None;
    let need_scan = scan_cfg.passive_scan || scan_cfg.active_probe;

    for attempt in 0..=max_retries {
        if cancel_token.is_cancelled() {
            return ((t0.elapsed().as_micros() as u64, Err((false, false))), None);
        }

        // Apply Jittered Exponential Backoff and pacing for retries
        if attempt > 0 {
            metrics.record_retry_attempt();

            let shift = (attempt - 1).min(6) as u32;
            let exp_backoff = client_pool.retry_backoff_ms.saturating_mul(1 << shift);
            let capped_backoff = exp_backoff.min(client_pool.max_backoff_ms);

            let delay_ms = if client_pool.no_jitter {
                capped_backoff
            } else {
                compute_full_jitter(client_pool.retry_backoff_ms, capped_backoff)
            };

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;

            if !pacer.throttle_retry().await {
                return ((t0.elapsed().as_micros() as u64, Err((false, false))), None);
            }
        }

        // Dynamically obtain a client/proxy via round-robin, skipping failed/blacklisted proxies
        let (client, proxy_entry) = client_pool.get_client_for_request(last_failed_proxy_id);
        let proxy_id = proxy_entry.as_ref().map(|p| p.id);

        // Generate a unique polymorphic fingerprint for this individual request
        let fp = generate_fingerprint(evasion, &spec.method, &spec.body);

        // Merge base headers then overlay evasion headers (evasion wins on conflict)
        let mut merged_headers = spec.headers.clone();
        for (k, v) in &fp.extra_headers {
            merged_headers.insert(k.clone(), v.clone());
        }

        let mut req = client
            .request(fp.method, spec.url.clone())
            .headers(merged_headers);

        // Use polymorphic body override if present, else fall back to spec body
        if let Some((body_bytes, content_type)) = fp.body_override {
            req = req
                .body(body_bytes)
                .header(reqwest::header::CONTENT_TYPE, content_type);
        } else if let Some(ref body) = spec.body {
            req = req.body(body.clone());
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_url = resp.url().to_string();
                let resp_headers = resp.headers().clone();

                // 1. TRUE SUCCESS (2xx)
                if (200..=299).contains(&status) {
                    // Capture body bytes — needed for both no_body mode and scanner
                    let (body_bytes, body_len) = if no_body {
                        let len = resp.content_length().unwrap_or(0) as usize;
                        (Vec::new(), len)
                    } else {
                        match resp.bytes().await {
                            Ok(b) => {
                                let l = b.len();
                                (b.to_vec(), l)
                            }
                            Err(e) => {
                                if let Some(ref proxy) = proxy_entry {
                                    proxy.record_network_failure(
                                        client_pool.proxy_fail_threshold,
                                        Instant::now(),
                                    );
                                }
                                last_failed_proxy_id = proxy_id;
                                last_err = (e.is_timeout(), e.is_connect());
                                last_status = None;
                                continue;
                            }
                        }
                    };

                    if let Some(ref proxy) = proxy_entry {
                        proxy.record_success();
                    }
                    if attempt > 0 {
                        metrics.record_retry_recovered();
                    }

                    let capture = if need_scan {
                        Some((resp_url, status, resp_headers, body_bytes))
                    } else {
                        None
                    };
                    return (
                        (t0.elapsed().as_micros() as u64, Ok((status, body_len))),
                        capture,
                    );
                } else if client_pool.is_retryable_status(status) {
                    // 2. TRANSIENT / RATE LIMIT / WAF ERROR
                    if let Some(ref proxy) = proxy_entry {
                        proxy.record_status_failure(
                            status,
                            client_pool.proxy_fail_threshold,
                            Instant::now(),
                        );
                    }
                    metrics.record_status_intercepted(status);
                    last_failed_proxy_id = proxy_id;
                    last_status = Some(status);
                    last_err = (false, false);
                } else {
                    // 3. Non-retryable status (404, 400, 3xx, etc.)
                    let body_bytes = if need_scan && !no_body {
                        resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    let body_len = body_bytes.len();
                    if let Some(ref proxy) = proxy_entry {
                        proxy.record_success();
                    }
                    let capture = if need_scan {
                        Some((resp_url, status, resp_headers, body_bytes))
                    } else {
                        None
                    };
                    return (
                        (t0.elapsed().as_micros() as u64, Ok((status, body_len))),
                        capture,
                    );
                }
            }
            Err(e) => {
                let is_timeout = e.is_timeout();
                let is_connect = e.is_connect();
                if let Some(ref proxy) = proxy_entry {
                    proxy.record_network_failure(client_pool.proxy_fail_threshold, Instant::now());
                }
                last_failed_proxy_id = proxy_id;
                last_err = (is_timeout, is_connect);
                last_status = None;
            }
        }
    }

    metrics.record_retry_exhausted();
    if let Some(status) = last_status {
        ((t0.elapsed().as_micros() as u64, Ok((status, 0))), None)
    } else {
        ((t0.elapsed().as_micros() as u64, Err(last_err)), None)
    }
}

/// Record the outcome of a completed request into the metrics collector.
#[inline]
fn record_outcome(metrics: &MetricsCollector, outcome: &RequestOutcome) {
    match &outcome.1 {
        Ok((status, bytes)) => {
            if (200..=299).contains(status) {
                metrics.record_success(*status, *bytes);
            } else {
                metrics.record_final_status(*status);
            }
        }
        Err((is_timeout, is_connect)) => metrics.record_error(*is_timeout, *is_connect),
    }
}

/// Fire the scanner on a captured response (off the hot path).
#[inline]
fn maybe_scan(capture: ScanCapture, cfg: &ScannerConfig, sink: &Arc<ScanSink>) {
    if let Some((url, status, headers, body)) = capture {
        analyze_response(&url, status, &body, &headers, cfg, sink);
    }
}

/// Long-lived worker coroutine.
pub async fn run_worker(
    worker_id: usize,
    client_pool: Arc<ClientPool>,
    spec: Arc<RequestSpec>,
    pacer: Arc<Pacer>,
    metrics: Arc<MetricsCollector>,
    cancel_token: CancellationToken,
    pipeline_depth: usize,
    no_body: bool,
    evasion: Arc<EvasionConfig>,
    scan_cfg: Arc<ScannerConfig>,
    scan_sink: Arc<ScanSink>,
) {
    if pipeline_depth <= 1 {
        run_sequential(
            worker_id,
            client_pool,
            spec,
            pacer,
            metrics,
            cancel_token,
            no_body,
            evasion,
            scan_cfg,
            scan_sink,
        )
        .await;
    } else {
        run_pipelined(
            worker_id,
            client_pool,
            spec,
            pacer,
            metrics,
            cancel_token,
            pipeline_depth,
            no_body,
            evasion,
            scan_cfg,
            scan_sink,
        )
        .await;
    }
}

/// Sequential execution: one request at a time per worker. Minimal overhead.
async fn run_sequential(
    worker_id: usize,
    client_pool: Arc<ClientPool>,
    spec: Arc<RequestSpec>,
    pacer: Arc<Pacer>,
    metrics: Arc<MetricsCollector>,
    cancel_token: CancellationToken,
    no_body: bool,
    evasion: Arc<EvasionConfig>,
    scan_cfg: Arc<ScannerConfig>,
    scan_sink: Arc<ScanSink>,
) {
    let mut latency_buf = Vec::with_capacity(LATENCY_BATCH_SIZE);

    while !cancel_token.is_cancelled() {
        if !pacer.acquire().await {
            break;
        }

        metrics.record_start();
        let (outcome, capture) = execute_request_with_retries(
            &client_pool,
            &spec,
            &pacer,
            &metrics,
            &cancel_token,
            no_body,
            &evasion,
            &scan_cfg,
        )
        .await;
        pacer.release();

        // Off-hot-path scanner invocation
        maybe_scan(capture, &scan_cfg, &scan_sink);

        latency_buf.push(outcome.0);
        if latency_buf.len() >= LATENCY_BATCH_SIZE {
            metrics.record_latencies(worker_id, &latency_buf);
            latency_buf.clear();
        }
        record_outcome(&metrics, &outcome);
    }

    if !latency_buf.is_empty() {
        metrics.record_latencies(worker_id, &latency_buf);
    }
}

/// Pipelined execution: maintain `pipeline_depth` concurrent in-flight requests.
async fn run_pipelined(
    worker_id: usize,
    client_pool: Arc<ClientPool>,
    spec: Arc<RequestSpec>,
    pacer: Arc<Pacer>,
    metrics: Arc<MetricsCollector>,
    cancel_token: CancellationToken,
    pipeline_depth: usize,
    no_body: bool,
    evasion: Arc<EvasionConfig>,
    scan_cfg: Arc<ScannerConfig>,
    scan_sink: Arc<ScanSink>,
) {
    let mut latency_buf = Vec::with_capacity(LATENCY_BATCH_SIZE);
    let mut futs: FuturesUnordered<_> = FuturesUnordered::new();
    let mut draining = false;

    loop {
        while futs.len() < pipeline_depth && !draining {
            if cancel_token.is_cancelled() {
                draining = true;
                break;
            }
            if !pacer.acquire().await {
                draining = true;
                break;
            }
            metrics.record_start();
            let cp = Arc::clone(&client_pool);
            let s = Arc::clone(&spec);
            let pac = Arc::clone(&pacer);
            let m = Arc::clone(&metrics);
            let cancel = cancel_token.clone();
            let ev = Arc::clone(&evasion);
            let sc = Arc::clone(&scan_cfg);

            futs.push(async move {
                let (outcome, capture) =
                    execute_request_with_retries(&cp, &s, &pac, &m, &cancel, no_body, &ev, &sc)
                        .await;
                pac.release();
                (outcome, capture)
            });
        }

        if futs.is_empty() {
            break;
        }

        let Some((outcome, capture)) = futs.next().await else {
            break;
        };

        maybe_scan(capture, &scan_cfg, &scan_sink);

        latency_buf.push(outcome.0);
        if latency_buf.len() >= LATENCY_BATCH_SIZE {
            metrics.record_latencies(worker_id, &latency_buf);
            latency_buf.clear();
        }
        record_outcome(&metrics, &outcome);
    }

    if !latency_buf.is_empty() {
        metrics.record_latencies(worker_id, &latency_buf);
    }
}
