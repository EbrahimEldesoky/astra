use hdrhistogram::Histogram;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const NUM_HISTOGRAM_SHARDS: usize = 64;

pub struct MetricsCollector {
    start_time: Instant,
    pub requests_started: AtomicU64,
    pub requests_completed: AtomicU64,
    pub bytes_transferred: AtomicU64,

    pub status_1xx: AtomicU64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,

    pub errors_timeout: AtomicU64,
    pub errors_connect: AtomicU64,
    pub errors_other: AtomicU64,

    pub retries_attempted: AtomicU64,
    pub retries_recovered: AtomicU64,
    pub retries_exhausted: AtomicU64,

    pub intercepted_429: AtomicU64,
    pub intercepted_403: AtomicU64,
    pub intercepted_5xx: AtomicU64,

    // Sharded histograms to avoid mutex contention across thousands of workers
    shards: Vec<Mutex<Histogram<u64>>>,

    // For calculating current live RPS in snapshots
    last_snapshot_time: Mutex<Instant>,
    last_completed_count: AtomicU64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LiveSnapshot {
    pub elapsed: Duration,
    pub total_started: u64,
    pub total_completed: u64,
    pub in_flight: u64,
    pub current_rps: f64,
    pub total_success: u64,
    pub total_errors: u64,
    pub bytes_transferred: u64,
    pub retries_count: u64,
}

#[derive(Debug, Clone)]
pub struct LatencySummary {
    pub min_us: u64,
    pub mean_us: f64,
    pub max_us: u64,
    pub std_dev_us: f64,
    pub p50_us: u64,
    pub p75_us: u64,
    pub p90_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub p99_9_us: u64,
    pub p99_99_us: u64,
    pub total_samples: u64,
}

impl MetricsCollector {
    pub fn new() -> Arc<Self> {
        let now = Instant::now();
        let mut shards = Vec::with_capacity(NUM_HISTOGRAM_SHARDS);
        for _ in 0..NUM_HISTOGRAM_SHARDS {
            // 1 microsecond to 60 seconds range, with 3 significant digits
            let hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
                .expect("Failed to create latency histogram");
            shards.push(Mutex::new(hist));
        }

        Arc::new(Self {
            start_time: now,
            requests_started: AtomicU64::new(0),
            requests_completed: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            status_1xx: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            errors_timeout: AtomicU64::new(0),
            errors_connect: AtomicU64::new(0),
            errors_other: AtomicU64::new(0),
            retries_attempted: AtomicU64::new(0),
            retries_recovered: AtomicU64::new(0),
            retries_exhausted: AtomicU64::new(0),
            intercepted_429: AtomicU64::new(0),
            intercepted_403: AtomicU64::new(0),
            intercepted_5xx: AtomicU64::new(0),
            shards,
            last_snapshot_time: Mutex::new(now),
            last_completed_count: AtomicU64::new(0),
        })
    }

    #[inline]
    pub fn record_start(&self) {
        self.requests_started.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_retry_attempt(&self) {
        self.retries_attempted.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_retry_recovered(&self) {
        self.retries_recovered.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_retry_exhausted(&self) {
        self.retries_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_status_intercepted(&self, status: u16) {
        match status {
            429 => {
                self.intercepted_429.fetch_add(1, Ordering::Relaxed);
            }
            403 => {
                self.intercepted_403.fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.intercepted_5xx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    #[inline]
    pub fn record_final_status(&self, status_code: u16) {
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
        match status_code {
            100..=199 => self.status_1xx.fetch_add(1, Ordering::Relaxed),
            200..=299 => self.status_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.status_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.status_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.status_5xx.fetch_add(1, Ordering::Relaxed),
            _ => self.errors_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    #[inline]
    pub fn record_success(&self, status_code: u16, bytes: usize) {
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
        self.bytes_transferred
            .fetch_add(bytes as u64, Ordering::Relaxed);

        match status_code {
            100..=199 => self.status_1xx.fetch_add(1, Ordering::Relaxed),
            200..=299 => self.status_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.status_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.status_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.status_5xx.fetch_add(1, Ordering::Relaxed),
            _ => self.errors_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    #[inline]
    pub fn record_error(&self, is_timeout: bool, is_connect: bool) {
        self.requests_completed.fetch_add(1, Ordering::Relaxed);
        if is_timeout {
            self.errors_timeout.fetch_add(1, Ordering::Relaxed);
        } else if is_connect {
            self.errors_connect.fetch_add(1, Ordering::Relaxed);
        } else {
            self.errors_other.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a batch of latency values (in microseconds) into the worker's shard.
    #[inline]
    pub fn record_latencies(&self, worker_id: usize, latencies: &[u64]) {
        let shard_idx = worker_id % NUM_HISTOGRAM_SHARDS;
        let mut hist = self.shards[shard_idx].lock();
        for &lat in latencies {
            // Clamp within bounds to prevent panics on extreme outliers
            let clamped = lat.clamp(1, 59_999_999);
            let _ = hist.record(clamped);
        }
    }

    /// Capture live metrics for the real-time TUI progress display.
    pub fn snapshot(&self) -> LiveSnapshot {
        let now = Instant::now();
        let total_started = self.requests_started.load(Ordering::Relaxed);
        let total_completed = self.requests_completed.load(Ordering::Relaxed);
        let bytes_transferred = self.bytes_transferred.load(Ordering::Relaxed);

        let s2xx = self.status_2xx.load(Ordering::Relaxed);
        let err_timeout = self.errors_timeout.load(Ordering::Relaxed);
        let err_conn = self.errors_connect.load(Ordering::Relaxed);
        let err_other = self.errors_other.load(Ordering::Relaxed);
        let s4xx = self.status_4xx.load(Ordering::Relaxed);
        let s5xx = self.status_5xx.load(Ordering::Relaxed);
        let retries_count = self.retries_attempted.load(Ordering::Relaxed);

        let total_errors = err_timeout + err_conn + err_other + s4xx + s5xx;

        let in_flight = total_started.saturating_sub(total_completed);

        let mut last_time = self.last_snapshot_time.lock();
        let delta_secs = now.duration_since(*last_time).as_secs_f64();
        let prev_completed = self
            .last_completed_count
            .swap(total_completed, Ordering::Relaxed);

        let current_rps = if delta_secs > 0.05 {
            let count_delta = total_completed.saturating_sub(prev_completed);
            *last_time = now;
            count_delta as f64 / delta_secs
        } else {
            0.0
        };

        LiveSnapshot {
            elapsed: self.start_time.elapsed(),
            total_started,
            total_completed,
            in_flight,
            current_rps,
            total_success: s2xx,
            total_errors,
            bytes_transferred,
            retries_count,
        }
    }

    /// Consolidate all sharded histograms into a single final latency summary.
    pub fn consolidate_latencies(&self) -> (Histogram<u64>, LatencySummary) {
        let mut total_hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
            .expect("Failed to build consolidated histogram");

        for shard in &self.shards {
            let hist = shard.lock();
            let _ = total_hist.add(&*hist);
        }

        let total_samples = total_hist.len();
        if total_samples == 0 {
            return (
                total_hist,
                LatencySummary {
                    min_us: 0,
                    mean_us: 0.0,
                    max_us: 0,
                    std_dev_us: 0.0,
                    p50_us: 0,
                    p75_us: 0,
                    p90_us: 0,
                    p95_us: 0,
                    p99_us: 0,
                    p99_9_us: 0,
                    p99_99_us: 0,
                    total_samples: 0,
                },
            );
        }

        let summary = LatencySummary {
            min_us: total_hist.min(),
            mean_us: total_hist.mean(),
            max_us: total_hist.max(),
            std_dev_us: total_hist.stdev(),
            p50_us: total_hist.value_at_quantile(0.50),
            p75_us: total_hist.value_at_quantile(0.75),
            p90_us: total_hist.value_at_quantile(0.90),
            p95_us: total_hist.value_at_quantile(0.95),
            p99_us: total_hist.value_at_quantile(0.99),
            p99_9_us: total_hist.value_at_quantile(0.999),
            p99_99_us: total_hist.value_at_quantile(0.9999),
            total_samples,
        };

        (total_hist, summary)
    }
}
