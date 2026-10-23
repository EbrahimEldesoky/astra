use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// High-throughput, anti-stampede pacer capable of governing up to millions of RPS.
///
/// Features:
/// 1. Ticket-based sub-microsecond rate pacing for target RPS.
/// 2. Anti-stampede debt clamping (Burst Window Limiter): Prevents coordinated omission
///    bursts when the system or network lags, ensuring sustainable, balanced request flow.
/// 3. In-flight backpressure limiter: Caps active concurrent requests across all workers,
///    preventing OS file descriptor exhaustion, TCP socket buffer bloat, and memory spikes.
/// 4. Separate retry throttling: Retried requests are throttled without consuming the primary
///    target request quota (`max_requests`).
pub struct Pacer {
    target_rps: u64,
    max_requests: Option<u64>,
    start_time: Instant,
    deadline: Instant,
    counter: AtomicU64,
    stopped: AtomicBool,
    max_burst_nanos: u64,
    max_in_flight: usize,
    in_flight: AtomicUsize,
    lag_offset_nanos: AtomicU64,
}

impl Pacer {
    pub fn new(
        target_rps: u64,
        duration: Duration,
        max_requests: Option<u64>,
        burst_limit: u64,
        max_in_flight: usize,
    ) -> Self {
        let now = Instant::now();
        let deadline = if duration.is_zero() {
            now + Duration::from_secs(365 * 24 * 3600) // Virtually infinite when governed by request count
        } else {
            now + duration
        };

        let effective_burst = if burst_limit > 0 {
            burst_limit
        } else if target_rps > 0 {
            (target_rps / 10).clamp(20, 1000) // 100ms worth of RPS, clamped
        } else {
            1000
        };

        let max_burst_nanos = if target_rps > 0 {
            ((effective_burst as u128 * 1_000_000_000) / (target_rps as u128)) as u64
        } else {
            100_000_000 // 100ms default
        };

        Self {
            target_rps,
            max_requests,
            start_time: now,
            deadline,
            counter: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            max_burst_nanos,
            max_in_flight,
            in_flight: AtomicUsize::new(0),
            lag_offset_nanos: AtomicU64::new(0),
        }
    }

    /// Stop the pacer immediately (e.g. on Ctrl+C).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    /// Check if the test has been stopped or exceeded its duration or max requests.
    #[inline]
    pub fn is_stopped(&self) -> bool {
        if self.stopped.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            return true;
        }
        if let Some(max) = self.max_requests {
            if self.counter.load(Ordering::Relaxed) >= max {
                return true;
            }
        }
        false
    }

    /// Acquire permission to send the next primary request.
    ///
    /// Claims a ticket towards `max_requests`.
    /// Returns `true` if permitted, or `false` if the test duration expired,
    /// max request count was reached, or test was stopped.
    #[inline]
    pub async fn acquire(&self) -> bool {
        if self.stopped.load(Ordering::Relaxed) {
            return false;
        }

        // Apply in-flight backpressure if capped
        if self.max_in_flight > 0 {
            while self.in_flight.load(Ordering::Relaxed) >= self.max_in_flight {
                if self.is_stopped() {
                    return false;
                }
                tokio::task::yield_now().await;
            }
        }

        let now = Instant::now();
        if now >= self.deadline {
            self.stopped.store(true, Ordering::Release);
            return false;
        }

        let ticket = self.counter.fetch_add(1, Ordering::Relaxed);
        if let Some(max) = self.max_requests {
            if ticket >= max {
                self.stopped.store(true, Ordering::Release);
                return false;
            }
        }

        self.in_flight.fetch_add(1, Ordering::Relaxed);

        // Unlimited mode: fire as fast as hardware/network allows. Tokio's
        // cooperative budget and the request I/O awaits already yield the
        // worker, so no artificial delay is injected here.
        if self.target_rps == 0 {
            return true;
        }

        // Calculate expected time in nanoseconds for this ticket
        let raw_nanos = ((ticket as u128 * 1_000_000_000) / (self.target_rps as u128)) as u64;
        let lag_adjustment = self.lag_offset_nanos.load(Ordering::Relaxed);
        let scheduled_nanos = raw_nanos.saturating_add(lag_adjustment);
        let scheduled_time = self.start_time + Duration::from_nanos(scheduled_nanos);

        if scheduled_time > now {
            let wait = scheduled_time - now;
            if wait >= Duration::from_millis(1) {
                tokio::time::sleep(wait).await;
            } else if wait >= Duration::from_micros(50) {
                tokio::task::yield_now().await;
            }
        } else {
            // Anti-Stampede Clamping: If behind by more than max burst window,
            // shift the time base forward so workers don't flood all backlog at once.
            let behind_nanos = (now - scheduled_time).as_nanos() as u64;
            if behind_nanos > self.max_burst_nanos {
                let excess = behind_nanos - self.max_burst_nanos;
                self.lag_offset_nanos.fetch_add(excess, Ordering::Relaxed);
            }
        }

        !self.stopped.load(Ordering::Relaxed)
    }

    /// Throttle a retried request without consuming a new ticket from `max_requests`.
    #[inline]
    pub async fn throttle_retry(&self) -> bool {
        if self.stopped.load(Ordering::Relaxed) || Instant::now() >= self.deadline {
            return false;
        }

        if self.max_in_flight > 0 {
            while self.in_flight.load(Ordering::Relaxed) >= self.max_in_flight {
                if self.is_stopped() {
                    return false;
                }
                tokio::task::yield_now().await;
            }
        }

        // Cooperative yield for retries to avoid CPU monopolization
        tokio::task::yield_now().await;
        !self.stopped.load(Ordering::Relaxed)
    }

    /// Release an in-flight request slot.
    #[inline]
    pub fn release(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    #[inline]
    pub fn current_in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn total_scheduled(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}
