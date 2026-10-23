use colored::Colorize;
use hdrhistogram::Histogram;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use crate::args::Args;
use crate::client::ClientPool;
use crate::metrics::{LatencySummary, LiveSnapshot, MetricsCollector};
use crate::sys::SystemInfo;

pub fn print_banner(args: &Args, sys: &SystemInfo, client_pools: usize, proxy_count: usize) {
    let banner = r#"
    █████╗ ███████╗████████╗██████╗  █████╗ 
   ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
   ███████║███████╗   ██║   ██████╔╝███████║
   ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║
   ██║  ██║███████║   ██║   ██║  ██║██║  ██║
   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
"#;
    println!("{}", banner.bright_cyan().bold());
    println!(
        "   {} {}",
        "Astra HTTP Load Engine".bright_white().bold(),
        "v0.1.0 [Release]".bright_black()
    );
    println!(
        "   {}\n",
        "Extreme-scale asynchronous HTTP benchmarking & stress testing"
            .bright_blue()
            .italic()
    );

    println!(
        "{}",
        "── Benchmark Configuration ──────────────────────────────────────────".bright_black()
    );
    println!(
        "  {:<20} {}",
        "Target URL:".bright_white().bold(),
        args.url.bright_yellow()
    );
    println!(
        "  {:<20} {}",
        "HTTP Method:".bright_white().bold(),
        args.method.to_uppercase().bright_green()
    );
    println!(
        "  {:<20} {} workers",
        "Concurrency:".bright_white().bold(),
        format_number(args.concurrency as u64).bright_cyan().bold()
    );
    if let Some(reqs) = args.requests {
        println!(
            "  {:<20} {} requests",
            "Target Requests:".bright_white().bold(),
            format_number(reqs).bright_cyan().bold()
        );
    }
    println!(
        "  {:<20} {}",
        "Target Rate:".bright_white().bold(),
        if args.rps > 0 {
            format!("{} req/s", format_number(args.rps))
                .bright_cyan()
                .bold()
        } else {
            "Unlimited (max line-rate)".bright_magenta().bold()
        }
    );
    if args.duration > 0 {
        println!(
            "  {:<20} {} seconds",
            "Test Duration:".bright_white().bold(),
            args.duration.to_string().bright_white().bold()
        );
    } else {
        println!(
            "  {:<20} {}",
            "Test Duration:".bright_white().bold(),
            "Unlimited (until target requests completed)"
                .bright_white()
                .bold()
        );
    }
    if args.pipeline > 1 {
        let effective = args.concurrency.saturating_mul(args.pipeline);
        println!(
            "  {:<20} {} req/worker ({} effective in-flight)",
            "Pipeline Depth:".bright_white().bold(),
            args.pipeline.to_string().bright_cyan().bold(),
            format_number(effective as u64).bright_magenta().bold()
        );
    }
    if args.no_body {
        println!(
            "  {:<20} {}",
            "Body Reading:".bright_white().bold(),
            "Disabled (max throughput mode)".bright_yellow()
        );
    }
    if proxy_count > 0 {
        println!(
            "  {:<20} {} proxies (dynamic round-robin & auto-skip)",
            "Proxy Rotation:".bright_white().bold(),
            format_number(proxy_count as u64).bright_green().bold()
        );
        println!(
            "  {:<20} {}s (fail-threshold: {} consecutive fails)",
            "Proxy Cooldown:".bright_white().bold(),
            args.proxy_cooldown.to_string().bright_yellow(),
            args.proxy_fail_threshold.to_string().bright_yellow()
        );
    }
    if args.retries > 0 {
        let jitter_str = if args.no_jitter {
            "Fixed"
        } else {
            "Full Jitter"
        };
        println!(
            "  {:<20} max {} retries, {}ms backoff ({}, cap: {}ms)",
            "Automatic Retries:".bright_white().bold(),
            args.retries.to_string().bright_green().bold(),
            args.retry_backoff.to_string().bright_cyan(),
            jitter_str.bright_yellow(),
            args.retry_max_backoff.to_string().bright_cyan()
        );
        println!(
            "  {:<20} {}",
            "Retry Interception:".bright_white().bold(),
            args.retry_statuses.bright_magenta()
        );
    }
    if args.rps > 0 {
        let burst_str = if args.burst_limit > 0 {
            format!("cap: {}", args.burst_limit)
        } else {
            "anti-stampede dynamic clamping".to_string()
        };
        println!(
            "  {:<20} {}",
            "Rate Throttling:".bright_white().bold(),
            burst_str.bright_magenta()
        );
    }
    println!(
        "  {:<20} {}s (connect timeout: {}s)",
        "Socket Timeout:".bright_white().bold(),
        args.timeout,
        args.connect_timeout
    );
    let runtime_threads = if args.threads == 0 {
        sys.cpu_cores
    } else {
        args.threads
    };
    println!(
        "  {:<20} {} (workers: {}{}, CPU cores: {}, Clients: {})",
        "Runtime Engines:".bright_white().bold(),
        "Tokio Multi-Threaded / work-stealing".bright_green(),
        runtime_threads,
        if args.pin_cores { ", pinned" } else { "" },
        sys.cpu_cores,
        client_pools
    );
    println!(
        "  {:<20} soft: {} (boosted from {}) | hard: {}",
        "File Descriptors:".bright_white().bold(),
        format_number(sys.current_nofile_soft).bright_green().bold(),
        format_number(sys.initial_nofile_soft).bright_white(),
        format_number(sys.nofile_hard).bright_white()
    );
    if !args.headers.is_empty() {
        println!(
            "  {:<20} {}",
            "Custom Headers:".bright_white().bold(),
            args.headers.join(", ").bright_blue()
        );
    }
    println!(
        "{}",
        "─────────────────────────────────────────────────────────────────────\n".bright_black()
    );
}

pub fn create_progress_bar(duration_secs: u64, max_requests: Option<u64>) -> ProgressBar {
    if let Some(total_reqs) = max_requests {
        let pb = ProgressBar::new(total_reqs);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} reqs ({percent}%) | RPS: {msg}")
                .expect("Valid progress bar template")
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    } else {
        let pb = ProgressBar::new(duration_secs);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len}s ({percent}%) | RPS: {msg}")
                .expect("Valid progress bar template")
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }
}

pub fn update_progress_bar(
    pb: &ProgressBar,
    snapshot: &LiveSnapshot,
    elapsed_secs: u64,
    max_requests: Option<u64>,
) {
    if max_requests.is_some() {
        pb.set_position(snapshot.total_completed);
    } else {
        pb.set_position(elapsed_secs);
    }
    let retries_info = if snapshot.retries_count > 0 {
        format!(
            " | Retries: {}",
            snapshot.retries_count.to_string().bright_yellow()
        )
    } else {
        String::new()
    };
    let msg = format!(
        "{} | Req: {} | In-flight: {} | Data: {} | Err: {}{}",
        format_number(snapshot.current_rps as u64)
            .bright_yellow()
            .bold(),
        format_number(snapshot.total_completed).bright_white(),
        format_number(snapshot.in_flight).bright_cyan(),
        format_bytes(snapshot.bytes_transferred).bright_white(),
        if snapshot.total_errors > 0 {
            snapshot.total_errors.to_string().bright_red().bold()
        } else {
            "0".bright_green()
        },
        retries_info
    );
    pb.set_message(msg);
}

pub fn print_final_report(
    metrics: &MetricsCollector,
    total_duration: Duration,
    hist: &Histogram<u64>,
    lat: &LatencySummary,
    client_pool: &ClientPool,
) {
    let elapsed_secs = total_duration.as_secs_f64();
    let total_started = metrics
        .requests_started
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_completed = metrics
        .requests_completed
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_bytes = metrics
        .bytes_transferred
        .load(std::sync::atomic::Ordering::Relaxed);

    let s1xx = metrics
        .status_1xx
        .load(std::sync::atomic::Ordering::Relaxed);
    let s2xx = metrics
        .status_2xx
        .load(std::sync::atomic::Ordering::Relaxed);
    let s3xx = metrics
        .status_3xx
        .load(std::sync::atomic::Ordering::Relaxed);
    let s4xx = metrics
        .status_4xx
        .load(std::sync::atomic::Ordering::Relaxed);
    let s5xx = metrics
        .status_5xx
        .load(std::sync::atomic::Ordering::Relaxed);

    let err_timeout = metrics
        .errors_timeout
        .load(std::sync::atomic::Ordering::Relaxed);
    let err_conn = metrics
        .errors_connect
        .load(std::sync::atomic::Ordering::Relaxed);
    let err_other = metrics
        .errors_other
        .load(std::sync::atomic::Ordering::Relaxed);

    let retries_attempted = metrics
        .retries_attempted
        .load(std::sync::atomic::Ordering::Relaxed);
    let retries_recovered = metrics
        .retries_recovered
        .load(std::sync::atomic::Ordering::Relaxed);
    let retries_exhausted = metrics
        .retries_exhausted
        .load(std::sync::atomic::Ordering::Relaxed);

    let total_network_errs = err_timeout + err_conn + err_other;
    let actual_rps = if elapsed_secs > 0.0 {
        total_completed as f64 / elapsed_secs
    } else {
        0.0
    };
    let transfer_rate_mb = if elapsed_secs > 0.0 {
        (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs
    } else {
        0.0
    };
    let success_rate = if total_completed > 0 {
        (s2xx as f64 / total_completed as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "\n{}",
        "═════════════════════════════════════════════════════════════════════"
            .bright_cyan()
            .bold()
    );
    println!(
        "                   {}                    ",
        "ASTRA BENCHMARK RESULTS".bright_white().bold()
    );
    println!(
        "{}\n",
        "═════════════════════════════════════════════════════════════════════"
            .bright_cyan()
            .bold()
    );

    // Summary Section
    println!(
        "{}",
        "── Execution Summary ────────────────────────────────────────────────".bright_black()
    );
    println!(
        "  {:<26} {:.2}s",
        "Total Time Elapsed:".bright_white().bold(),
        elapsed_secs
    );
    println!(
        "  {:<26} {}",
        "Requests Initiated:".bright_white().bold(),
        format_number(total_started).bright_white()
    );
    println!(
        "  {:<26} {}",
        "Requests Completed:".bright_white().bold(),
        format_number(total_completed).bright_cyan().bold()
    );
    println!(
        "  {:<26} {} req/s",
        "Throughput (Actual RPS):".bright_white().bold(),
        format_number(actual_rps as u64).bright_green().bold()
    );
    let success_colored = if success_rate >= 99.0 {
        format!("{:.2}%", success_rate).bright_green().bold()
    } else {
        format!("{:.2}%", success_rate).bright_yellow().bold()
    };
    println!(
        "  {:<26} {}",
        "Success Rate:".bright_white().bold(),
        success_colored
    );
    println!(
        "  {:<26} {} ({:.2} MB/s)",
        "Total Data Received:".bright_white().bold(),
        format_bytes(total_bytes).bright_white(),
        transfer_rate_mb
    );
    println!();

    // Automatic Retries & Fault Recovery Section
    if retries_attempted > 0 {
        let int_429 = metrics
            .intercepted_429
            .load(std::sync::atomic::Ordering::Relaxed);
        let int_403 = metrics
            .intercepted_403
            .load(std::sync::atomic::Ordering::Relaxed);
        let int_5xx = metrics
            .intercepted_5xx
            .load(std::sync::atomic::Ordering::Relaxed);

        println!(
            "{}",
            "── Automatic Retries & Fault Recovery ───────────────────────────────".bright_black()
        );
        println!(
            "  {:<26} {}",
            "Retries Attempted:".bright_white().bold(),
            format_number(retries_attempted).bright_yellow()
        );
        if int_429 > 0 {
            println!(
                "    - {:<28} {}",
                "429 (Rate-Limit Intercepted):",
                format_number(int_429).bright_yellow()
            );
        }
        if int_403 > 0 {
            println!(
                "    - {:<28} {}",
                "403 (WAF/Block Intercepted):",
                format_number(int_403).bright_yellow()
            );
        }
        if int_5xx > 0 {
            println!(
                "    - {:<28} {}",
                "5xx (Server Error Intercepted):",
                format_number(int_5xx).bright_yellow()
            );
        }
        let recovery_pct = (retries_recovered as f64 / retries_attempted as f64) * 100.0;
        println!(
            "  {:<26} {} ({:.1}%)",
            "Successfully Recovered (2xx):".bright_white().bold(),
            format_number(retries_recovered).bright_green().bold(),
            recovery_pct
        );
        if retries_exhausted > 0 {
            println!(
                "  {:<26} {}",
                "Retries Exhausted:".bright_white().bold(),
                format_number(retries_exhausted).bright_red().bold()
            );
        }
        println!();
    }

    // Status Code Breakdown Section
    println!(
        "{}",
        "── Status Code & Error Breakdown ───────────────────────────────────".bright_black()
    );
    println!(
        "  {:<22} {:>14} {:>14}",
        "Status Category", "Count", "Percentage"
    );
    println!("  {}", "─".repeat(52).bright_black());
    print_status_line("2xx (Success)", s2xx, total_completed, true);
    if s1xx > 0 {
        print_status_line("1xx (Informational)", s1xx, total_completed, false);
    }
    if s3xx > 0 {
        print_status_line("3xx (Redirection)", s3xx, total_completed, false);
    }
    if s4xx > 0 {
        print_status_line("4xx (Client Error)", s4xx, total_completed, false);
    }
    if s5xx > 0 {
        print_status_line("5xx (Server Error)", s5xx, total_completed, false);
    }
    if total_network_errs > 0 {
        println!("  {}", "─".repeat(52).bright_black());
        println!(
            "  {:<22} {:>14}",
            "Network Errors:".bright_red().bold(),
            format_number(total_network_errs).bright_red()
        );
        if err_timeout > 0 {
            println!(
                "    - {:<18} {:>14}",
                "Connection Timeouts",
                format_number(err_timeout).bright_yellow()
            );
        }
        if err_conn > 0 {
            println!(
                "    - {:<18} {:>14}",
                "Connection Refused/Reset",
                format_number(err_conn).bright_yellow()
            );
        }
        if err_other > 0 {
            println!(
                "    - {:<18} {:>14}",
                "Other Network I/O Errors",
                format_number(err_other).bright_yellow()
            );
        }
    }
    println!();

    // Proxy Pool Telemetry Section
    if client_pool.has_proxies() {
        let stats = client_pool.get_proxy_stats();
        if !stats.is_empty() {
            println!(
                "{}",
                "── Proxy Pool Telemetry & Balancing ────────────────────────────────"
                    .bright_black()
            );
            println!(
                "  {:<4} {:<24} {:<10} {:>8} {:>8} {:>6} {:>6} {:>6} {:>8}",
                "ID", "Proxy Address", "Health", "Total", "2xx OK", "429", "403", "5xx", "NetErr"
            );
            println!("  {}", "─".repeat(90).bright_black());
            for p in &stats {
                let status_str = if p.is_healthy {
                    "Active".bright_green()
                } else {
                    "Cooldown".bright_yellow()
                };
                let display_url = if p.url.len() > 24 {
                    format!("{}...", &p.url[..21])
                } else {
                    p.url.clone()
                };
                println!(
                    "  {:<4} {:<24} {:<10} {:>8} {:>8} {:>6} {:>6} {:>6} {:>8}",
                    p.id,
                    display_url,
                    status_str,
                    format_number(p.total_requests).bright_white(),
                    format_number(p.successes).bright_green(),
                    if p.status_429 > 0 {
                        format_number(p.status_429).bright_yellow()
                    } else {
                        "0".bright_black()
                    },
                    if p.status_403 > 0 {
                        format_number(p.status_403).bright_red()
                    } else {
                        "0".bright_black()
                    },
                    if p.status_5xx > 0 {
                        format_number(p.status_5xx).bright_magenta()
                    } else {
                        "0".bright_black()
                    },
                    if p.failures > 0 {
                        format_number(p.failures).bright_yellow()
                    } else {
                        "0".bright_black()
                    }
                );
            }
            println!();
        }
    }

    // Latency Distribution Section
    println!(
        "{}",
        "── High-Precision Latency Distribution ──────────────────────────────".bright_black()
    );
    if lat.total_samples > 0 {
        println!("  {:<22} {:>16}", "Metric", "Value");
        println!("  {}", "─".repeat(40).bright_black());
        println!(
            "  {:<22} {:>16}",
            "Fastest (Min):",
            format_duration_us(lat.min_us).bright_green()
        );
        println!(
            "  {:<22} {:>16}",
            "Average (Mean):",
            format_duration_us(lat.mean_us as u64).bright_cyan()
        );
        println!(
            "  {:<22} {:>16}",
            "Slowest (Max):",
            format_duration_us(lat.max_us).bright_red()
        );
        println!(
            "  {:<22} {:>16}",
            "Standard Deviation:",
            format_duration_us(lat.std_dev_us as u64).bright_white()
        );
        println!("  {}", "─".repeat(40).bright_black());
        println!(
            "  {:<22} {:>16}",
            "50.00% (p50 / Median):",
            format_duration_us(lat.p50_us).bright_green().bold()
        );
        println!(
            "  {:<22} {:>16}",
            "75.00% (p75):",
            format_duration_us(lat.p75_us).bright_green()
        );
        println!(
            "  {:<22} {:>16}",
            "90.00% (p90):",
            format_duration_us(lat.p90_us).bright_yellow()
        );
        println!(
            "  {:<22} {:>16}",
            "95.00% (p95):",
            format_duration_us(lat.p95_us).bright_yellow()
        );
        println!(
            "  {:<22} {:>16}",
            "99.00% (p99):",
            format_duration_us(lat.p99_us).bright_yellow().bold()
        );
        println!(
            "  {:<22} {:>16}",
            "99.90% (p99.9):",
            format_duration_us(lat.p99_9_us).bright_red()
        );
        println!(
            "  {:<22} {:>16}",
            "99.99% (p99.99):",
            format_duration_us(lat.p99_99_us).bright_red().bold()
        );
        println!();

        // Visual Latency Histogram
        print_latency_histogram(hist);
    } else {
        println!("  {}", "No latency data collected.".bright_red());
    }

    println!(
        "{}",
        "═════════════════════════════════════════════════════════════════════\n"
            .bright_cyan()
            .bold()
    );
}

fn print_status_line(label: &str, count: u64, total: u64, is_success: bool) {
    let pct = if total > 0 {
        (count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let formatted_count = format_number(count);
    let formatted_pct = format!("{:.2}%", pct);

    if is_success {
        println!(
            "  {:<22} {:>14} {:>14}",
            label.bright_green(),
            formatted_count.bright_white(),
            formatted_pct.bright_green()
        );
    } else if count > 0 {
        println!(
            "  {:<22} {:>14} {:>14}",
            label.bright_red(),
            formatted_count.bright_red(),
            formatted_pct.bright_red()
        );
    } else {
        println!(
            "  {:<22} {:>14} {:>14}",
            label.bright_black(),
            "0".bright_black(),
            "0.00%".bright_black()
        );
    }
}

fn print_latency_histogram(hist: &Histogram<u64>) {
    println!(
        "{}",
        "── Latency Percentile Chart ─────────────────────────────────────────".bright_black()
    );

    let quantiles = [
        ("p10", 0.10),
        ("p25", 0.25),
        ("p50", 0.50),
        ("p75", 0.75),
        ("p90", 0.90),
        ("p95", 0.95),
        ("p99", 0.99),
        ("p99.9", 0.999),
    ];

    let max_val = hist.value_at_quantile(0.999).max(1);

    for (label, q) in quantiles {
        let val = hist.value_at_quantile(q);
        let ratio = (val as f64 / max_val as f64).clamp(0.02, 1.0);
        let bar_len = (ratio * 30.0).round() as usize;
        let bar = "■".repeat(bar_len);

        let colored_bar = if q <= 0.75 {
            bar.bright_green()
        } else if q <= 0.95 {
            bar.bright_yellow()
        } else {
            bar.bright_red()
        };

        println!(
            "  {:<6} {:>10}  {:<30}",
            label.bright_white(),
            format_duration_us(val),
            colored_bar
        );
    }
    println!();
}

pub fn format_duration_us(us: u64) -> String {
    if us < 1_000 {
        format!("{} µs", us)
    } else if us < 1_000_000 {
        format!("{:.2} ms", us as f64 / 1_000.0)
    } else {
        format!("{:.3} s", us as f64 / 1_000_000.0)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    result
}
