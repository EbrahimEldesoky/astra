mod args;
mod client;
mod display;
mod evasion;
mod metrics;
mod pacer;
mod proxy_fetcher;
mod scanner;
mod sys;
mod worker;

use anyhow::{Context, Result, bail};
use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use args::Args;
use client::ClientPool;
use display::{create_progress_bar, print_banner, print_final_report, update_progress_bar};
use evasion::EvasionConfig;
use metrics::MetricsCollector;
use pacer::Pacer;
use scanner::{ScanSink, ScannerConfig, print_scan_summary, run_active_probes, write_report};
use sys::{SystemInfo, tune_system_limits};
use worker::run_worker;

fn main() -> Result<()> {
    let args = Args::parse();

    if args.concurrency == 0 {
        bail!("Concurrency must be greater than zero");
    }
    if args.duration == 0 && args.requests.is_none() {
        bail!("Either --duration must be greater than zero, or --requests (-n) must be specified");
    }
    if args.pipeline == 0 {
        bail!("Pipeline depth must be at least 1");
    }

    // -----------------------------------------------------------------------
    // Initialization phase: raise OS resource limits before the runtime and
    // its sockets are created, then size the Tokio runtime to the host.
    // -----------------------------------------------------------------------
    let total_in_flight = args.concurrency.saturating_mul(args.pipeline.max(1));
    let sys_info = tune_system_limits(total_in_flight).unwrap_or_else(|_| SystemInfo {
        initial_nofile_soft: 1024,
        current_nofile_soft: 1024,
        nofile_hard: 4096,
        cpu_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
    });

    let worker_threads = if args.threads == 0 {
        sys_info.cpu_cores
    } else {
        args.threads
    }
    .max(1);

    let runtime = build_runtime(worker_threads, args.pin_cores)?;
    let result = runtime.block_on(run_benchmark(args, sys_info));
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

/// Build an explicitly sized multi-threaded Tokio runtime.
///
/// Tokio's scheduler is work-stealing by default. Giving it one worker per
/// available core (instead of relying on an implicit default) guarantees that
/// every core participates in polling the reactor and executing tasks.
fn build_runtime(worker_threads: usize, pin_cores: bool) -> Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .worker_threads(worker_threads)
        .thread_name("astra-worker")
        .enable_all();

    if pin_cores {
        match core_affinity::get_core_ids() {
            Some(cores) if !cores.is_empty() => {
                let cores = Arc::new(cores);
                let next_core = Arc::new(AtomicUsize::new(0));
                builder.on_thread_start(move || {
                    let index = next_core.fetch_add(1, Ordering::Relaxed) % cores.len();
                    if !core_affinity::set_for_current(cores[index]) {
                        eprintln!(
                            "⚠️  Could not pin a Tokio worker thread to CPU core {}.",
                            cores[index].id
                        );
                    }
                });
            }
            _ => eprintln!(
                "⚠️  CPU affinity is unavailable on this platform; \
                 continuing without core pinning."
            ),
        }
    }

    builder.build().context("Failed to build the Tokio runtime")
}

async fn run_benchmark(args: Args, sys_info: SystemInfo) -> Result<()> {
    // -----------------------------------------------------------------------
    // --fetch-proxies: download fresh proxy lists before starting the engine
    // -----------------------------------------------------------------------
    if args.fetch_proxies {
        let result = proxy_fetcher::fetch_and_update(&args.proxy_output).await;

        if result.file_updated {
            println!(
                "📋  Proxy pool ready: {} unique proxies fetched ({} sources OK, {} failed).",
                result.total_proxies, result.sources_ok, result.sources_failed
            );
        } else if result.total_proxies > 0 {
            println!(
                "📋  Using cached proxy pool: {} proxies in '{}' ({} sources failed).",
                result.total_proxies,
                args.proxy_output.display(),
                result.sources_failed
            );
        } else {
            eprintln!(
                "⚠️  No proxies available — all upstream sources failed and '{}' is empty or absent.\n\
                 Continuing with direct connection mode.",
                args.proxy_output.display()
            );
        }
        println!();
    }

    // Build partitioned HTTP client pool and pre-parsed request specifications
    let client_pool = Arc::new(ClientPool::new(&args, sys_info.cpu_cores)?);

    // Build evasion configuration from CLI flags
    let evasion_cfg = Arc::new(EvasionConfig {
        randomise_headers: args.evasion,
        polymorphic_methods: args.polymorphic,
        post_probability: args.post_ratio.min(95),
        json_probability: args.json_ratio.min(100),
        options_probability: args.options_ratio.min(30),
    });

    if args.evasion {
        println!(
            "🎭  Evasion mode: header fingerprint randomisation ENABLED ({} browser profiles).",
            15
        );
        if args.polymorphic {
            println!(
                "🔀  Polymorphic mode: GET / POST(JSON/form) / OPTIONS distribution \
                 (POST {}%, JSON {}%, OPTIONS {}%).",
                args.post_ratio, args.json_ratio, args.options_ratio
            );
        }
        println!();
    }

    // Build scanner configuration from CLI flags
    let active = args.scan_active || args.probe_paths || args.probe_sqli || args.probe_xss;
    let passive = args.scan || active;
    let any_specific_probe = args.probe_paths || args.probe_sqli || args.probe_xss;
    let probe_paths = args.probe_paths || (args.scan_active && !any_specific_probe);
    let probe_sqli = args.probe_sqli || (args.scan_active && !any_specific_probe);
    let probe_xss = args.probe_xss || (args.scan_active && !any_specific_probe);

    let scan_cfg = Arc::new(ScannerConfig {
        passive_scan: passive,
        active_probe: active,
        probe_paths,
        probe_sqli,
        probe_xss,
        check_headers: args.check_headers,
        output_path: args.scan_output.clone(),
        max_body_scan_bytes: args.scan_max_body,
    });
    let scan_sink = ScanSink::new();

    if passive {
        println!("🔍  Scanner: response anomaly analysis ENABLED.");
        if active {
            print!("🎯  Active probing: ");
            let mut modes = Vec::new();
            if probe_paths {
                modes.push("sensitive paths");
            }
            modes.push("path traversal");
            if probe_sqli {
                modes.push("SQLi canaries");
            }
            if probe_xss {
                modes.push("XSS canaries");
            }
            println!("{}", modes.join(" + "));
        }
        if args.check_headers {
            println!("🛡️   Security header audit ENABLED.");
        }
        println!("📁  Scan output: '{}'", args.scan_output);
        println!();
    }

    // Display banner and configuration parameters
    print_banner(
        &args,
        &sys_info,
        client_pool.client_count(),
        client_pool.proxy_count(),
    );

    let duration = Duration::from_secs(args.duration);
    let pacer = Arc::new(Pacer::new(
        args.rps,
        duration,
        args.requests,
        args.burst_limit,
        args.max_in_flight,
    ));
    let metrics = MetricsCollector::new();

    // Coordinate graceful cancellation (Ctrl+C)
    let cancel_token = CancellationToken::new();
    let cancel_for_signal = cancel_token.clone();
    let pacer_for_signal = Arc::clone(&pacer);

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!(
                "\n⚠️  Interruption signal received (Ctrl+C). Draining in-flight requests..."
            );
            pacer_for_signal.stop();
            cancel_for_signal.cancel();
        }
    });

    // Spawn concurrent worker coroutines
    let pipeline_depth = args.pipeline;
    let no_body = args.no_body;
    let mut worker_handles = Vec::with_capacity(args.concurrency);
    for worker_id in 0..args.concurrency {
        let cp = Arc::clone(&client_pool);
        let spec = Arc::clone(&client_pool.spec);
        let pacer = Arc::clone(&pacer);
        let metrics = Arc::clone(&metrics);
        let cancel = cancel_token.child_token();
        let ev = Arc::clone(&evasion_cfg);
        let sc = Arc::clone(&scan_cfg);
        let sink = Arc::clone(&scan_sink);

        let handle = tokio::spawn(async move {
            run_worker(
                worker_id,
                cp,
                spec,
                pacer,
                metrics,
                cancel,
                pipeline_depth,
                no_body,
                ev,
                sc,
                sink,
            )
            .await;
        });
        worker_handles.push(handle);
    }

    // Spawn active vulnerability probing task concurrently if active probing is enabled
    let probe_handle = if scan_cfg.active_probe {
        let base_url = client_pool.spec.url.clone();
        let sc = Arc::clone(&scan_cfg);
        let sink = Arc::clone(&scan_sink);
        let cp = Arc::clone(&client_pool);
        let cancel = cancel_token.child_token();
        Some(tokio::spawn(async move {
            run_active_probes(&base_url, &sc, &sink, &cp, &cancel).await;
        }))
    } else {
        None
    };

    let start_time = Instant::now();

    // Live progress monitoring
    if !args.no_tui {
        let pb = create_progress_bar(args.duration, args.requests);
        let pacer_check = Arc::clone(&pacer);
        let metrics_check = Arc::clone(&metrics);
        let cancel_check = cancel_token.clone();
        let max_reqs = args.requests;

        let monitor_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            while !pacer_check.is_stopped() && !cancel_check.is_cancelled() {
                interval.tick().await;
                let snapshot = metrics_check.snapshot();
                let elapsed = snapshot.elapsed.as_secs();
                update_progress_bar(&pb, &snapshot, elapsed, max_reqs);
            }
            pb.finish_and_clear();
        });

        // Wait for workers to finish
        for handle in worker_handles {
            let _ = handle.await;
        }

        let _ = monitor_handle.await;
    } else {
        // Headless mode
        for handle in worker_handles {
            let _ = handle.await;
        }
    }

    // Wait for active probing task to complete if active
    if let Some(h) = probe_handle {
        let _ = h.await;
    }

    let total_duration = start_time.elapsed();

    // Consolidate latency metrics and generate comprehensive report
    let (hist, summary) = metrics.consolidate_latencies();
    print_final_report(&metrics, total_duration, &hist, &summary, &client_pool);

    // Write vulnerability scan report and display summary if scanner was active
    if scan_cfg.passive_scan || scan_cfg.active_probe {
        if let Err(e) = write_report(&scan_sink, &scan_cfg.output_path) {
            eprintln!(
                "\n⚠️  Failed to write scan report '{}': {e}",
                scan_cfg.output_path
            );
        }
        print_scan_summary(&scan_sink, &scan_cfg.output_path);
    }

    Ok(())
}
