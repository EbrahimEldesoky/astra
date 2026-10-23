//! # Dynamic Proxy Pool Feeder
//!
//! Fetches open-source / publicly available proxy lists from GitHub raw URLs
//! and writes them into the local `proxies.txt` file for use by the load engine.
//!
//! Features:
//! - Async fetch via `reqwest` + `tokio`
//! - Deduplication and format normalisation (ensures `scheme://host:port`)
//! - Graceful fallback: if every upstream source fails, the existing local file
//!   is left untouched so the benchmark can still proceed.
//! - Configurable output path (defaults to `proxies.txt` in the working directory)

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Public upstream sources
// Each entry is a raw GitHub (or similar) URL returning a plain-text list of
// proxies — one entry per line in `host:port` or `scheme://host:port` format.
// ---------------------------------------------------------------------------
const PROXY_SOURCES: &[(&str, &str)] = &[
    (
        "TheSpeedX/PROXY-List (HTTP)",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    ),
    (
        "TheSpeedX/PROXY-List (SOCKS4)",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    ),
    (
        "TheSpeedX/PROXY-List (SOCKS5)",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    ),
    (
        "clarketm/proxy-list",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    ),
    (
        "monosans/proxy-list (HTTP)",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ),
    (
        "monosans/proxy-list (SOCKS4)",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    ),
    (
        "monosans/proxy-list (SOCKS5)",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ),
    (
        "hookzof/socks5_list",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    ),
    (
        "ShiftyTR/Proxy-List (HTTP)",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    ),
    (
        "ShiftyTR/Proxy-List (HTTPS)",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    ),
    (
        "ShiftyTR/Proxy-List (SOCKS5)",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    ),
    (
        "jetkai/proxy-list (HTTP)",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    ),
    (
        "jetkai/proxy-list (SOCKS5)",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    ),
];

/// Per-source connection + read timeout.
const FETCH_TIMEOUT_SECS: u64 = 20;

/// User-Agent sent with every upstream request.
const FETCH_USER_AGENT: &str = "astra-proxy-fetcher/0.1";

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

pub struct FetchResult {
    /// Total unique proxies written to disk (or already present locally).
    pub total_proxies: usize,
    /// Number of upstream sources that responded successfully.
    pub sources_ok: usize,
    /// Number of upstream sources that failed (network error / timeout).
    pub sources_failed: usize,
    /// `true` if the local file was actually overwritten with fresh data.
    pub file_updated: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetches all configured upstream sources concurrently, deduplicates the
/// results, and writes them to `output_path`.
///
/// On complete failure (no source reachable) the existing local file is kept
/// intact as a fallback so the benchmark can still proceed.
pub async fn fetch_and_update(output_path: &Path) -> FetchResult {
    println!(
        "🌐  Fetching proxy lists from {} upstream sources…",
        PROXY_SOURCES.len()
    );

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(FETCH_USER_AGENT)
        .tcp_nodelay(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to build HTTP client for proxy fetcher: {e}");
            return FetchResult {
                total_proxies: count_local(output_path),
                sources_ok: 0,
                sources_failed: PROXY_SOURCES.len(),
                file_updated: false,
            };
        }
    };

    // Fire all upstream requests concurrently.
    let mut task_handles = Vec::with_capacity(PROXY_SOURCES.len());
    for &(label, url) in PROXY_SOURCES {
        let c = client.clone();
        task_handles.push(tokio::spawn(async move { fetch_one(&c, label, url).await }));
    }

    let mut all_proxies: HashSet<String> = HashSet::new();
    let mut sources_ok = 0usize;
    let mut sources_failed = 0usize;

    for task in task_handles {
        match task.await {
            Ok(Ok((label, proxies))) => {
                println!("  ✓  [{label}] — {} entries", proxies.len());
                all_proxies.extend(proxies);
                sources_ok += 1;
            }
            Ok(Err((label, err))) => {
                eprintln!("  ✗  [{label}] — {err}");
                sources_failed += 1;
            }
            Err(e) => {
                eprintln!("  ✗  [task error] — {e}");
                sources_failed += 1;
            }
        }
    }

    // Fallback: if all sources failed, preserve the existing local file.
    if all_proxies.is_empty() {
        eprintln!(
            "\n⚠️  All {} proxy sources failed to respond. \
             Keeping the existing '{}' as fallback.\n",
            PROXY_SOURCES.len(),
            output_path.display()
        );
        return FetchResult {
            total_proxies: count_local(output_path),
            sources_ok: 0,
            sources_failed,
            file_updated: false,
        };
    }

    let mut sorted: Vec<String> = all_proxies.into_iter().collect();
    sorted.sort_unstable();

    match write_proxy_file(output_path, &sorted) {
        Ok(()) => {
            println!(
                "\n✅  Wrote {} unique proxies → '{}'\n",
                sorted.len(),
                output_path.display()
            );
            FetchResult {
                total_proxies: sorted.len(),
                sources_ok,
                sources_failed,
                file_updated: true,
            }
        }
        Err(e) => {
            eprintln!(
                "\n⚠️  Could not write '{}': {e}. \
                 Keeping existing file as fallback.\n",
                output_path.display()
            );
            FetchResult {
                total_proxies: count_local(output_path),
                sources_ok,
                sources_failed,
                file_updated: false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Fetch a single upstream source and return its normalised proxy list.
async fn fetch_one(
    client: &reqwest::Client,
    label: &'static str,
    url: &'static str,
) -> Result<(&'static str, Vec<String>), (&'static str, String)> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| (label, format!("request error: {e}")))?;

    if !response.status().is_success() {
        return Err((label, format!("HTTP {}", response.status())));
    }

    let text = response
        .text()
        .await
        .map_err(|e| (label, format!("body read error: {e}")))?;

    let proxies = parse_proxy_list(&text, url);
    Ok((label, proxies))
}

/// Parse a raw text proxy list into normalised `scheme://host:port` strings.
///
/// Handles:
/// - `host:port`  (assumed HTTP unless source URL implies socks)
/// - `http://host:port`, `https://host:port`
/// - `socks4://host:port`, `socks5://host:port`
/// - Lines beginning with `#` are skipped
fn parse_proxy_list(text: &str, source_url: &str) -> Vec<String> {
    let default_scheme = infer_scheme_from_source(source_url);

    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            // Already has a scheme — do a quick sanity check.
            if trimmed.contains("://") {
                let after = trimmed.splitn(2, "://").nth(1).unwrap_or("");
                if after.contains(':') {
                    return Some(trimmed.to_string());
                }
                return None;
            }
            // Plain `host:port`
            if trimmed.contains(':') {
                return Some(format!("{default_scheme}://{trimmed}"));
            }
            None
        })
        .collect()
}

/// Guess the scheme to prepend to bare `host:port` entries based on keywords
/// present in the upstream source URL.
fn infer_scheme_from_source(source_url: &str) -> &'static str {
    let lower = source_url.to_lowercase();
    if lower.contains("socks5") {
        "socks5"
    } else if lower.contains("socks4") {
        "socks4"
    } else {
        "http"
    }
}

/// Write the final deduplicated proxy list to disk with a human-readable header.
fn write_proxy_file(path: &Path, proxies: &[String]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut file = std::fs::File::create(path)?;

    writeln!(
        file,
        "# Astra Proxy List — auto-generated by --fetch-proxies"
    )?;
    writeln!(file, "# Generated: {}", now_utc_string())?;
    writeln!(file, "# Total: {} unique proxies", proxies.len())?;
    writeln!(file, "#")?;
    writeln!(
        file,
        "# Formats: http://host:port | https://host:port | socks4://host:port | socks5://host:port"
    )?;
    writeln!(file, "# Lines starting with '#' are ignored by Astra.")?;
    writeln!(
        file,
        "# -------------------------------------------------------------"
    )?;
    writeln!(file)?;

    for proxy in proxies {
        writeln!(file, "{proxy}")?;
    }

    Ok(())
}

/// Count the number of active (non-comment, non-empty) entries in the existing
/// local proxy file.
fn count_local(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count()
}

/// Minimal UTC timestamp string without external crate dependencies.
fn now_utc_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let total_days = secs / 86400;
    // Simple (approximate) Gregorian calendar — accurate enough for a header comment.
    let mut year = 1970u64;
    let mut remaining_days = total_days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let month_days: [u64; 12] = [
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
    for days in month_days {
        if remaining_days < days {
            break;
        }
        remaining_days -= days;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

#[inline]
fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
