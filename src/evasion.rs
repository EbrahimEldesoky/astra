//! # Polymorphic Traffic & Evasion Module
//!
//! Generates realistic, rotating browser fingerprints for every HTTP request
//! to avoid static-signature-based rate limiting and WAF fingerprinting.
//!
//! ## Capabilities
//! - Randomized `User-Agent` from a curated pool of real browser UA strings
//!   covering Chrome, Firefox, and Safari on Windows, macOS, and Linux.
//! - Matching `Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile` headers
//!   (Chrome client hints, correctly paired with the UA).
//! - Randomized `Accept-Language`, `Accept-Encoding`, `Accept`, `Referer`.
//! - Polymorphic payload mode: distributes requests across GET / POST(JSON) /
//!   POST(form) / OPTIONS according to configurable weights.
//! - Zero external dependencies — uses only the Xorshift64* RNG already
//!   embedded in `worker.rs` (replicated as a module-local function here).

use reqwest::Method;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, HeaderMap, HeaderName, HeaderValue, REFERER,
    USER_AGENT,
};
use std::cell::Cell;

// ─────────────────────────────────────────────────────────────────────────────
// Thread-local Xorshift64* RNG (lock-free, allocation-free)
// ─────────────────────────────────────────────────────────────────────────────

thread_local! {
    static RNG: Cell<u64> = Cell::new(
        0xdeadbeefcafe1234u64
            ^ (std::process::id() as u64).wrapping_mul(0x9e3779b97f4a7c15)
    );
}

#[inline(always)]
fn rng_next() -> u64 {
    RNG.with(|c| {
        let mut x = c.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545F4914F6CDD1D);
        c.set(x);
        v
    })
}

#[inline(always)]
fn pick<T>(items: &[T]) -> &T {
    &items[(rng_next() as usize) % items.len()]
}

#[inline(always)]
fn rand_bool(probability_percent: u64) -> bool {
    (rng_next() % 100) < probability_percent
}

// ─────────────────────────────────────────────────────────────────────────────
// Browser profile table
// Each entry: (user_agent, sec_ch_ua, sec_ch_ua_platform, is_mobile, engine)
// engine: 0 = chromium, 1 = firefox, 2 = safari
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Engine {
    Chromium,
    Firefox,
    Safari,
}

struct BrowserProfile {
    ua: &'static str,
    sec_ch_ua: &'static str, // only used for Chromium
    platform: &'static str,  // "Windows" | "macOS" | "Linux" | "Android" | "iOS"
    mobile: bool,
    engine: Engine,
}

static PROFILES: &[BrowserProfile] = &[
    // ── Chrome 124 / Windows ────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua: r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
        platform: "Windows",
        mobile: false,
        engine: Engine::Chromium,
    },
    BrowserProfile {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        sec_ch_ua: r#""Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="24""#,
        platform: "Windows",
        mobile: false,
        engine: Engine::Chromium,
    },
    // ── Chrome 124 / macOS ──────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua: r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
        platform: "macOS",
        mobile: false,
        engine: Engine::Chromium,
    },
    BrowserProfile {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua: r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
        platform: "macOS",
        mobile: false,
        engine: Engine::Chromium,
    },
    // ── Chrome 124 / Linux ──────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        sec_ch_ua: r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
        platform: "Linux",
        mobile: false,
        engine: Engine::Chromium,
    },
    // ── Edge 124 / Windows ──────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        sec_ch_ua: r#""Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99""#,
        platform: "Windows",
        mobile: false,
        engine: Engine::Chromium,
    },
    // ── Chrome 124 / Android (mobile) ───────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        sec_ch_ua: r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#,
        platform: "Android",
        mobile: true,
        engine: Engine::Chromium,
    },
    // ── Firefox 125 / Windows ───────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        sec_ch_ua: "",
        platform: "Windows",
        mobile: false,
        engine: Engine::Firefox,
    },
    BrowserProfile {
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        sec_ch_ua: "",
        platform: "Windows",
        mobile: false,
        engine: Engine::Firefox,
    },
    // ── Firefox 125 / macOS ─────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
        sec_ch_ua: "",
        platform: "macOS",
        mobile: false,
        engine: Engine::Firefox,
    },
    // ── Firefox 125 / Linux ─────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        sec_ch_ua: "",
        platform: "Linux",
        mobile: false,
        engine: Engine::Firefox,
    },
    BrowserProfile {
        ua: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        sec_ch_ua: "",
        platform: "Linux",
        mobile: false,
        engine: Engine::Firefox,
    },
    // ── Safari 17 / macOS ───────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        sec_ch_ua: "",
        platform: "macOS",
        mobile: false,
        engine: Engine::Safari,
    },
    BrowserProfile {
        ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        sec_ch_ua: "",
        platform: "macOS",
        mobile: false,
        engine: Engine::Safari,
    },
    // ── Safari / iOS ────────────────────────────────────────────────────────
    BrowserProfile {
        ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
        sec_ch_ua: "",
        platform: "iOS",
        mobile: true,
        engine: Engine::Safari,
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// Accept-Language pool
// ─────────────────────────────────────────────────────────────────────────────

static ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "ar-SA,ar;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "tr-TR,tr;q=0.9,en;q=0.8",
    "id-ID,id;q=0.9,en;q=0.8",
];

// ─────────────────────────────────────────────────────────────────────────────
// Accept-Encoding pool
// ─────────────────────────────────────────────────────────────────────────────

static ACCEPT_ENCODINGS: &[&str] = &[
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "br, gzip, deflate",
    "identity",
    "gzip",
];

// ─────────────────────────────────────────────────────────────────────────────
// Accept header pool (varies by engine type)
// ─────────────────────────────────────────────────────────────────────────────

static CHROME_ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
];

static FIREFOX_ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
];

static SAFARI_ACCEPTS: &[&str] =
    &["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"];

// ─────────────────────────────────────────────────────────────────────────────
// Referer pool
// ─────────────────────────────────────────────────────────────────────────────

static REFERERS: &[Option<&str>] = &[
    None,
    None,
    None, // 3/N chance of no referer (most realistic)
    Some("https://www.google.com/"),
    Some("https://www.google.com/search?q=site"),
    Some("https://duckduckgo.com/"),
    Some("https://www.bing.com/search?q=site"),
    Some("https://t.co/"),
    Some("https://www.reddit.com/"),
    Some("https://www.linkedin.com/"),
    Some("https://news.ycombinator.com/"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Public API types
// ─────────────────────────────────────────────────────────────────────────────

/// A complete polymorphic fingerprint for a single HTTP request.
pub struct RequestFingerprint {
    /// The HTTP method to use for this request.
    pub method: Method,
    /// Override request body (present for POST payloads). `None` = use the
    /// original body from `RequestSpec`.
    pub body_override: Option<(Vec<u8>, &'static str)>, // (bytes, content-type)
    /// Extra headers to merge on top of the base `RequestSpec` headers.
    pub extra_headers: HeaderMap,
}

/// Configuration knobs for the evasion module (set once, read many times).
#[derive(Debug, Clone)]
pub struct EvasionConfig {
    /// Enable header fingerprint randomisation.
    pub randomise_headers: bool,
    /// Enable polymorphic method / payload distribution.
    pub polymorphic_methods: bool,
    /// Probability (0–100) that a request is sent as POST instead of GET.
    pub post_probability: u64,
    /// Probability (0–100) that a POST uses JSON (vs form-data).
    pub json_probability: u64,
    /// Probability (0–100) that a request is sent as OPTIONS.
    pub options_probability: u64,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            randomise_headers: true,
            polymorphic_methods: false,
            post_probability: 20,
            json_probability: 60,
            options_probability: 5,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Core fingerprint generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a fresh [`RequestFingerprint`] for every outgoing request.
///
/// This function is `#[inline]` to keep hot-loop overhead minimal; the random
/// picks are a handful of integer operations each.
#[inline]
pub fn generate_fingerprint(
    cfg: &EvasionConfig,
    original_method: &Method,
    original_body: &Option<Vec<u8>>,
) -> RequestFingerprint {
    // Avoid an allocation on the common path where evasion is disabled.
    let mut extra_headers = if cfg.randomise_headers {
        HeaderMap::with_capacity(10)
    } else {
        HeaderMap::new()
    };

    // ── 1. Browser profile ──────────────────────────────────────────────────
    if cfg.randomise_headers {
        let profile = pick(PROFILES);

        // User-Agent
        extra_headers.insert(USER_AGENT, HeaderValue::from_static(profile.ua));

        // Engine-specific Client Hints (Chromium only)
        if let Engine::Chromium = profile.engine {
            if !profile.sec_ch_ua.is_empty() {
                if let Ok(v) = HeaderValue::from_str(profile.sec_ch_ua) {
                    extra_headers.insert(HeaderName::from_static("sec-ch-ua"), v);
                }
                extra_headers.insert(
                    HeaderName::from_static("sec-ch-ua-mobile"),
                    HeaderValue::from_static(if profile.mobile { "?1" } else { "?0" }),
                );
                extra_headers.insert(
                    HeaderName::from_static("sec-ch-ua-platform"),
                    // Platform must be a quoted string in the CH-UA spec
                    HeaderValue::from_str(&format!("\"{}\"", profile.platform))
                        .unwrap_or(HeaderValue::from_static("\"Windows\"")),
                );
            }

            // Chromium always sends Sec-Fetch-* headers
            extra_headers.insert(
                HeaderName::from_static("sec-fetch-dest"),
                HeaderValue::from_static("document"),
            );
            extra_headers.insert(
                HeaderName::from_static("sec-fetch-mode"),
                HeaderValue::from_static("navigate"),
            );
            extra_headers.insert(
                HeaderName::from_static("sec-fetch-site"),
                if rand_bool(30) {
                    HeaderValue::from_static("same-origin")
                } else {
                    HeaderValue::from_static("none")
                },
            );
            extra_headers.insert(
                HeaderName::from_static("sec-fetch-user"),
                HeaderValue::from_static("?1"),
            );
        }

        // Accept
        let accept = match profile.engine {
            Engine::Chromium => *pick(CHROME_ACCEPTS),
            Engine::Firefox => *pick(FIREFOX_ACCEPTS),
            Engine::Safari => *pick(SAFARI_ACCEPTS),
        };
        if let Ok(v) = HeaderValue::from_str(accept) {
            extra_headers.insert(ACCEPT, v);
        }

        // Accept-Language
        if let Ok(v) = HeaderValue::from_str(pick(ACCEPT_LANGS)) {
            extra_headers.insert(ACCEPT_LANGUAGE, v);
        }

        // Accept-Encoding
        if let Ok(v) = HeaderValue::from_str(pick(ACCEPT_ENCODINGS)) {
            extra_headers.insert(ACCEPT_ENCODING, v);
        }

        // Referer (optional)
        if let Some(referer) = pick(REFERERS) {
            if let Ok(v) = HeaderValue::from_str(referer) {
                extra_headers.insert(REFERER, v);
            }
        }

        // DNT (Do Not Track) — randomly present
        if rand_bool(35) {
            extra_headers.insert(
                HeaderName::from_static("dnt"),
                HeaderValue::from_static("1"),
            );
        }

        // Upgrade-Insecure-Requests — browsers send this on navigation
        if rand_bool(70) {
            extra_headers.insert(
                HeaderName::from_static("upgrade-insecure-requests"),
                HeaderValue::from_static("1"),
            );
        }

        // Cache-Control — vary between no-cache / max-age=0 / empty
        let cc_roll = rng_next() % 4;
        if cc_roll == 0 {
            extra_headers.insert(
                reqwest::header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache"),
            );
        } else if cc_roll == 1 {
            extra_headers.insert(
                reqwest::header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=0"),
            );
        }
        // else: omit Cache-Control entirely (most realistic for non-reload navigations)
    }

    // ── 2. Polymorphic method / payload ─────────────────────────────────────
    let (method, body_override) = if cfg.polymorphic_methods {
        choose_method_and_body(cfg, original_method, original_body)
    } else {
        (original_method.clone(), None)
    };

    RequestFingerprint {
        method,
        body_override,
        extra_headers,
    }
}

/// Randomly select an HTTP method and, if POST, generate a matching payload.
fn choose_method_and_body(
    cfg: &EvasionConfig,
    original_method: &Method,
    original_body: &Option<Vec<u8>>,
) -> (Method, Option<(Vec<u8>, &'static str)>) {
    let roll = rng_next() % 100;

    // OPTIONS probe (low probability — avoids overwhelming CORS handlers)
    if roll < cfg.options_probability {
        return (Method::OPTIONS, None);
    }

    // POST with synthetic payload
    if roll < cfg.options_probability + cfg.post_probability {
        let use_json = rand_bool(cfg.json_probability);

        // If caller already provided a body, reuse it rather than generating noise
        if let Some(body) = original_body {
            let ct = if use_json {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };
            return (Method::POST, Some((body.clone(), ct)));
        }

        // Generate minimal synthetic payloads to keep overhead low
        if use_json {
            let json = format!(
                r#"{{"ts":{},"id":"{}","v":{}}}"#,
                pseudo_ts(),
                hex8(rng_next()),
                rng_next() % 1000
            );
            return (Method::POST, Some((json.into_bytes(), "application/json")));
        } else {
            let form = format!(
                "token={}&ref={}&t={}",
                hex8(rng_next()),
                hex8(rng_next()),
                pseudo_ts()
            );
            return (
                Method::POST,
                Some((form.into_bytes(), "application/x-www-form-urlencoded")),
            );
        }
    }

    // Default: preserve the original method
    (original_method.clone(), None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tiny helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Pseudo Unix timestamp (seconds) — derived from the RNG, not wall clock,
/// to avoid any `SystemTime` overhead in the hot loop.
#[inline]
fn pseudo_ts() -> u64 {
    // Produce a plausible-looking epoch second in ~2024 range
    1_700_000_000u64.wrapping_add(rng_next() % 31_536_000)
}

/// Format a u64 as 8 lowercase hex characters.
#[inline]
fn hex8(v: u64) -> String {
    format!("{:08x}", v & 0xFFFF_FFFF)
}
