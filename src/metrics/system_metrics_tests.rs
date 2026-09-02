//! Scrape-level tests for [`bastion_vault::metrics::system_metrics`].
//!
//! They live in the root crate rather than next to the code they exercise
//! because they drive a whole `TestHttpServer` through `crate::test_utils`,
//! which cannot travel into `bv-metrics` without a dependency cycle. See
//! roadmaps/workspace-decomposition.md § Phase 1.

use std::{
    collections::HashMap,
    thread,
    time::{Duration, Instant},
};

use crate::{metrics::system_metrics::*, test_utils::TestHttpServer};

static SYS_METRICS_MAP: &[(&str, &str)] = &[
    (CPU_USAGE_PERCENT, CPU_USAGE_PERCENT_HELP),
    (TOTAL_MEMORY, TOTAL_MEMORY_HELP),
    (USED_MEMORY, USED_MEMORY_HELP),
    (FREE_MEMORY, FREE_MEMORY_HELP),
    (TOTAL_DISK_SPACE, TOTAL_DISK_SPACE_HELP),
    (TOTAL_DISK_AVAILABLE, TOTAL_DISK_AVAILABLE_HELP),
    // (NETWORK_IN, NETWORK_IN_HELP),
    // (NETWORK_OUT, NETWORK_OUT_HELP),
    (LOAD_AVERAGE, LOAD_AVERAGE_HELP),
];

fn parse_gauge(raw: &str) -> HashMap<String, f64> {
    let mut gauge_map = HashMap::new();
    let lines: Vec<&str> = raw.split('\n').collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        if line.ends_with("gauge") {
            let parts: Vec<&str> = lines[i + 1].split(" ").collect();
            // println!("in parse_gauge {}:{}", parts[0], parts[1]);
            let metric_name = parts[0].to_string();
            let value: f64 = parts[1].parse().unwrap();
            gauge_map.insert(metric_name, value);
        }
        i += 1;
    }
    gauge_map
}

/// Every system gauge is registered, scraped, and populated with a real
/// reading.
///
/// **Polls rather than sleeping once, on purpose.** A single fixed sleep raced
/// the collector and failed intermittently. `SystemMetrics::collect_metrics`
/// is slow -- `System::refresh_all` plus a full `Disks` enumeration measured
/// over ten seconds on a loaded host -- and it sets `load_average` *last*, so
/// a scrape landing mid-pass sees the gauges after that point still holding
/// their `Gauge::default()` zero. Which one tripped the old assertion depended
/// on `HashMap` iteration order, so the failure looked like a platform
/// difference in `load_average` rather than the timing bug it was. (It is not
/// a platform difference: `sysinfo`'s Apple path calls `libc::getloadavg`, and
/// the gauge encodes a real value there.)
///
/// So: scrape until every gauge is non-zero, then assert. A genuinely broken
/// gauge still fails, just after the deadline instead of racily before it.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sys_metrics() {
    let server = TestHttpServer::new_with_prometheus("test_sys_metrics", false).await;
    let root_token = &server.root_token;

    // Generous: the first collection pass is the slow one, and CI hosts are
    // slower than this one. The loop exits as soon as the gauges are ready,
    // so the budget costs nothing when the collector is prompt.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut gauge_map;
    loop {
        let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(root_token), None).unwrap();
        assert_eq!(status, 200);

        gauge_map = parse_gauge(resp["metrics"].as_str().unwrap());

        // load average is not available on Windows
        if cfg!(target_os = "windows") {
            gauge_map.remove(LOAD_AVERAGE);
        }

        let pending: Vec<&String> = gauge_map.iter().filter(|(_, v)| **v == 0.0).map(|(k, _)| k).collect();
        if pending.is_empty() && gauge_map.len() == expected_gauge_count() {
            break;
        }
        if Instant::now() >= deadline {
            println!("giving up waiting for gauges; still zero: {pending:?}");
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    assert_eq!(expected_gauge_count(), gauge_map.len(), "scrape did not expose every registered system gauge");

    for (metric, value) in gauge_map {
        println!("{}:{}", metric, value);
        assert!(value != 0.0, "gauge `{metric}` was never populated with a real reading");
    }
}

/// How many system gauges a scrape should expose, accounting for the one the
/// platform does not provide.
fn expected_gauge_count() -> usize {
    if cfg!(target_os = "windows") {
        SYS_METRICS_MAP.len() - 1
    } else {
        SYS_METRICS_MAP.len()
    }
}
