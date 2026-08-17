//! Scrape-level tests for [`bastion_vault::metrics::system_metrics`].
//!
//! They live in the root crate rather than next to the code they exercise
//! because they drive a whole `TestHttpServer` through `crate::test_utils`,
//! which cannot travel into `bv-metrics` without a dependency cycle. See
//! roadmaps/workspace-decomposition.md § Phase 1.

use std::{collections::HashMap, thread, time::Duration};

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

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_sys_metrics() {
    let server = TestHttpServer::new_with_prometheus("test_sys_metrics", false).await;
    let root_token = &server.root_token;
    thread::sleep(Duration::from_secs(20));

    let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(root_token), None).unwrap();
    assert_eq!(status, 200);

    let mut gauge_map = parse_gauge(resp["metrics"].as_str().unwrap());
    assert_eq!(SYS_METRICS_MAP.len(), gauge_map.len());

    // load average is not available on Windows
    if cfg!(target_os = "windows") {
        gauge_map.remove("load_average");
    }

    for (metric, value) in gauge_map {
        println!("{}:{}", metric, value);
        assert!(value != 0.0);
    }
}
