//! Scrape-level tests for [`bastion_vault::metrics::http_metrics`].
//!
//! They live in the root crate rather than next to the code they exercise
//! because they drive a whole `TestHttpServer` through `crate::test_utils`,
//! which cannot travel into `bv-metrics` without a dependency cycle. See
//! roadmaps/workspace-decomposition.md § Phase 1.

use std::collections::HashMap;


use regex::Regex;
use serde_json::json;

use crate::test_utils::TestHttpServer;

const PATH: &str = "path";
const METHOD: &str = "method";

const GET: &str = "GET";
const LIST: &str = "LIST";
const POST: &str = "POST";
const PUT: &str = "PUT";
const DELETE: &str = "DELETE";

fn parse_counter(raw: &str) -> HashMap<String, HashMap<String, u32>> {
    let lines: Vec<&str> = raw.split('\n').collect();
    let mut i = 0;
    let mut counter_map: HashMap<String, HashMap<String, u32>> = HashMap::new();
    let name_label_re =
        Regex::new(r#"\bpath="(?P<path>[^"]+)",method="(?P<method>[^"]+)",status="(?P<status>[^"]+)""#).unwrap();

    while i < lines.len() {
        let line = lines[i];
        if line.ends_with("counter") {
            // move to next line, which is counter
            i += 1;
            let parts: Vec<&str> = lines[i].split("{").collect();
            let metric_name = parts[0];

            // capture following counter lines
            while lines[i].starts_with(metric_name) {
                let parts: Vec<&str> = lines[i].split(" ").collect();
                let name_label = parts[0];
                let value: u32 = parts[1].parse().unwrap();

                if let Some(caps) = name_label_re.captures(name_label) {
                    let path = caps[PATH].to_string();
                    let method = caps[METHOD].to_string().to_uppercase();
                    if let Some(req) = counter_map.get_mut(&path) {
                        req.insert(method, value);
                    } else {
                        let mut req: HashMap<String, u32> = HashMap::new();
                        req.insert(method, value);
                        println!("path:{}", &path);
                        counter_map.insert(path, req);
                    }
                }

                i += 1;
            }
        }
        i += 1;
    }
    counter_map
}

#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_http_request() {
    let server = TestHttpServer::new_with_prometheus("test_http_request", false).await;
    let root_token = &server.root_token;

    let path = ["v1/secret/password-0", "v1/secret/password-1", "v1/secret/password-2", "v1/secret"];
    let mock = [
        vec![(DELETE, 2)],
        vec![(POST, 3), (GET, 5), (PUT, 7), (DELETE, 9)],
        vec![(POST, 2), (GET, 8), (PUT, 12), (DELETE, 16)],
        vec![(LIST, 1)],
    ];
    let mut mock_map: HashMap<&str, Vec<(&str, u32)>> = HashMap::new();
    for (p, m) in path.iter().zip(mock.iter()) {
        mock_map.insert(p, m.to_vec());
    }

    for (path, mock) in &mock_map {
        for request in mock {
            let method = request.0;
            let count = request.1;
            for _ in 0..count {
                if method == "POST" || method == "PUT" {
                    let random_number: u32 = {
                        use rand::RngExt;
                        rand::rng().random_range(0..10000)
                    };
                    let data = json!({
                        "password": random_number,
                    })
                    .as_object()
                    .unwrap()
                    .clone();
                    let (_, _) = server.request(method, path, Some(data), Some(root_token), None).unwrap();
                } else {
                    let (_, _) = server.request(method, path, None, Some(root_token), None).unwrap();
                }
            }
        }
    }

    let (status, resp) = server.request_prometheus("GET", "metrics", None, Some(root_token), None).unwrap();
    assert_eq!(status, 200);

    let counter_map = parse_counter(resp["metrics"].as_str().unwrap());
    println!("counter map len={}", counter_map.len());

    for (path, mock) in &mock_map {
        for mock_req in mock {
            let method = mock_req.0;
            let count = mock_req.1;
            let path = format!("/{}", path);
            assert!(counter_map.contains_key(&path));

            let prom = counter_map.get(&path).unwrap();
            assert!(prom.contains_key(method));

            let value = *prom.get(method).unwrap();
            assert_eq!(count, value);
        }
    }
}
