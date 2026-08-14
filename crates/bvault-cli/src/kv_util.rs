use serde_json::{Map, Value};

use crate::{
    api::{Client, HttpResponse},
    errors::RvError,
    bv_error_string,
};

pub fn kv_read_request(client: &Client, path: &str, data: Option<Map<String, Value>>) -> Result<HttpResponse, RvError> {
    client.request("GET", format!("{}/{path}", client.api_prefix()), data)
}

pub fn kv_preflight_version_request(client: &Client, path: &str) -> Result<(String, u32), RvError> {
    let resp = client.request_read(format!("{}/sys/internal/ui/mounts/{path}", client.api_prefix()))?;

    if resp.response_status == 404 {
        // If we get a 404 we are using an older version of bastion_vault, default to version 2
        return Ok(("".to_string(), 2));
    }

    let Some(data) = resp.response_data else {
        return Err(bv_error_string!("nil response from pre-flight request"));
    };

    let path = data["path"].as_str().unwrap_or("");
    // Treat the mount as KV v2 only when the options explicitly opt in
    // with version="2". Missing options, missing version key, or any other
    // value (including the common version="1") mean KV v1.
    let version: u32 = match data.get("options") {
        Some(options) => match options.get("version").and_then(|v| v.as_str()).unwrap_or("") {
            "2" => 2,
            _ => 1,
        },
        None => 1,
    };

    Ok((path.to_string(), version))
}

pub fn is_kv_v2(client: &Client, path: &str) -> Result<(String, bool), RvError> {
    let (mount_path, version) = kv_preflight_version_request(client, path)?;
    Ok((mount_path, version == 2))
}
