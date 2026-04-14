use serde_json::{Map, Value};

use crate::{
    api::{Client, HttpResponse},
    errors::RvError,
    bv_error_string,
};

pub fn kv_read_request(client: &Client, path: &str, data: Option<Map<String, Value>>) -> Result<HttpResponse, RvError> {
    client.request("GET", format!("/v1/{path}"), data)
}

pub fn kv_preflight_version_request(client: &Client, path: &str) -> Result<(String, u32), RvError> {
    let resp = client.request_read(format!("/v1/sys/internal/ui/mounts/{path}"))?;

    if resp.response_status == 404 {
        // If we get a 404 we are using an older version of bastion_vault, default to version 2
        return Ok(("".to_string(), 2));
    }

    let Some(data) = resp.response_data else {
        return Err(bv_error_string!("nil response from pre-flight request"));
    };

    let path = data["path"].as_str().unwrap_or("");
    let version: u32 = if let Some(options) = data.get("options") {
        match options["version"].as_str().unwrap_or("") {
            "1" => 1,
            _ => 2,
        }
    } else {
        1
    };

    Ok((path.to_string(), version))
}

pub fn is_kv_v2(client: &Client, path: &str) -> Result<(String, bool), RvError> {
    let (mount_path, version) = kv_preflight_version_request(client, path)?;
    Ok((mount_path, version == 2))
}
