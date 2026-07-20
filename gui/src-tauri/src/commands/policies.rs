use bv_client::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

use crate::error::CmdResult;
use crate::state::AppState;

use super::make_request;

#[derive(Serialize)]
pub struct PolicyListResult {
    pub policies: Vec<String>,
}

#[derive(Serialize)]
pub struct PolicyContent {
    pub name: String,
    pub policy: String,
}

#[derive(Serialize)]
pub struct PolicyHistoryEntry {
    pub ts: String,
    pub user: String,
    /// "create" | "update" | "delete"
    pub op: String,
    pub before_raw: String,
    pub after_raw: String,
}

#[derive(Serialize)]
pub struct PolicyHistoryResult {
    pub entries: Vec<PolicyHistoryEntry>,
}

#[tauri::command]
pub async fn list_policies(state: State<'_, AppState>) -> CmdResult<PolicyListResult> {
    // Server registers this route as `GET /v1/sys/policies/acl` and
    // forces `Operation::List` inside the handler — go through Read
    // (GET) with no trailing slash so actix routing actually matches.
    let resp = make_request(&state, Operation::Read, "sys/policies/acl".to_string(), None).await?;

    match resp {
        Some(r) => {
            if let Some(data) = &r.data {
                if let Some(Value::Array(keys)) = data.get("keys") {
                    let policies: Vec<String> = keys
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    return Ok(PolicyListResult { policies });
                }
            }
            Ok(PolicyListResult { policies: vec![] })
        }
        None => Ok(PolicyListResult { policies: vec![] }),
    }
}

#[tauri::command]
pub async fn read_policy(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PolicyContent> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("sys/policies/acl/{name}"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let policy = r
                .data
                .as_ref()
                .and_then(|d| d.get("policy"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(PolicyContent { name, policy })
        }
        None => Err("Policy not found".into()),
    }
}

#[tauri::command]
pub async fn write_policy(
    state: State<'_, AppState>,
    name: String,
    policy: String,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert("policy".to_string(), Value::String(policy));

    make_request(
        &state,
        Operation::Write,
        format!("sys/policies/acl/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn list_policy_history(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<PolicyHistoryResult> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("sys/policies/acl/{name}/history"),
        None,
    )
    .await?;

    match resp {
        Some(r) => {
            let data = r.data.as_ref();
            let entries = data
                .and_then(|d| d.get("entries"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| {
                            let o = v.as_object()?;
                            Some(PolicyHistoryEntry {
                                ts: o.get("ts").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                user: o.get("user").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                op: o.get("op").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                                before_raw: o
                                    .get("before_raw")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                after_raw: o
                                    .get("after_raw")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(PolicyHistoryResult { entries })
        }
        None => Ok(PolicyHistoryResult { entries: vec![] }),
    }
}

/// One `(path, capability)` assertion to evaluate against a draft policy.
#[derive(Deserialize)]
pub struct PolicyTestCaseInput {
    pub path: String,
    pub capability: String,
    /// Optional environment, forwarded as the `env` request parameter so the
    /// dry-run exercises the rule's env restriction.
    #[serde(default)]
    pub env: Option<String>,
}

/// Per-case verdict from the stateless dry-run endpoint.
#[derive(Serialize, Deserialize, Default)]
pub struct PolicyTestResultRow {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub capability: String,
    #[serde(default)]
    pub allowed: bool,
    #[serde(default)]
    pub matched_path: Option<String>,
    #[serde(default)]
    pub match_kind: String,
    #[serde(default)]
    pub denied_by_deny: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full response from `POST /v2/sys/policies/acl/test`.
#[derive(Serialize, Deserialize, Default)]
pub struct PolicyTestResult {
    #[serde(default)]
    pub parse_ok: bool,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub results: Vec<PolicyTestResultRow>,
}

/// Dry-run a draft policy: parse it and evaluate each `(path, capability)`
/// case against the authoritative ACL matcher, without ever persisting.
/// Backs the Validate & test panel of the graphical policy builder.
#[tauri::command]
pub async fn policy_test(
    state: State<'_, AppState>,
    policy: String,
    cases: Vec<PolicyTestCaseInput>,
) -> CmdResult<PolicyTestResult> {
    let mut body = Map::new();
    body.insert("policy".to_string(), Value::String(policy));
    let cases_json: Vec<Value> = cases
        .into_iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("path".to_string(), Value::String(c.path));
            m.insert("capability".to_string(), Value::String(c.capability));
            if let Some(env) = c.env.filter(|s| !s.is_empty()) {
                m.insert("env".to_string(), Value::String(env));
            }
            Value::Object(m)
        })
        .collect();
    body.insert("cases".to_string(), Value::Array(cases_json));

    let resp = make_request(
        &state,
        Operation::Write,
        "sys/policies/acl/test".to_string(),
        Some(body),
    )
    .await?;

    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let result: PolicyTestResult =
        serde_json::from_value(Value::Object(data)).map_err(|e| e.to_string())?;
    Ok(result)
}

/// A savable effectivity test case attached to a policy.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PolicyTestCase {
    pub path: String,
    pub capability: String,
    /// "allow" | "deny"
    pub expect: String,
    #[serde(default)]
    pub note: String,
    /// Environment fed to the dry-run matcher as the `env` request param.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub env: String,
    /// Value assertion: secret key to compare (checked live at Run time).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect_key: String,
    /// Value assertion: expected value of `expect_key`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expect_value: String,
}

/// Read the saved effectivity test cases attached to a policy (empty when
/// none are saved). Stored alongside, not inside, the policy HCL.
#[tauri::command]
pub async fn read_policy_tests(
    state: State<'_, AppState>,
    name: String,
) -> CmdResult<Vec<PolicyTestCase>> {
    let resp = make_request(
        &state,
        Operation::Read,
        format!("sys/policy-tests/{name}"),
        None,
    )
    .await?;

    let data = resp.and_then(|r| r.data).unwrap_or_default();
    let cases = data.get("cases").cloned().unwrap_or_else(|| Value::Array(vec![]));
    Ok(serde_json::from_value(cases).unwrap_or_default())
}

/// Overwrite the saved effectivity test cases attached to a policy. An
/// empty list clears them.
#[tauri::command]
pub async fn write_policy_tests(
    state: State<'_, AppState>,
    name: String,
    cases: Vec<PolicyTestCase>,
) -> CmdResult<()> {
    let mut body = Map::new();
    body.insert(
        "cases".to_string(),
        serde_json::to_value(&cases).map_err(|e| e.to_string())?,
    );
    make_request(
        &state,
        Operation::Write,
        format!("sys/policy-tests/{name}"),
        Some(body),
    )
    .await?;
    Ok(())
}

#[tauri::command]
pub async fn delete_policy(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    make_request(
        &state,
        Operation::Delete,
        format!("sys/policies/acl/{name}"),
        None,
    )
    .await?;
    Ok(())
}
