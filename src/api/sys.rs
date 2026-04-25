use std::time::Duration;

use derive_more::Deref;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{secret::SecretAuth, Client, HttpResponse};
use crate::{
    errors::RvError,
    http::sys::InitRequest,
    utils::{deserialize_duration, serialize_duration},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub lease_id: String,
    #[serde(default)]
    pub lease_duration: u32,
    #[serde(default)]
    pub renewable: bool,
    #[serde(default)]
    pub data: Map<String, Value>,
    #[serde(default)]
    pub auth: Option<SecretAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountOutput {
    #[serde(default)]
    pub uuid: String,
    #[serde(default, rename = "type")]
    pub logical_type: String,
    #[serde(default)]
    pub accessor: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub plugin_version: String,
}

pub type AuthInput = MountInput;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountInput {
    #[serde(default, rename = "type")]
    pub logical_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub config: MountConfigInput,
    #[serde(default)]
    pub options: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountConfigInput {
    #[serde(default, serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub default_lease_ttl: Duration,
    #[serde(default, serialize_with = "serialize_duration", deserialize_with = "deserialize_duration")]
    pub max_lease_ttl: Duration,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub options: Map<String, Value>,
}

#[derive(Deref)]
pub struct Sys<'a> {
    #[deref]
    pub client: &'a Client,
}

impl Client {
    pub fn sys(&self) -> Sys<'_> {
        Sys { client: self }
    }
}

impl Sys<'_> {
    pub fn init(&self, init_req: &InitRequest) -> Result<HttpResponse, RvError> {
        let data = json!({
            "secret_shares": init_req.secret_shares,
            "secret_threshold": init_req.secret_threshold,
        });

        self.request_put(format!("{}/sys/init", self.api_prefix()), data.as_object().cloned())
    }

    pub fn seal_status(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/seal-status", self.api_prefix()))
    }

    pub fn health(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/health", self.api_prefix()))
    }

    pub fn cluster_status(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/cluster-status", self.api_prefix()))
    }

    pub fn cluster_remove_node(&self, node_id: u64, stay_as_learner: bool) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "node_id": node_id,
            "stay_as_learner": stay_as_learner,
        });
        self.request_write(format!("{}/sys/cluster/remove-node", self.api_prefix()), data.as_object().cloned())
    }

    pub fn cluster_leave(&self) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/cluster/leave", self.api_prefix()), None)
    }

    pub fn cluster_failover(&self) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/cluster/failover", self.api_prefix()), None)
    }

    pub fn seal(&self) -> Result<HttpResponse, RvError> {
        self.request_put(format!("{}/sys/seal", self.api_prefix()), None)
    }

    pub fn unseal(&self, key: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "key": key,
        });

        self.request_put(format!("{}/sys/unseal", self.api_prefix()), data.as_object().cloned())
    }

    pub fn list_auth(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/auth", self.api_prefix()))
    }

    pub fn enable_auth(&self, path: &str, input: &AuthInput) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(format!("{}/sys/auth/{path}", self.api_prefix()), data.as_object().cloned())
    }

    pub fn disable_auth(&self, path: &str) -> Result<HttpResponse, RvError> {
        self.request_delete(format!("{}/sys/auth/{path}", self.api_prefix()), None)
    }

    pub fn mount(&self, path: &str, input: &MountInput) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(format!("{}/sys/mounts/{path}", self.api_prefix()), data.as_object().cloned())
    }

    pub fn unmount(&self, path: &str) -> Result<HttpResponse, RvError> {
        self.request_delete(format!("{}/sys/mounts/{path}", self.api_prefix()), None)
    }

    pub fn remount(&self, from: &str, to: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "from": from,
            "to": to,
        });

        self.request_write(format!("{}/sys/remount", self.api_prefix()), data.as_object().cloned())
    }

    pub fn list_mounts(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/mounts", self.api_prefix()))
    }

    pub fn list_policy(&self) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/policies/acl", self.api_prefix()))
    }

    pub fn read_policy(&self, name: &str) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/policies/acl/{name}", self.api_prefix()))
    }

    pub fn write_policy(&self, name: &str, policy: &str) -> Result<HttpResponse, RvError> {
        let data = json!({
            "policy": policy,
        });

        self.request_write(format!("{}/sys/policies/acl/{name}", self.api_prefix()), data.as_object().cloned())
    }

    pub fn delete_policy(&self, name: &str) -> Result<HttpResponse, RvError> {
        self.request_delete(format!("{}/sys/policies/acl/{name}", self.api_prefix()), None)
    }

    pub fn export_secrets(&self, path: &str) -> Result<HttpResponse, RvError> {
        self.request_read(format!("{}/sys/export/{path}", self.api_prefix()))
    }

    pub fn import_secrets(
        &self,
        mount: &str,
        data: Option<serde_json::Map<String, Value>>,
    ) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/import/{mount}", self.api_prefix()), data)
    }

    /// `POST /v1/sys/exchange/export` — returns a JSON envelope whose
    /// `file_b64` field is the base64 of the produced `.bvx` (or
    /// plaintext JSON) document.
    pub fn exchange_export(
        &self,
        body: serde_json::Map<String, Value>,
    ) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/exchange/export", self.api_prefix()), Some(body))
    }

    /// `POST /v1/sys/exchange/import` — single-shot import.
    pub fn exchange_import(
        &self,
        body: serde_json::Map<String, Value>,
    ) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/exchange/import", self.api_prefix()), Some(body))
    }

    /// `POST /v1/sys/exchange/import/preview` — two-step import,
    /// preview phase. Returns a per-item classification table + opaque
    /// `token` for `exchange_apply`.
    pub fn exchange_preview(
        &self,
        body: serde_json::Map<String, Value>,
    ) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/exchange/import/preview", self.api_prefix()), Some(body))
    }

    /// `POST /v1/sys/exchange/import/apply` — consume a preview token.
    pub fn exchange_apply(
        &self,
        body: serde_json::Map<String, Value>,
    ) -> Result<HttpResponse, RvError> {
        self.request_write(format!("{}/sys/exchange/import/apply", self.api_prefix()), Some(body))
    }
}
