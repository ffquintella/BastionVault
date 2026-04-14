use std::collections::HashMap;

use derive_more::Deref;
use serde::{Deserialize, Serialize};

use super::{Client, HttpResponse};
use crate::errors::RvError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenInput {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub meta: HashMap<String, String>,
    #[serde(default)]
    pub lease: String,
    #[serde(default)]
    pub ttl: String,
    #[serde(default)]
    pub explicit_max_ttl: String,
    #[serde(default)]
    pub period: String,
    #[serde(default)]
    pub no_parent: bool,
    #[serde(default)]
    pub no_default_policy: bool,
    pub display_name: String,
    pub num_uses: u32,
    #[serde(default)]
    pub renewable: bool,
    #[serde(default, rename = "type")]
    pub logical_type: String,
}

#[derive(Deref)]
pub struct TokenAuth<'a> {
    #[deref]
    pub client: &'a Client,
}

impl Client {
    pub fn token(&self) -> TokenAuth<'_> {
        TokenAuth { client: self }
    }
}

impl TokenAuth<'_> {
    pub fn create(&self, input: &TokenInput) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(format!("{}/auth/token/create", self.api_prefix()), data.as_object().cloned())
    }

    pub fn create_orphan(&self, input: &TokenInput) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(format!("{}/auth/token/create-orphan", self.api_prefix()), data.as_object().cloned())
    }

    pub fn create_with_role(&self, input: &TokenInput, role_name: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::to_value(input)?;
        self.request_write(format!("{}/auth/token/create/{role_name}", self.api_prefix()), data.as_object().cloned())
    }

    pub fn lookup(&self, token: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "token": token,
        });
        self.request_write(format!("{}/auth/token/lookup", self.api_prefix()), data.as_object().cloned())
    }

    pub fn lookup_accessor(&self, accessor: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "accessor": accessor,
        });
        self.request_write(format!("{}/auth/token/lookup-accessor", self.api_prefix()), data.as_object().cloned())
    }

    pub fn lookup_self(&self) -> Result<HttpResponse, RvError> {
        self.request_get(format!("{}/auth/token/lookup-self", self.api_prefix()))
    }

    pub fn renew(&self, token: &str, increment: u32) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "token": token,
            "increment": increment,
        });
        self.request_write(format!("{}/auth/token/renew", self.api_prefix()), data.as_object().cloned())
    }

    pub fn renew_accessor(&self, accessor: &str, increment: u32) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "accessor": accessor,
            "increment": increment,
        });
        self.request_write(format!("{}/auth/token/renew-accessor", self.api_prefix()), data.as_object().cloned())
    }

    pub fn renew_self(&self, increment: u32) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "increment": increment,
        });
        self.request_write(format!("{}/auth/token/renew-self", self.api_prefix()), data.as_object().cloned())
    }

    pub fn renew_token_as_self(&self, token: &str, increment: u32) -> Result<HttpResponse, RvError> {
        let mut client = self.client.clone();
        client.token = token.to_string();
        let data = serde_json::json!({
            "increment": increment,
        });
        client.request_write(format!("{}/auth/token/renew-self", client.api_prefix()), data.as_object().cloned())
    }

    pub fn revoke_accessor(&self, accessor: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "accessor": accessor,
        });
        self.request_write(format!("{}/auth/token/revoke-accessor", self.api_prefix()), data.as_object().cloned())
    }

    pub fn revoke_orphan(&self, token: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "token": token,
        });
        self.request_put(format!("{}/auth/token/revoke-orphan", self.api_prefix()), data.as_object().cloned())
    }

    pub fn revoke_self(&self) -> Result<HttpResponse, RvError> {
        self.request_put(format!("{}/auth/token/revoke-self", self.api_prefix()), None)
    }

    pub fn revoke_tree(&self, token: &str) -> Result<HttpResponse, RvError> {
        let data = serde_json::json!({
            "token": token,
        });
        self.request_put(format!("{}/auth/token/revoke", self.api_prefix()), data.as_object().cloned())
    }
}
