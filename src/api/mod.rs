//! The `bastion_vault::api` module which contains code useful for interacting with a BastionVault server.

use serde_json::Value;

pub mod auth;
pub mod auth_token;
pub mod client;
pub mod logical;
pub mod secret;
pub mod sys;

pub use client::Client;

#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub method: String,
    pub url: String,
    pub response_status: u16,
    pub response_data: Option<Value>,
}

impl HttpResponse {
    pub fn print_debug_info(&self) {
        println!("URL: {} {}", self.method, self.url);
        let is_ok = self.response_status == 200 || self.response_status == 204;
        if is_ok {
            println!("Code: {}.", self.response_status);
        } else {
            println!("Code: {}. Error:", self.response_status);
        }

        if let Some(response_data) = &self.response_data {
            // Prefer the `error` field when present so the user sees a
            // human-readable message instead of the full Debug-formatted
            // JSON Object. Falls back to pretty-printed JSON otherwise.
            if let Some(err) = response_data.get("error").and_then(|v| v.as_str()) {
                println!("{err}");
            } else {
                match serde_json::to_string_pretty(response_data) {
                    Ok(s) => println!("{s}"),
                    Err(_) => println!("{response_data:?}"),
                }
            }
        }
    }
}
