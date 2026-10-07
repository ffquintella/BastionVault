//! Credential-provider authoring surface (ABI 1.3).
//!
//! Spec: features/self-accounts.md §4. A provider plugin declares
//! `caller_identity`, `storage_scope = "entity"` and
//! `[capabilities.credential_provider]` in its manifest. The host then adds an
//! attested `caller` block to every envelope and confines `bv.storage_*` to
//! that caller's entity, so the plugin never addresses another user's data.
//!
//! A provider implements [`CredentialProvider`] and wires itself up with
//! [`provider_module!`]. The two provider ops, `provider.candidates` and
//! `provider.release`, are decoded and answered here; every other op reaches
//! [`CredentialProvider::handle_logical`], the plugin's own API.
//!
//! The released secret never goes through `Debug`: [`Released`] has no
//! `Debug` impl for its secret field and the SDK's [`ProviderError`] carries
//! only a fixed message.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::{Host, Request, Response};

/// The host-attested caller. Present on every envelope of a plugin that
/// declares `caller_identity`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Caller {
    pub entity_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub principal: Principal,
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Principal {
    #[serde(default)]
    pub mount: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub os_type: Option<String>,
}

/// The target being dialled. `Host` for SSH/RDP, `Origins` for web `form`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Target {
    Host { host: String, port: u16 },
    Origins { origins: Vec<String> },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CandidatesQuery {
    pub protocol: String,
    pub resource: Resource,
    pub target: Target,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub struct Needs {
    #[serde(default)]
    pub password: bool,
    #[serde(default)]
    pub totp: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ConnectContext {
    pub mfa_verified: bool,
    pub transport: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReleaseRequest {
    pub account_id: String,
    pub protocol: String,
    pub resource: Resource,
    pub target: Target,
    #[serde(default)]
    pub needs: Needs,
    pub connect: ConnectContext,
}

/// One account the operator may pick. Metadata only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub label: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub secret_kind: String,
    pub has_totp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// The secret half of a released credential.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ReleasedSecret {
    Password {
        password: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        totp_seed: Option<String>,
    },
    SshKey {
        private_key: String,
    },
}

/// A released credential. Deliberately no `Debug`.
#[derive(Serialize)]
pub struct Released {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub secret: ReleasedSecret,
}

/// A refusal. The message is returned to the host verbatim, so it must never
/// contain secret material; the SDK offers no way to attach any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub status: i32,
    pub message: &'static str,
}

impl ProviderError {
    /// Not found, or does not match this resource, protocol and target.
    pub const NO_MATCH: Self = Self { status: 2, message: "no matching account" };
    pub const MFA_REQUIRED: Self = Self { status: 3, message: "connect-time MFA is required" };
    pub const BAD_REQUEST: Self = Self { status: 4, message: "malformed request" };
    pub const INTERNAL: Self = Self { status: 5, message: "provider error" };
}

/// A non-provider op, handed to [`CredentialProvider::handle_logical`].
#[derive(Debug, Clone)]
pub struct LogicalOp {
    /// `read`, `write`, `delete`, `list`, ...
    pub op: String,
    /// Path relative to the mount.
    pub path: String,
    pub data: serde_json::Value,
}

/// What a credential provider implements.
pub trait CredentialProvider {
    fn candidates(
        caller: &Caller,
        query: &CandidatesQuery,
        host: &Host,
    ) -> Result<Vec<Candidate>, ProviderError>;

    fn release(
        caller: &Caller,
        req: &ReleaseRequest,
        host: &Host,
    ) -> Result<Released, ProviderError>;

    /// The plugin's own API (its CRUD paths). `caller` is the attested caller.
    fn handle_logical(caller: &Caller, op: LogicalOp, host: &Host) -> Response;
}

fn err(e: ProviderError) -> Response {
    Response::err(e.status, e.message.as_bytes().to_vec())
}

fn data<T: Serialize>(v: &T) -> Response {
    match serde_json::to_vec(&serde_json::json!({ "data": v })) {
        Ok(b) => Response::ok(b),
        Err(_) => err(ProviderError::INTERNAL),
    }
}

/// Decode the envelope and route it. Used by [`provider_module!`].
pub fn dispatch<P: CredentialProvider>(req: Request<'_>, host: &Host) -> Response {
    #[derive(Deserialize)]
    struct Envelope {
        op: String,
        #[serde(default)]
        path: String,
        #[serde(default)]
        data: serde_json::Value,
        #[serde(default)]
        caller: Option<Caller>,
    }
    let Ok(env) = serde_json::from_slice::<Envelope>(req.input()) else {
        return err(ProviderError::BAD_REQUEST);
    };
    // The host refuses an entity-scoped plugin before it runs when there is no
    // entity, so a missing caller here is a host bug: fail closed.
    let Some(caller) = env.caller.filter(|c| !c.entity_id.is_empty()) else {
        return err(ProviderError::BAD_REQUEST);
    };
    match env.op.as_str() {
        "provider.candidates" => match serde_json::from_value::<CandidatesQuery>(env.data) {
            Ok(q) => match P::candidates(&caller, &q, host) {
                Ok(c) => data(&serde_json::json!({ "candidates": c })),
                Err(e) => err(e),
            },
            Err(_) => err(ProviderError::BAD_REQUEST),
        },
        "provider.release" => match serde_json::from_value::<ReleaseRequest>(env.data) {
            Ok(r) => match P::release(&caller, &r, host) {
                Ok(c) => data(&c),
                Err(e) => err(e),
            },
            Err(_) => err(ProviderError::BAD_REQUEST),
        },
        other if other.starts_with("provider.") => err(ProviderError::BAD_REQUEST),
        _ => P::handle_logical(
            &caller,
            LogicalOp { op: env.op, path: env.path, data: env.data },
            host,
        ),
    }
}

/// Adapter so [`provider_module!`] can reuse [`register!`](crate::register).
pub struct Adapter<P>(core::marker::PhantomData<P>);

impl<P: CredentialProvider> crate::Plugin for Adapter<P> {
    fn handle(req: Request<'_>, host: &Host) -> Response {
        dispatch::<P>(req, host)
    }
}

/// Wire a [`CredentialProvider`] up to the WASM ABI.
///
/// ```ignore
/// provider_module!(SelfAccounts);
/// ```
#[macro_export]
macro_rules! provider_module {
    ($provider:ty) => {
        $crate::register!($crate::provider::Adapter<$provider>);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct P;
    impl CredentialProvider for P {
        fn candidates(
            caller: &Caller,
            q: &CandidatesQuery,
            _h: &Host,
        ) -> Result<Vec<Candidate>, ProviderError> {
            if q.protocol == "web" {
                return Err(ProviderError::NO_MATCH);
            }
            Ok(vec![Candidate {
                id: "a1".into(),
                label: caller.entity_id.clone(),
                username: "u".into(),
                domain: None,
                secret_kind: "password".into(),
                has_totp: false,
                last_used_at: None,
            }])
        }
        fn release(_c: &Caller, r: &ReleaseRequest, _h: &Host) -> Result<Released, ProviderError> {
            if !r.connect.mfa_verified {
                return Err(ProviderError::MFA_REQUIRED);
            }
            Ok(Released {
                username: "u".into(),
                domain: None,
                secret: ReleasedSecret::Password { password: "hunter2".into(), totp_seed: None },
            })
        }
        fn handle_logical(_c: &Caller, op: LogicalOp, _h: &Host) -> Response {
            Response::ok(op.path.into_bytes())
        }
    }

    fn run(json: &str) -> Response {
        dispatch::<P>(Request::new(json.as_bytes()), &Host::new())
    }

    const CALLER: &str = r#""caller":{"entity_id":"e1","principal":{"mount":"userpass/","name":"f"}}"#;

    #[test]
    fn candidates_roundtrip() {
        let r = run(&alloc::format!(
            r#"{{"op":"provider.candidates",{CALLER},"data":{{"protocol":"ssh","resource":{{"type":"server"}},"target":{{"host":"h","port":22}}}}}}"#
        ));
        assert_eq!(r.status, 0);
        let v: serde_json::Value = serde_json::from_slice(&r.bytes).unwrap();
        assert_eq!(v["data"]["candidates"][0]["label"], "e1");
    }

    #[test]
    fn release_requires_what_the_plugin_requires() {
        let body = |mfa: bool| {
            alloc::format!(
                r#"{{"op":"provider.release",{CALLER},"data":{{"account_id":"a1","protocol":"rdp","resource":{{"type":"server"}},"target":{{"host":"h","port":3389}},"needs":{{"password":true}},"connect":{{"mfa_verified":{mfa},"transport":"direct"}}}}}}"#
            )
        };
        assert_eq!(run(&body(false)).status, ProviderError::MFA_REQUIRED.status);
        let ok = run(&body(true));
        assert_eq!(ok.status, 0);
        let v: serde_json::Value = serde_json::from_slice(&ok.bytes).unwrap();
        assert_eq!(v["data"]["secret"]["kind"], "password");
    }

    #[test]
    fn refusals_carry_only_a_fixed_message() {
        let r = run(&alloc::format!(
            r#"{{"op":"provider.candidates",{CALLER},"data":{{"protocol":"web","resource":{{"type":"web_application"}},"target":{{"origins":["https://x"]}}}}}}"#
        ));
        assert_eq!(r.bytes, b"no matching account");
    }

    #[test]
    fn missing_caller_fails_closed() {
        assert_eq!(run(r#"{"op":"read","path":"v2/accounts","data":{}}"#).status, 4);
        assert_eq!(run(r#"{"op":"read","caller":{"entity_id":""},"data":{}}"#).status, 4);
    }

    #[test]
    fn unknown_provider_op_is_not_a_logical_op() {
        let r = run(&alloc::format!(r#"{{"op":"provider.exfiltrate",{CALLER},"data":{{}}}}"#));
        assert_eq!(r.status, 4);
    }

    #[test]
    fn logical_ops_reach_the_plugin() {
        let r = run(&alloc::format!(r#"{{"op":"list","path":"v2/accounts",{CALLER},"data":{{}}}}"#));
        assert_eq!(r.bytes, b"v2/accounts");
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert_eq!(run("not json").status, 4);
        let r = run(&alloc::format!(r#"{{"op":"provider.release",{CALLER},"data":{{}}}}"#));
        assert_eq!(r.status, 4);
    }
}
