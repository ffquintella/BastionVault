//! SAML roles — per-mount attribute-to-policy mappings.
//!
//! Stored at `role/<name>`. A role:
//!   * Pins arbitrary SAML attribute values the assertion must carry
//!     (`bound_attributes`) — e.g. require `department ∈ {eng, sre}`.
//!   * Optionally restricts the allowed `NameID` values (`bound_subjects`)
//!     and format (`bound_subjects_type`).
//!   * Maps SAML attributes onto Vault token metadata
//!     (`attribute_mappings`) so downstream identity-group bindings
//!     can match on them.
//!   * Names the attribute carrying group membership (`groups_attribute`).
//!   * Lists the vault policies to attach on successful login.
//!   * Carries per-role token TTL settings.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{SamlBackend, SamlBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{
        is_reserved_token_meta_key, Backend, Field, FieldType, Operation, Path, PathOperation, Request,
        Response, USERNAME_META,
    },
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

pub(crate) const ROLE_PREFIX: &str = "role/";

/// Stored role entry. Field names match the design doc so operators
/// hand-editing configs or writing Terraform have a stable contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SamlRoleEntry {
    /// Per-attribute allow-list map: attribute name → allowed values.
    /// A login must match at least one value for every listed
    /// attribute. Missing attribute ⇒ no match ⇒ login denied.
    #[serde(default)]
    pub bound_attributes: HashMap<String, Vec<String>>,
    /// Allowed NameID values. Empty accepts any subject.
    #[serde(default)]
    pub bound_subjects: Vec<String>,
    /// Required NameID format (e.g. `emailAddress`, `persistent`,
    /// `transient`). Empty accepts any format.
    #[serde(default)]
    pub bound_subjects_type: String,
    /// SAML attribute → Vault token metadata key. Lets operators
    /// project named attributes (email, displayName, employeeID, ...)
    /// into `auth.metadata` without exposing every attribute the
    /// IdP ships.
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
    /// SAML attribute whose value is a list of group names.
    /// Surfaced on `auth.metadata` so identity-group bindings that
    /// key on it pick up federated groups.
    #[serde(default)]
    pub groups_attribute: String,
    /// Narrower redirect-URI whitelist overriding the provider-level
    /// list. Empty falls through to provider config.
    #[serde(default)]
    pub allowed_redirect_uris: Vec<String>,
    /// Vault policies attached on successful login.
    #[serde(default)]
    pub policies: Vec<String>,
    /// Token TTL in seconds. 0 = default (token store's own TTL).
    #[serde(default)]
    pub token_ttl_secs: u64,
    /// Token max-TTL in seconds. 0 = unlimited renewal.
    #[serde(default)]
    pub token_max_ttl_secs: u64,
}

impl SamlRoleEntry {
    pub async fn load(req: &Request, name: &str) -> Result<Option<Self>, RvError> {
        let key = format!("{ROLE_PREFIX}{name}");
        match req.storage_get(&key).await? {
            Some(entry) => Ok(Some(serde_json::from_slice(&entry.value)?)),
            None => Ok(None),
        }
    }

    /// Apply `bound_subjects`, `bound_subjects_type`, and
    /// `bound_attributes` against values extracted from the SAML
    /// assertion. Returns `Ok(())` on success, a descriptive
    /// `RvError::ErrString` on rejection. Used by Phase 3's callback
    /// handler.
    pub fn validate_assertion(
        &self,
        name_id: &str,
        name_id_format: &str,
        attributes: &Map<String, Value>,
    ) -> Result<(), RvError> {
        if !self.bound_subjects.is_empty()
            && !self.bound_subjects.iter().any(|s| s == name_id)
        {
            return Err(RvError::ErrString(format!(
                "saml: NameID `{name_id}` not in role `bound_subjects`"
            )));
        }
        if !self.bound_subjects_type.is_empty()
            && !name_id_format.ends_with(&self.bound_subjects_type)
        {
            return Err(RvError::ErrString(format!(
                "saml: NameID format `{name_id_format}` does not match \
                 role `bound_subjects_type` `{}`",
                self.bound_subjects_type
            )));
        }
        for (attr, allowed) in &self.bound_attributes {
            let Some(value) = attributes.get(attr) else {
                return Err(RvError::ErrString(format!(
                    "saml: required bound_attribute `{attr}` missing from assertion"
                )));
            };
            if !attribute_matches_any(value, allowed) {
                return Err(RvError::ErrString(format!(
                    "saml: bound_attribute `{attr}` did not match allowed values"
                )));
            }
        }
        Ok(())
    }

    fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert(
            "bound_attributes".into(),
            Value::Object(
                self.bound_attributes
                    .iter()
                    .map(|(k, vs)| {
                        (
                            k.clone(),
                            Value::Array(vs.iter().cloned().map(Value::String).collect()),
                        )
                    })
                    .collect(),
            ),
        );
        m.insert(
            "bound_subjects".into(),
            Value::Array(
                self.bound_subjects
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m.insert(
            "bound_subjects_type".into(),
            Value::String(self.bound_subjects_type.clone()),
        );
        m.insert(
            "attribute_mappings".into(),
            Value::Object(
                self.attribute_mappings
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect(),
            ),
        );
        m.insert(
            "groups_attribute".into(),
            Value::String(self.groups_attribute.clone()),
        );
        m.insert(
            "allowed_redirect_uris".into(),
            Value::Array(
                self.allowed_redirect_uris
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        m.insert(
            "policies".into(),
            Value::Array(self.policies.iter().cloned().map(Value::String).collect()),
        );
        m.insert(
            "token_ttl_secs".into(),
            Value::Number(self.token_ttl_secs.into()),
        );
        m.insert(
            "token_max_ttl_secs".into(),
            Value::Number(self.token_max_ttl_secs.into()),
        );
        m
    }
}

fn attribute_matches_any(value: &Value, allowed: &[String]) -> bool {
    match value {
        Value::String(s) => allowed.iter().any(|a| a == s),
        Value::Number(n) => allowed.iter().any(|a| a == &n.to_string()),
        Value::Bool(b) => {
            let s = b.to_string();
            allowed.iter().any(|a| a == &s)
        }
        Value::Array(arr) => arr.iter().any(|v| attribute_matches_any(v, allowed)),
        _ => false,
    }
}

impl SamlBackend {
    pub fn roles_path(&self) -> Path {
        let this = self.inner.clone();
        let r = this.clone();
        let w = this.clone();
        let d = this;
        new_path!({
            pattern: r"role/(?P<name>[\w-]+)",
            fields: {
                "name": {
                    field_type: FieldType::Str,
                    required: true,
                    description: "Role name."
                },
                "bound_attributes":     { field_type: FieldType::Str },
                "bound_subjects":       { field_type: FieldType::CommaStringSlice },
                "bound_subjects_type":  { field_type: FieldType::Str },
                "attribute_mappings":   { field_type: FieldType::Str },
                "groups_attribute":     { field_type: FieldType::Str },
                "allowed_redirect_uris":{ field_type: FieldType::CommaStringSlice },
                "policies":             { field_type: FieldType::CommaStringSlice },
                "token_ttl_secs":       { field_type: FieldType::Int },
                "token_max_ttl_secs":   { field_type: FieldType::Int }
            },
            operations: [
                {op: Operation::Read,   handler: r.read_role},
                {op: Operation::Write,  handler: w.write_role},
                {op: Operation::Delete, handler: d.delete_role}
            ],
            help: "Read, write, or delete the SAML role named by `name`."
        })
    }

    pub fn role_list_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"role/?",
            operations: [
                {op: Operation::List, handler: this.list_roles}
            ],
            help: "List the names of all configured SAML roles."
        })
    }
}

#[maybe_async::maybe_async]
impl SamlBackendInner {
    pub async fn read_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        let Some(role) = SamlRoleEntry::load(req, &name).await? else {
            return Ok(None);
        };
        Ok(Some(Response::data_response(Some(role.to_map()))))
    }

    pub async fn write_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        if name.trim().is_empty() {
            return Err(RvError::ErrString("saml: role name is required".into()));
        }
        let mut role = SamlRoleEntry::load(req, &name).await?.unwrap_or_default();

        if let Ok(v) = req.get_data("bound_attributes") {
            // Accept either a JSON object (preferred) or the
            // comma-separated field-layer default. Silently dropping
            // bound_attributes would be a security regression, so an
            // unparseable payload is an explicit error.
            if let Value::String(raw) = &v {
                if !raw.trim().is_empty() {
                    role.bound_attributes = parse_claim_map(raw)?;
                }
            } else if let Value::Object(obj) = &v {
                role.bound_attributes = obj
                    .iter()
                    .map(|(k, vs)| (k.clone(), vals_to_strings(vs)))
                    .collect();
            }
        }
        if let Ok(v) = req.get_data("bound_subjects") {
            role.bound_subjects = parse_string_list(&v);
        }
        if let Ok(Value::String(v)) = req.get_data("bound_subjects_type") {
            role.bound_subjects_type = v;
        }
        if let Ok(v) = req.get_data("attribute_mappings") {
            if let Value::String(raw) = &v {
                if !raw.trim().is_empty() {
                    role.attribute_mappings = parse_str_map(raw)?;
                }
            } else if let Value::Object(obj) = &v {
                role.attribute_mappings = obj
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
            }
        }
        if let Ok(Value::String(v)) = req.get_data("groups_attribute") {
            role.groups_attribute = v;
        }
        if let Ok(v) = req.get_data("allowed_redirect_uris") {
            role.allowed_redirect_uris = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("policies") {
            role.policies = parse_string_list(&v);
        }
        if let Ok(v) = req.get_data("token_ttl_secs") {
            role.token_ttl_secs = v.as_u64().unwrap_or(0);
        }
        if let Ok(v) = req.get_data("token_max_ttl_secs") {
            role.token_max_ttl_secs = v.as_u64().unwrap_or(0);
        }

        // Reject a mapping onto a backend-owned metadata key before it is
        // persisted, rather than dropping it at login: the operator gets an
        // error naming the key, matching what `auth/token/create` does with a
        // reserved `meta` key. `path_callback` drops any that a role persisted
        // before this check still carries.
        reject_reserved_mapping_targets(&role.attribute_mappings)?;

        let bytes = serde_json::to_vec(&role)?;
        req.storage_put(&StorageEntry {
            key: format!("{ROLE_PREFIX}{name}"),
            value: bytes,
        })
        .await?;
        Ok(None)
    }

    pub async fn delete_role(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name").unwrap_or_default();
        req.storage_delete(&format!("{ROLE_PREFIX}{name}")).await?;
        Ok(None)
    }

    pub async fn list_roles(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let names = req.storage_list(ROLE_PREFIX).await?;
        Ok(Some(Response::list_response(&names)))
    }
}

/// The one reserved metadata key a role's `attribute_mappings` may still
/// target.
///
/// SAML has no `user_claim` equivalent: the attribute map is the *only* way an
/// operator can make the principal something other than the NameID, and
/// `login_callback` derives `principal` from a mapped `username` (falling back
/// to the NameID) *before* it resolves the login namespace and enforces the
/// namespace assignment — so the mapped name is the name the login is checked
/// against, and the name the token later widens as. There is no desync to
/// exploit, and both the NameID and a mapped attribute come out of the same
/// signed assertion, so allowing this hands the IdP no value it did not
/// already control.
///
/// OIDC deliberately allows no exception: there the assignment check runs on
/// `display_name`, derived from `user_claim`, so a claim mapped onto
/// `username` would be checked as one principal and widened as another.
const MAPPABLE_RESERVED_META_KEYS: &[&str] = &[USERNAME_META];

/// May a role's `attribute_mappings` project an attribute onto `vault_key`?
///
/// The target set is `bv_logical::auth::RESERVED_TOKEN_META_KEYS` minus
/// [`MAPPABLE_RESERVED_META_KEYS`] — the same list `auth/token/create` refuses
/// in a caller-supplied `meta` map, and for the same reason: those keys are
/// stamped by the auth backend and read back by authorization and audit code as
/// trusted input. An `attribute_mappings` entry is the *second* write point for
/// that set and the value it writes comes from the IdP's assertion, so an
/// operator who wrote `attribute_mappings = {"dept": "spiffe_id"}` would hand
/// the IdP the ability to mint tokens that satisfy the server-wide
/// `require_machine_identity` gate with no machine attestation at all.
pub(crate) fn reserved_mapping_target(vault_key: &str) -> bool {
    !MAPPABLE_RESERVED_META_KEYS.contains(&vault_key) && is_reserved_token_meta_key(vault_key)
}

/// Refuse a role whose `attribute_mappings` target a reserved metadata key.
///
/// Validated against the role as it will be *persisted*, not against the fields
/// this request happened to carry, so the invariant is the strong one: no stored
/// role passes this check and still carries a reserved target. An operator
/// updating an unrelated field on a legacy role that does carry one gets the
/// error too, which is the point — the mapping has to be fixed rather than
/// silently kept.
///
/// Names every offending pair, sorted, so one round trip shows the whole
/// problem and the same body always produces the same message.
fn reject_reserved_mapping_targets(mappings: &HashMap<String, String>) -> Result<(), RvError> {
    let mut offenders: Vec<(&str, &str)> = mappings
        .iter()
        .filter(|(_, vault_key)| reserved_mapping_target(vault_key))
        .map(|(attr, vault_key)| (attr.as_str(), vault_key.as_str()))
        .collect();
    if offenders.is_empty() {
        return Ok(());
    }
    offenders.sort_unstable();

    let listed = offenders
        .iter()
        .map(|(attr, vault_key)| format!("`{attr}` -> `{vault_key}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(RvError::ErrString(format!(
        "saml: attribute_mappings may not target reserved token metadata key(s): {listed}. Those \
         keys are set by the auth backend that authenticated the principal and are read back as \
         authorization input, so mapping an IdP-supplied attribute onto one lets the IdP forge it. \
         Map onto `username` to name the principal, use `groups_attribute` for group membership, \
         and an unreserved key for anything else"
    )))
}

fn parse_string_list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_claim_map(raw: &str) -> Result<HashMap<String, Vec<String>>, RvError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| RvError::ErrString(format!("bound_attributes: invalid JSON: {e}")))?;
    match parsed {
        Value::Object(obj) => Ok(obj
            .into_iter()
            .map(|(k, v)| (k, vals_to_strings(&v)))
            .collect()),
        _ => Err(RvError::ErrString(
            "bound_attributes: expected JSON object of attr → allowed-values".into(),
        )),
    }
}

fn parse_str_map(raw: &str) -> Result<HashMap<String, String>, RvError> {
    let parsed: Value = serde_json::from_str(raw)
        .map_err(|e| RvError::ErrString(format!("attribute_mappings: invalid JSON: {e}")))?;
    match parsed {
        Value::Object(obj) => Ok(obj
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect()),
        _ => Err(RvError::ErrString(
            "attribute_mappings: expected JSON object of attribute-name → metadata-key".into(),
        )),
    }
}

fn vals_to_strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_assertion_bound_subject_happy() {
        let role = SamlRoleEntry {
            bound_subjects: vec!["alice@example.com".into()],
            ..Default::default()
        };
        role.validate_assertion("alice@example.com", "emailAddress", &Map::new())
            .unwrap();
    }

    #[test]
    fn validate_assertion_bound_subject_rejects_other() {
        let role = SamlRoleEntry {
            bound_subjects: vec!["alice@example.com".into()],
            ..Default::default()
        };
        let err = role
            .validate_assertion("mallory@example.com", "emailAddress", &Map::new())
            .unwrap_err();
        assert!(format!("{err}").contains("not in role"));
    }

    #[test]
    fn validate_assertion_bound_subject_type_rejects_format() {
        let role = SamlRoleEntry {
            bound_subjects_type: "emailAddress".into(),
            ..Default::default()
        };
        let err = role
            .validate_assertion("xyz", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", &Map::new())
            .unwrap_err();
        assert!(format!("{err}").contains("does not match"));
    }

    #[test]
    fn validate_assertion_bound_attribute_missing_rejects() {
        let role = SamlRoleEntry {
            bound_attributes: [("department".to_string(), vec!["eng".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let err = role
            .validate_assertion("anyone", "", &Map::new())
            .unwrap_err();
        assert!(format!("{err}").contains("missing from assertion"));
    }

    #[test]
    fn validate_assertion_bound_attribute_mismatch_rejects() {
        let role = SamlRoleEntry {
            bound_attributes: [("department".to_string(), vec!["eng".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut attrs = Map::new();
        attrs.insert("department".into(), Value::String("sales".into()));
        let err = role.validate_assertion("anyone", "", &attrs).unwrap_err();
        assert!(format!("{err}").contains("did not match allowed"));
    }

    #[test]
    fn validate_assertion_bound_attribute_array_matches_any() {
        let role = SamlRoleEntry {
            bound_attributes: [("groups".to_string(), vec!["admins".to_string()])]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let mut attrs = Map::new();
        attrs.insert(
            "groups".into(),
            Value::Array(vec![
                Value::String("engineering".into()),
                Value::String("admins".into()),
            ]),
        );
        role.validate_assertion("anyone", "", &attrs).unwrap();
    }

    #[test]
    fn parse_claim_map_roundtrips() {
        let m = parse_claim_map(r#"{"dept":["a","b"],"role":["admin"]}"#).unwrap();
        assert_eq!(m.get("dept").unwrap().len(), 2);
        assert_eq!(m.get("role").unwrap(), &vec!["admin".to_string()]);
    }

    #[test]
    fn parse_claim_map_rejects_non_object() {
        let err = parse_claim_map(r#"["not","an","object"]"#).unwrap_err();
        assert!(format!("{err}").contains("expected JSON object"));
    }

    #[test]
    fn parse_str_map_extracts_strings_only() {
        let m = parse_str_map(r#"{"email":"mail","displayName":"name","nope":123}"#).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("email").unwrap(), "mail");
    }

    #[test]
    fn attribute_matches_any_number_and_bool() {
        assert!(attribute_matches_any(
            &Value::Number(42.into()),
            &["42".to_string()]
        ));
        assert!(attribute_matches_any(
            &Value::Bool(true),
            &["true".to_string()]
        ));
    }
}

#[cfg(test)]
mod reserved_mapping_tests {
    use super::*;

    fn mappings(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn unreserved_targets_are_accepted() {
        reject_reserved_mapping_targets(&mappings(&[
            ("email", "email"),
            ("displayName", "name"),
            ("http://schemas.example/dept", "dept"),
        ]))
        .unwrap();
    }

    #[test]
    fn spiffe_id_target_is_refused() {
        // The escalation this closes: `spiffe_id` is the whole of what the
        // server-wide `require_machine_identity` gate reads as proof of
        // machine attestation.
        let err = reject_reserved_mapping_targets(&mappings(&[("dept", "spiffe_id")])).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("reserved token metadata key"), "{msg}");
        assert!(msg.contains("`dept` -> `spiffe_id`"), "{msg}");
    }

    #[test]
    fn username_target_stays_mappable() {
        // SAML has no `user_claim` equivalent — the attribute map is the only
        // way to name the principal with something other than the NameID, and
        // `login_callback` enforces the namespace assignment against that same
        // value. See MAPPABLE_RESERVED_META_KEYS.
        assert!(!reserved_mapping_target(USERNAME_META));
        reject_reserved_mapping_targets(&mappings(&[("uid", "username")])).unwrap();
    }

    #[test]
    fn entity_id_target_is_refused_even_though_username_is_not() {
        // The exception is one key wide, not "principal identity" wide.
        let err = reject_reserved_mapping_targets(&mappings(&[("uid", "entity_id")])).unwrap_err();
        assert!(format!("{err}").contains("`uid` -> `entity_id`"));
    }

    #[test]
    fn every_offender_is_named_and_the_order_is_stable() {
        let bad = mappings(&[
            ("dept", "spiffe_id"),
            ("issuer", "mount_path"),
            ("email", "email"),
            ("env", "approle_env_scoped"),
        ]);
        let first = format!("{}", reject_reserved_mapping_targets(&bad).unwrap_err());
        let second = format!("{}", reject_reserved_mapping_targets(&bad).unwrap_err());
        assert_eq!(first, second, "message must not depend on HashMap order");
        assert!(first.contains("`dept` -> `spiffe_id`"), "{first}");
        assert!(first.contains("`issuer` -> `mount_path`"), "{first}");
        assert!(first.contains("`env` -> `approle_env_scoped`"), "{first}");
        assert!(!first.contains("`email`"), "{first}");
    }

    #[test]
    fn backend_written_provenance_keys_are_refused() {
        // These four the callback writes itself, after the mapping loop; the
        // ordering was the only thing protecting them.
        for key in ["name_id", "name_id_format", "role", "mount_path"] {
            let err = reject_reserved_mapping_targets(&mappings(&[("x", key)])).unwrap_err();
            assert!(format!("{err}").contains(key));
        }
    }

    #[test]
    fn login_time_predicate_matches_the_write_time_check() {
        // `path_callback` drops what `write_role` would have refused; the two
        // must not be able to disagree — including about the one exception.
        for key in ["spiffe_id", "entity_id", "mount_path", "approle_env_scoped", "namespace_path"] {
            assert!(reserved_mapping_target(key), "{key}");
            assert!(reject_reserved_mapping_targets(&mappings(&[("x", key)])).is_err(), "{key}");
        }
        for key in ["username", "email", "dept"] {
            assert!(!reserved_mapping_target(key), "{key}");
            assert!(reject_reserved_mapping_targets(&mappings(&[("x", key)])).is_ok(), "{key}");
        }
    }
}
