//! Operator-supplied plugin configuration storage.
//!
//! Plugins declare a `config_schema: Vec<ConfigField>` in their manifest;
//! operators set values via `PUT /v1/sys/plugins/{name}/config` (or the
//! GUI Configure modal); the host persists the resulting key→value map
//! at `core/plugins/<name>/config`; the plugin reads values at run-time
//! via `bv.config_get`.
//!
//! Storage is plain JSON, barrier-encrypted at rest like every other
//! vault state. Config values are UTF-8 strings on the wire — numbers /
//! booleans / select-of-options fields are still strings; the plugin
//! parses (the SDK provides a few convenience helpers).
//!
//! Secret-kind fields are stored exactly like any other string: the
//! barrier handles encryption-at-rest; the GUI reads them back through
//! [`redact_for_read`] which replaces every `Secret`-kind value with
//! the placeholder `"<set>"` so a curious operator can see *which* keys
//! are populated without leaking the values themselves.

use std::collections::BTreeMap;

use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

use super::manifest::{ConfigFieldKind, PluginManifest};

const CONFIG_SUFFIX: &str = "/config";
const SECRET_PLACEHOLDER: &str = "<set>";

/// Stateless helper. Storage is passed per-call so we don't hold an
/// `Arc<dyn Storage>` across seal/unseal — same pattern as
/// `crate::scheduled_exports::ScheduleStore`.
#[derive(Default, Clone)]
pub struct ConfigStore;

impl ConfigStore {
    pub fn new() -> Self {
        Self
    }

    /// Read the raw config map verbatim. **Includes secret values.**
    /// Plugin runtime uses this; HTTP / GUI must use [`get_redacted`].
    pub async fn get(
        &self,
        storage: &dyn Storage,
        plugin_name: &str,
    ) -> Result<BTreeMap<String, String>, RvError> {
        let key = config_key(plugin_name);
        match storage.get(&key).await? {
            None => Ok(BTreeMap::new()),
            Some(entry) => serde_json::from_slice(&entry.value)
                .map_err(|_| RvError::ErrRequestInvalid),
        }
    }

    /// Read the config map with every `Secret`-kind value replaced by
    /// the `"<set>"` placeholder. The HTTP `GET /v1/sys/plugins/<name>
    /// /config` and the GUI use this so the operator can see which
    /// secrets are populated without seeing their values.
    pub async fn get_redacted(
        &self,
        storage: &dyn Storage,
        manifest: &PluginManifest,
    ) -> Result<BTreeMap<String, String>, RvError> {
        let mut map = self.get(storage, &manifest.name).await?;
        for field in &manifest.config_schema {
            if matches!(field.kind, ConfigFieldKind::Secret) {
                if let Some(v) = map.get_mut(&field.name) {
                    if !v.is_empty() {
                        *v = SECRET_PLACEHOLDER.to_string();
                    }
                }
            }
        }
        Ok(map)
    }

    /// Write the full config map, replacing whatever was there.
    /// Validates against the manifest's `config_schema`:
    ///
    /// - Refuses keys not declared in the schema.
    /// - Honours the `required` flag.
    /// - Honours `required_if`: a field whose condition holds against
    ///   the *effective* value of the referenced field (post-merge,
    ///   schema defaults applied) must carry a value. This is how a
    ///   multi-mode plugin — the email channel is either SMTP or
    ///   Office 365 — gets its incomplete configs rejected here rather
    ///   than at delivery time.
    /// - For `Select` kind, refuses values outside the declared options.
    /// - For `Bool` kind, accepts only `"true"` / `"false"`.
    /// - For `Int` kind, accepts only base-10 ASCII digits (with an
    ///   optional leading `-`).
    /// - For `Secret` kind, the literal placeholder `"<set>"` is
    ///   treated as "keep existing" — so the GUI can do a
    ///   GET-edit-PUT round-trip without forcing the operator to
    ///   re-type every secret on every save.
    pub async fn put(
        &self,
        storage: &dyn Storage,
        manifest: &PluginManifest,
        new_values: BTreeMap<String, String>,
    ) -> Result<(), RvError> {
        let existing = self.get(storage, &manifest.name).await?;

        // Refuse any key the operator supplied that isn't declared.
        for k in new_values.keys() {
            if !manifest.config_schema.iter().any(|f| &f.name == k) {
                return Err(RvError::ErrRequestInvalid);
            }
        }

        // Pass 1 — merge supplied / existing values per field, so a
        // partial PUT keeps whatever the operator didn't re-send.
        let mut merged: BTreeMap<String, String> = BTreeMap::new();
        for field in &manifest.config_schema {
            let value = match new_values.get(&field.name) {
                Some(v) if matches!(field.kind, ConfigFieldKind::Secret) && v == SECRET_PLACEHOLDER => {
                    // GUI round-trip: keep existing value.
                    existing.get(&field.name).cloned().unwrap_or_default()
                }
                Some(v) => v.clone(),
                None => existing.get(&field.name).cloned().unwrap_or_default(),
            };
            merged.insert(field.name.clone(), value);
        }

        // Pass 2 — validate and build the record. `required_if` reads
        // the *effective* value of its target (merged, else the schema
        // default), because an unset field with a default still behaves
        // as that default at run time.
        let effective = |name: &str| -> String {
            let v = merged.get(name).cloned().unwrap_or_default();
            if !v.is_empty() {
                return v;
            }
            manifest
                .config_schema
                .iter()
                .find(|f| f.name == name)
                .and_then(|f| f.default.clone())
                .unwrap_or_default()
        };

        let mut out: BTreeMap<String, String> = BTreeMap::new();
        for field in &manifest.config_schema {
            let value = merged.get(&field.name).cloned().unwrap_or_default();
            let label = field.label.as_deref().unwrap_or(&field.name);

            if value.is_empty() {
                if field.required {
                    return Err(RvError::ErrResponse(format!("{label} is required")));
                }
                if let Some(cond) = &field.required_if {
                    let target = effective(&cond.field);
                    if cond.matches(&target) {
                        let target_label = manifest
                            .config_schema
                            .iter()
                            .find(|f| f.name == cond.field)
                            .and_then(|f| f.label.as_deref())
                            .unwrap_or(&cond.field);
                        return Err(RvError::ErrResponse(format!(
                            "{label} is required when {target_label} is \"{target}\""
                        )));
                    }
                }
                // Don't store empty values; let the plugin fall back to
                // its declared default.
                continue;
            }

            match field.kind {
                ConfigFieldKind::Bool => {
                    if !(value == "true" || value == "false") {
                        return Err(RvError::ErrResponse(format!(
                            "{label} must be true or false"
                        )));
                    }
                }
                ConfigFieldKind::Int => {
                    if value.parse::<i64>().is_err() {
                        return Err(RvError::ErrResponse(format!("{label} must be a number")));
                    }
                }
                ConfigFieldKind::Select => {
                    if !field.options.iter().any(|o| o == &value) {
                        return Err(RvError::ErrResponse(format!(
                            "{label} must be one of: {}",
                            field.options.join(", ")
                        )));
                    }
                }
                ConfigFieldKind::String | ConfigFieldKind::Secret => {}
            }
            out.insert(field.name.clone(), value);
        }

        let key = config_key(&manifest.name);
        let value = serde_json::to_vec(&out)?;
        storage.put(&StorageEntry { key, value }).await
    }

    /// Drop the config record. Idempotent.
    pub async fn delete(&self, storage: &dyn Storage, plugin_name: &str) -> Result<(), RvError> {
        storage.delete(&config_key(plugin_name)).await
    }
}

fn config_key(plugin_name: &str) -> String {
    format!("{}{}{}", super::PLUGIN_PREFIX, plugin_name, CONFIG_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::manifest::{Capabilities, ConfigField, RuntimeKind};

    fn manifest() -> PluginManifest {
        PluginManifest {
            name: "test-config".to_string(),
            version: "0.1.0".to_string(),
            plugin_type: "test".to_string(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.0".to_string(),
            sha256: "0".repeat(64),
            size: 0,
            capabilities: Capabilities::default(),
            description: String::new(),
            config_schema: vec![
                ConfigField {
                    name: "endpoint".to_string(),
                    kind: ConfigFieldKind::String,
                    label: None,
                    description: None,
                    required: true,
                    default: None,
                    options: vec![],
                    required_if: None,
                },
                ConfigField {
                    name: "timeout_ms".to_string(),
                    kind: ConfigFieldKind::Int,
                    label: None,
                    description: None,
                    required: false,
                    default: Some("3000".to_string()),
                    options: vec![],
                    required_if: None,
                },
                ConfigField {
                    name: "secure".to_string(),
                    kind: ConfigFieldKind::Bool,
                    label: None,
                    description: None,
                    required: false,
                    default: None,
                    options: vec![],
                    required_if: None,
                },
                ConfigField {
                    name: "algo".to_string(),
                    kind: ConfigFieldKind::Select,
                    label: None,
                    description: None,
                    required: false,
                    default: None,
                    options: vec!["sha1".to_string(), "sha256".to_string()],
                    required_if: None,
                },
                ConfigField {
                    name: "api_key".to_string(),
                    kind: ConfigFieldKind::Secret,
                    label: None,
                    description: None,
                    required: false,
                    default: None,
                    options: vec![],
                    required_if: None,
                },
            ],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        }
    }

    /// In-memory storage mirror of the one used in
    /// `crate::exchange::scope::tests`. We don't import that one because
    /// it lives behind `#[cfg(test)]` in a different module.
    #[derive(Default)]
    struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for k in g.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    if let Some(slash) = rest.find('/') {
                        out.insert(format!("{}/", &rest[..slash]));
                    } else {
                        out.insert(rest.to_string());
                    }
                }
            }
            Ok(out.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "https://api".to_string());
        input.insert("timeout_ms".to_string(), "1500".to_string());
        input.insert("secure".to_string(), "true".to_string());
        input.insert("algo".to_string(), "sha256".to_string());
        input.insert("api_key".to_string(), "supersecret".to_string());
        store.put(&s, &m, input).await.unwrap();
        let got = store.get(&s, &m.name).await.unwrap();
        assert_eq!(got.get("endpoint").unwrap(), "https://api");
        assert_eq!(got.get("timeout_ms").unwrap(), "1500");
        assert_eq!(got.get("secure").unwrap(), "true");
        assert_eq!(got.get("algo").unwrap(), "sha256");
        assert_eq!(got.get("api_key").unwrap(), "supersecret");
    }

    #[tokio::test]
    async fn redacted_get_masks_secrets_only() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "https://api".to_string());
        input.insert("api_key".to_string(), "supersecret".to_string());
        store.put(&s, &m, input).await.unwrap();
        let got = store.get_redacted(&s, &m).await.unwrap();
        assert_eq!(got.get("endpoint").unwrap(), "https://api");
        assert_eq!(got.get("api_key").unwrap(), "<set>");
    }

    #[tokio::test]
    async fn round_trip_with_placeholder_keeps_secret() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        // First save with a real secret.
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "https://api".to_string());
        input.insert("api_key".to_string(), "first-value".to_string());
        store.put(&s, &m, input).await.unwrap();
        // GUI does GET (gets "<set>") → user edits endpoint → PUT with
        // the same placeholder. The store should keep the original.
        let mut input2 = BTreeMap::new();
        input2.insert("endpoint".to_string(), "https://api2".to_string());
        input2.insert("api_key".to_string(), "<set>".to_string());
        store.put(&s, &m, input2).await.unwrap();
        let got = store.get(&s, &m.name).await.unwrap();
        assert_eq!(got.get("api_key").unwrap(), "first-value");
        assert_eq!(got.get("endpoint").unwrap(), "https://api2");
    }

    #[tokio::test]
    async fn rejects_unknown_key() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "x".to_string());
        input.insert("not_in_schema".to_string(), "x".to_string());
        assert!(store.put(&s, &m, input).await.is_err());
    }

    #[tokio::test]
    async fn rejects_required_missing() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        // `endpoint` is required.
        let input = BTreeMap::new();
        assert!(store.put(&s, &m, input).await.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_int() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "x".to_string());
        input.insert("timeout_ms".to_string(), "not-a-number".to_string());
        assert!(store.put(&s, &m, input).await.is_err());
    }

    /// Mode-scoped manifest in the shape the email channel uses: a
    /// `mode` select defaulting to `"smtp"`, one field required only in
    /// that mode, one required only in the other. `mode` itself is left
    /// optional here so the condition can be exercised against the
    /// schema default as well as an explicit value.
    fn mode_manifest() -> PluginManifest {
        let mut m = manifest();
        m.config_schema = vec![
            ConfigField {
                name: "mode".to_string(),
                kind: ConfigFieldKind::Select,
                label: Some("Mode".to_string()),
                description: None,
                required: false,
                default: Some("smtp".to_string()),
                options: vec!["smtp".to_string(), "office365".to_string()],
                required_if: None,
            },
            ConfigField {
                name: "from_address".to_string(),
                kind: ConfigFieldKind::String,
                label: Some("From address".to_string()),
                description: None,
                required: false,
                default: None,
                options: vec![],
                required_if: Some(super::super::manifest::ConfigCondition {
                    field: "mode".to_string(),
                    equals: vec!["smtp".to_string()],
                }),
            },
            ConfigField {
                name: "o365_sender".to_string(),
                kind: ConfigFieldKind::String,
                label: Some("O365 sender address".to_string()),
                description: None,
                required: false,
                default: None,
                options: vec![],
                required_if: Some(super::super::manifest::ConfigCondition {
                    field: "mode".to_string(),
                    equals: vec!["office365".to_string()],
                }),
            },
        ];
        m
    }

    /// The condition holds via the schema default: `mode` is unset, so
    /// it is effectively `"smtp"` and `from_address` is mandatory.
    #[tokio::test]
    async fn required_if_matches_via_default() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = mode_manifest();
        let err = store.put(&s, &m, BTreeMap::new()).await.unwrap_err();
        assert!(
            err.to_string().contains("From address is required when Mode is \"smtp\""),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn required_if_scopes_to_the_selected_mode() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = mode_manifest();

        // office365 mode: from_address is irrelevant, o365_sender isn't.
        let mut input = BTreeMap::new();
        input.insert("mode".to_string(), "office365".to_string());
        assert!(store.put(&s, &m, input.clone()).await.is_err());

        input.insert("o365_sender".to_string(), "bv@example.com".to_string());
        store.put(&s, &m, input).await.unwrap();

        // Switching back to smtp now needs from_address, even though
        // the stored o365_sender is still there.
        let mut back = BTreeMap::new();
        back.insert("mode".to_string(), "smtp".to_string());
        assert!(store.put(&s, &m, back).await.is_err());
    }

    #[tokio::test]
    async fn required_if_satisfied_saves() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = mode_manifest();
        let mut input = BTreeMap::new();
        input.insert("mode".to_string(), "smtp".to_string());
        input.insert("from_address".to_string(), "bv@example.com".to_string());
        store.put(&s, &m, input).await.unwrap();
        let got = store.get(&s, &m.name).await.unwrap();
        assert_eq!(got.get("from_address").unwrap(), "bv@example.com");
        assert!(!got.contains_key("o365_sender"));
    }

    #[tokio::test]
    async fn rejects_select_value_outside_options() {
        let s = MemStorage::default();
        let store = ConfigStore::new();
        let m = manifest();
        let mut input = BTreeMap::new();
        input.insert("endpoint".to_string(), "x".to_string());
        input.insert("algo".to_string(), "sha999".to_string());
        assert!(store.put(&s, &m, input).await.is_err());
    }
}
