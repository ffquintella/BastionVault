use std::{any::Any, str::FromStr, sync::Arc};

use arc_swap::ArcSwap;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use better_default::Default;
use serde_json::{Map, Value};

use super::{resource_group::ResourceGroupModule, Module};
use crate::kernel_api::VaultCtx;
use crate::{
    core::Core,
    errors::RvError,
    handler::{AuthHandler, Handler},
    logical::{Backend, Request, Response},
    bv_error_response_status,
};

#[allow(clippy::module_inception)]
pub mod policy;
pub use policy::{Permissions, Policy, PolicyPathRules, PolicyType};

pub mod policy_store;
pub mod kernel_service;
pub use policy_store::{PolicyHistoryEntry, PolicyStore};

pub mod acl;

#[derive(Default)]
pub struct PolicyModule {
    #[default("policy".into())]
    pub name: String,
    pub core: Arc<Core>,
    pub policy_store: ArcSwap<PolicyStore>,
}

#[maybe_async::maybe_async]
impl PolicyModule {
    pub fn new(core: Arc<Core>) -> Self {
        Self { name: "policy".into(), core, policy_store: ArcSwap::new(Arc::new(PolicyStore::default())) }
    }

    pub async fn setup_policy(&self) -> Result<(), RvError> {
        self.policy_store.load().load_default_acl_policy().await
    }

    pub async fn handle_policy_list(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        let mut policies = self.policy_store.load().list_policy_ns(PolicyType::Acl, &ns).await?;

        // The synthetic `root` policy is a deployment-wide superuser document;
        // it is only meaningful (and only listed) in the root namespace.
        if ns.is_empty() {
            policies.push("root".into());
        }

        let mut resp = Response::list_response(&policies);

        if req.path.starts_with("policy") {
            let data = resp.data.as_mut().unwrap();
            data.insert("policies".into(), data["keys"].clone());
        }
        Ok(Some(resp))
    }

    pub async fn handle_policy_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        if let Some(policy) =
            self.policy_store.load().get_policy_ns(&name, PolicyType::Acl, &ns).await?
        {
            let mut resp_data = Map::new();
            resp_data.insert("name".into(), Value::String(name));

            // If the request is from sys/policy/ we handle backwards compatibility
            if req.path.starts_with("policy") {
                resp_data.insert("rules".into(), Value::String(policy.raw.clone()));
            } else {
                resp_data.insert("policy".into(), Value::String(policy.raw.clone()));
            }

            let resp = Response::data_response(Some(resp_data));
            if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
                policy.add_sentinel_policy_data(&resp)?;
            }

            return Ok(Some(resp));
        }
        Err(bv_error_response_status!(404, &format!("No policy named: {name}")))
    }

    pub async fn handle_policy_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let policy_str = req.get_data("policy")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let policy_raw = if let Ok(policy_bytes) = STANDARD.decode(&policy_str) {
            String::from_utf8_lossy(&policy_bytes).to_string()
        } else {
            policy_str
        };

        let mut policy = Policy::from_str(&policy_raw)?;
        policy.name = name.clone();

        // Multi-tenancy: a policy authored inside a namespace may only
        // reference paths that belong to that namespace. Refused at write time
        // for non-root writers; a no-op for root-scoped writes. The same
        // namespace scopes where the policy document is *stored* below.
        let writer_ns =
            crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        {
            let paths: Vec<String> = policy.paths.iter().map(|r| r.path.clone()).collect();
            crate::modules::namespace::policy_scope::refuse_cross_namespace_paths(
                &self.core,
                &writer_ns,
                &paths,
            )
            .await?;
        }

        // Sentinel (RGP/EGP) policies are deployment-global; they cannot be
        // authored inside a tenant namespace.
        if !writer_ns.is_empty()
            && (policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp)
        {
            return Err(bv_error_response_status!(
                400,
                "sentinel (RGP/EGP) policies cannot be created inside a namespace"
            ));
        }

        if policy.policy_type == PolicyType::Egp || policy.policy_type == PolicyType::Rgp {
            policy.input_sentinel_policy_data(req)?;
        }

        // Snapshot the previous raw HCL before the write so we can record
        // both sides of the change in the audit log. Only ACL policies
        // are history-tracked here; sentinel (RGP/EGP) edits flow through
        // this handler too but do not yet emit history entries.
        let store = self.policy_store.load();
        let previous_raw = if policy.policy_type == PolicyType::Acl {
            store
                .get_policy_ns(&name, PolicyType::Acl, &writer_ns)
                .await?
                .map(|p| p.raw.clone())
        } else {
            None
        };
        let op = if previous_raw.is_some() { "update" } else { "create" };
        let new_raw = policy.raw.clone();

        // Compile-time warning: any `groups = [...]` entries that
        // reference a non-existent asset group contribute zero
        // authorization at runtime. The policy is still accepted —
        // later creating the named group retroactively activates the
        // clause — but we surface the unknown names so operators can
        // spot typos immediately. Silent on any resolution failure
        // (module absent, store uninitialized).
        let mut warnings: Vec<String> = Vec::new();
        if policy.policy_type == PolicyType::Acl {
            let referenced = collect_referenced_groups(&policy);
            if !referenced.is_empty() {
                if let Some(known) = self.known_asset_groups().await {
                    let unknown: Vec<String> = referenced
                        .into_iter()
                        .filter(|g| !known.iter().any(|k| k == g))
                        .collect();
                    if !unknown.is_empty() {
                        warnings.push(format!(
                            "policy references unknown asset group(s): {}. \
                             The policy is accepted; these clauses grant no \
                             access until a group with a matching name is created.",
                            unknown.join(", "),
                        ));
                    }
                }
            }
        }

        store.set_policy_ns(policy, &writer_ns).await?;

        if matches!(op, "create" | "update")
            && previous_raw.as_deref() != Some(new_raw.as_str())
        {
            let entry = PolicyHistoryEntry {
                ts: now_iso(),
                user: caller_username(req),
                op: op.to_string(),
                before_raw: previous_raw.unwrap_or_default(),
                after_raw: new_raw,
            };
            // History failures must not fail the write.
            let _ = store.append_history_ns(&name, entry, &writer_ns).await;
        }

        if warnings.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Response { warnings, ..Response::default() }))
        }
    }

    /// Snapshot the current asset-group names. Returns `None` when the
    /// subsystem isn't loaded — caller treats that as "can't validate,
    /// don't warn".
    async fn known_asset_groups(&self) -> Option<Vec<String>> {
        let module = self
            .core
            .module_manager()
            .get_module::<ResourceGroupModule>("resource-group")?;
        let store = module.store()?;
        store.list_groups().await.ok()
    }

    pub async fn handle_policy_delete(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());

        // Capture the current raw HCL *before* deletion so the audit
        // entry retains the full final state of the policy.
        let store = self.policy_store.load();
        let previous_raw = store
            .get_policy_ns(&name, PolicyType::Acl, &ns)
            .await?
            .map(|p| p.raw.clone())
            .unwrap_or_default();

        store.delete_policy_ns(&name, PolicyType::Acl, &ns).await?;

        let entry = PolicyHistoryEntry {
            ts: now_iso(),
            user: caller_username(req),
            op: "delete".to_string(),
            before_raw: previous_raw,
            after_raw: String::new(),
        };
        let _ = store.append_history_ns(&name, entry, &ns).await;

        Ok(None)
    }

    pub async fn handle_policy_history(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        let entries = self.policy_store.load().list_history_ns(&name, &ns).await?;

        let arr = Value::Array(
            entries
                .iter()
                .map(|e| {
                    let mut m = Map::new();
                    m.insert("ts".into(), Value::String(e.ts.clone()));
                    m.insert("user".into(), Value::String(e.user.clone()));
                    m.insert("op".into(), Value::String(e.op.clone()));
                    m.insert("before_raw".into(), Value::String(e.before_raw.clone()));
                    m.insert("after_raw".into(), Value::String(e.after_raw.clone()));
                    Value::Object(m)
                })
                .collect(),
        );
        let mut data = Map::new();
        data.insert("entries".into(), arr);
        Ok(Some(Response::data_response(Some(data))))
    }

    /// Stateless dry-run for the graphical policy builder/validator.
    ///
    /// Parses a *draft* HCL policy (never persisted), constructs an
    /// in-memory `ACL` from it plus the policies a real token would carry
    /// alongside it, and evaluates each supplied `(path, capability)` case
    /// with the production matcher. Returns, per case, the authoritative
    /// allow/deny verdict plus an advisory identification of the rule that
    /// decided it and of the policies that wrote that rule.
    ///
    /// ## Why more than one policy
    ///
    /// ACL precedence selects a *single* winning rule and unions
    /// capabilities only between rules whose path string is identical, so a
    /// narrow rule in an attached policy replaces — rather than adds to —
    /// a broad rule in the draft. `default` is attached to every token
    /// unless the auth mount sets `token_no_default_policy`, so a draft
    /// validated in isolation can look correct and still be narrowed in
    /// production; that is exactly how `default`'s `rustion/targets/+`
    /// silently downgraded every administrator. A case therefore carries an
    /// optional `policies` array:
    ///
    ///   * absent / `null` — `["default"]`, the set a real token carries.
    ///   * `[]` — the draft alone (the original single-policy dry-run).
    ///   * `["a", "b"]` — the draft plus exactly those.
    ///
    /// Each row also reports `draft_only_allowed`: the verdict the draft
    /// would give on its own. When it disagrees with `allowed`, the
    /// difference *is* the cross-policy narrowing, and `granting_policies`
    /// names who caused it.
    ///
    /// A parse failure is reported as a normal result
    /// (`parse_ok = false` + the message) rather than an error, so the
    /// GUI can surface syntax problems inline. The endpoint requires the
    /// same ACL capability as a policy write because it shares the
    /// `sys/policies/acl/*` path prefix; the attached policies are read
    /// through the same store the caller could already read them from, so
    /// it discloses nothing new. See
    /// `features/policy-builder-validator.md` (Phase 1).
    pub async fn handle_policy_test(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use crate::modules::policy::acl::ACL;
        use crate::modules::policy::policy::Capability;

        // Accept either raw or base64-encoded HCL, mirroring policy write.
        let policy_str = req.get_data("policy")?.as_str().ok_or(RvError::ErrRequestFieldInvalid)?.to_string();
        let policy_raw = if let Ok(bytes) = STANDARD.decode(&policy_str) {
            String::from_utf8_lossy(&bytes).to_string()
        } else {
            policy_str
        };

        // The name the draft would be saved under. Supplied by the client
        // because a policy's name comes from the URL, not the HCL — and it
        // matters twice: it is what `granting_policies` reports for the
        // draft's own rules, and it is how an attached policy that *is* the
        // draft is recognized and skipped (an operator editing `default`
        // must not have the stored `default` merged back in underneath).
        let supplied_name = req
            .get_data("name")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty());

        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());

        // Cases parse independently of the policy so the GUI can still
        // render rows when the draft fails to parse.
        let cases: Vec<DryRunCase> = match req.get_data("cases") {
            Ok(Value::Array(arr)) => arr.iter().filter_map(parse_dry_run_case).collect(),
            _ => Vec::new(),
        };

        // `root` is a synthetic superuser policy, not a document: an ACL
        // containing it allows everything, and `ACL::new` rejects it
        // alongside any sibling. Refuse explicitly rather than filtering it
        // out, so a case naming it never reports a silently different set.
        if cases.iter().any(|c| c.attached.iter().any(|n| n == "root")) {
            return Err(bv_error_response_status!(
                400,
                "\"root\" cannot be named as an attached policy; it is a synthetic superuser policy that allows every \
                 path, so the dry-run would be meaningless"
            ));
        }

        let mut data = Map::new();

        let mut policy = match Policy::from_str(&policy_raw) {
            Ok(p) => p,
            Err(e) => {
                data.insert("parse_ok".into(), Value::Bool(false));
                data.insert("errors".into(), Value::Array(vec![Value::String(e.to_string())]));
                data.insert("results".into(), Value::Array(vec![]));
                return Ok(Some(Response::data_response(Some(data))));
            }
        };
        if let Some(name) = supplied_name {
            policy.name = name;
        }
        // ACL::new requires a name; a lone "root" policy would build a
        // superuser ACL, so reject that here — a dry-run must evaluate the
        // literal rules, not synthesize root.
        if policy.name == "root" {
            return Err(bv_error_response_status!(
                400,
                "a draft policy named \"root\" cannot be dry-run; root is a synthetic superuser policy"
            ));
        }
        if policy.name.is_empty() {
            policy.name = "__draft__".into();
        }

        let draft_name = policy.name.clone();
        let draft = Arc::new(policy);

        let store = self.policy_store.load();

        // Attaching a policy *reads* it, so the caller must be able to read
        // it. Without this the dry-run would be a read oracle for a caller
        // holding `update` on `sys/policies/acl/test` (the dry-run route)
        // but not `read` on the policy it names: attach it to an empty
        // draft and the per-case `matched_path` / `allowed` pairs recover
        // its rules. That combination is unusual — a caller who can write
        // any ACL policy can rewrite `default` and escalate anyway — but
        // "unusual" is not a control, and the endpoint's stated contract is
        // that it discloses nothing the caller could not already reach.
        //
        // Checked once per request against the caller's own ACL, built from
        // the token's own policies exactly as the request pipeline does.
        // Root short-circuits (`is_root`). No auth means the request never
        // reached a Write route, so treat it as deny.
        let attached_named: Vec<String> = {
            let mut names: Vec<String> = Vec::new();
            for case in cases.iter() {
                for n in case.attached.iter() {
                    if *n != draft_name && !names.iter().any(|x| x == n) {
                        names.push(n.clone());
                    }
                }
            }
            names
        };
        if !attached_named.is_empty() {
            let auth = req.auth.clone().ok_or(RvError::ErrPermissionDenied)?;
            let request_ns = if ns.is_empty() { None } else { Some(ns.as_str()) };
            let caller_acl = store.new_acl_for_request(&auth.policies, None, &auth, request_ns).await?;
            for name in attached_named.iter() {
                let probe = format!("sys/policies/acl/{name}");
                if !caller_acl
                    .explain_capability(&probe, crate::modules::policy::policy::Capability::Read)
                    .allowed
                {
                    return Err(bv_error_response_status!(
                        403,
                        &format!(
                            "cannot attach policy \"{name}\": the caller has no `read` capability on \
                             sys/policies/acl/{name}"
                        )
                    ));
                }
            }
        }

        // The namespace prefix the request router would put on a
        // mount-relative path before the ACL ever sees it. Every case path is
        // normalised through the router's own helper below, so the dry-run
        // and the pipeline agree on what a policy path means.
        let ns_prefix = if ns.is_empty() { String::new() } else { format!("{ns}/") };

        // The token being modelled: one bound to `ns`, carrying the named
        // policies. Namespace metadata is overridden so `{{namespace.path}}`
        // and the implicit `namespace-self` / `namespace-shared` injection
        // resolve for the namespace under test rather than for the
        // administrator running the dry-run. Identity placeholders
        // (`{{username}}`, `{{entity.id}}`) still resolve to the caller —
        // a stateless dry-run has no other principal to offer, and that
        // limitation is documented in `features/policy-builder-validator.md`.
        let modelled_auth = {
            let mut a = req.auth.clone().unwrap_or_default();
            use crate::modules::namespace::token_binding::NS_PATH_META;
            a.metadata.insert(NS_PATH_META.to_string(), ns.clone());
            a
        };
        let request_ns_opt = Some(ns.as_str());

        // Throwaway ACLs, all built from the draft. Never stored.
        //
        // The draft-only ACL backs `draft_only_allowed` on every row: it is
        // the verdict the single-policy dry-run used to give, kept so the
        // GUI can point at the difference instead of just reporting a
        // narrower answer than the operator's draft says.
        let draft_acl = ACL::new(std::slice::from_ref(&draft))?;
        // One ACL per distinct attached-policy set, keyed by that set.
        // Cases usually share one set, so this reads each attached policy
        // from the store once.
        let mut acl_cache: Vec<AttachedAcl> = Vec::new();

        let mut results = Vec::with_capacity(cases.len());
        for case in &cases {
            let key = case.attached.join("\u{0}");
            let cached = match acl_cache.iter().position(|c| c.key == key) {
                Some(i) => i,
                None => {
                    // Built through the *same* function the request pipeline
                    // uses (`PolicyStore::build_acl`), in the same namespace,
                    // with the same implicit-policy injection and the same
                    // templating. Resolving attached policies here by hand is
                    // what let the dry-run model a policy set no real token
                    // could ever carry.
                    let attached: Vec<String> =
                        case.attached.iter().filter(|n| **n != draft_name).cloned().collect();
                    let (acl, unresolved) = store
                        .new_acl_in_namespace(
                            &attached,
                            Some(vec![draft.clone()]),
                            &modelled_auth,
                            request_ns_opt,
                            &ns,
                        )
                        .await?;
                    let mut evaluated: Vec<String> = vec![draft_name.clone()];
                    evaluated.extend(attached.iter().filter(|n| !unresolved.contains(n)).cloned());
                    // A `default` that does not exist in a non-root namespace
                    // is not missing: the implicit `namespace-self` /
                    // `namespace-shared` pair injected by `build_acl` *is*
                    // that namespace's effective default, and it is in the ACL
                    // we just built. Reporting it as missing (and then
                    // rendering a verdict anyway) told operators their test
                    // ran against a policy set it had not actually used.
                    let substituted_default =
                        !ns.is_empty() && unresolved.iter().any(|n| n == policy_store::DEFAULT_POLICY_NAME);
                    if substituted_default {
                        evaluated.push("namespace-self".into());
                        evaluated.push("namespace-shared".into());
                    }
                    let missing: Vec<String> = unresolved
                        .into_iter()
                        .filter(|n| !(substituted_default && n == policy_store::DEFAULT_POLICY_NAME))
                        .collect();
                    acl_cache.push(AttachedAcl { key, acl, evaluated, missing });
                    acl_cache.len() - 1
                }
            };
            let entry = &acl_cache[cached];

            // The string the pipeline would authorize. A case typed
            // mount-relative and the same case typed namespace-prefixed are
            // the same request once the router has run, so they must produce
            // one verdict — previously they produced two, and the prefixed one
            // (which is what the GUI's POLICY PATH field hands the operator)
            // reported `allowed` for requests the pipeline refused.
            let resolved_path =
                crate::modules::namespace::router::qualify_path_for_namespace(&ns_prefix, &case.path);

            let mut row = Map::new();
            row.insert("path".into(), Value::String(case.path.clone()));
            row.insert("resolved_path".into(), Value::String(resolved_path.clone()));
            row.insert("namespace".into(), Value::String(ns.clone()));
            row.insert("capability".into(), Value::String(case.capability.clone()));
            row.insert("evaluated_policies".into(), string_array(&entry.evaluated));
            row.insert("missing_policies".into(), string_array(&entry.missing));

            // Fail closed and loudly. A named policy that does not resolve in
            // this namespace makes the modelled ACL strictly narrower than the
            // token it claims to represent, so any verdict computed from it is
            // a guess. Render the row without one rather than print an answer
            // the pipeline may contradict.
            if !entry.missing.is_empty() {
                row.insert("verdict_available".into(), Value::Bool(false));
                row.insert("allowed".into(), Value::Null);
                row.insert("denied_by_deny".into(), Value::Null);
                row.insert("match_kind".into(), Value::String("unknown".into()));
                row.insert("matched_path".into(), Value::Null);
                row.insert("granting_policies".into(), Value::Array(vec![]));
                row.insert("draft_only_allowed".into(), Value::Null);
                row.insert(
                    "error".into(),
                    Value::String(format!(
                        "cannot evaluate: {} does not exist in namespace {:?}, so the modelled \
                         policy set is not the one a real token would carry",
                        entry
                            .missing
                            .iter()
                            .map(|n| format!("policy {n:?}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        if ns.is_empty() { "(root)" } else { ns.as_str() },
                    )),
                );
                results.push(Value::Object(row));
                continue;
            }
            row.insert("verdict_available".into(), Value::Bool(true));

            match Capability::from_str(&case.capability) {
                Ok(cap) => {
                    // The optional `env` is fed to the matcher as a request
                    // parameter so the governing rule's env restriction
                    // (`required_parameters` / `allowed_parameters.env`) is
                    // actually evaluated. Empty/absent env preserves the
                    // bitmap-only dry-run.
                    let explain = |acl: &ACL| match &case.env {
                        Some(e) => {
                            let mut params = Map::new();
                            params.insert("env".into(), Value::String(e.clone()));
                            acl.explain_capability_with_params(&resolved_path, cap, &params)
                        }
                        None => acl.explain_capability(&resolved_path, cap),
                    };
                    let ex = explain(&entry.acl);
                    let draft_only = explain(&draft_acl);

                    row.insert("allowed".into(), Value::Bool(ex.allowed));
                    row.insert("denied_by_deny".into(), Value::Bool(ex.denied_by_deny));
                    row.insert("match_kind".into(), Value::String(ex.match_kind.as_str().into()));
                    row.insert(
                        "matched_path".into(),
                        ex.matched_path.map(Value::String).unwrap_or(Value::Null),
                    );
                    row.insert("granting_policies".into(), string_array(&ex.granting_policies));
                    row.insert("draft_only_allowed".into(), Value::Bool(draft_only.allowed));
                }
                Err(_) => {
                    row.insert("allowed".into(), Value::Bool(false));
                    row.insert("denied_by_deny".into(), Value::Bool(false));
                    row.insert("match_kind".into(), Value::String("none".into()));
                    row.insert("matched_path".into(), Value::Null);
                    row.insert("granting_policies".into(), Value::Array(vec![]));
                    row.insert("draft_only_allowed".into(), Value::Bool(false));
                    row.insert("error".into(), Value::String(format!("unknown capability: {}", case.capability)));
                }
            }
            results.push(Value::Object(row));
        }

        data.insert("parse_ok".into(), Value::Bool(true));
        data.insert("errors".into(), Value::Array(vec![]));
        data.insert("results".into(), Value::Array(results));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `GET sys/policy-tests/<name>` — return the saved effectivity test
    /// cases attached to a policy. Empty when none are saved. Test cases
    /// are stored alongside, not inside, the policy HCL.
    pub async fn handle_policy_tests_read(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req.get_data_as_str("name")?;
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());
        let cases = self.policy_store.load().get_policy_tests_ns(&name, &ns).await?;

        let arr = Value::Array(
            cases
                .iter()
                .map(|c| {
                    let mut m = Map::new();
                    m.insert("path".into(), Value::String(c.path.clone()));
                    m.insert("capability".into(), Value::String(c.capability.clone()));
                    m.insert("expect".into(), Value::String(c.expect.clone()));
                    m.insert("note".into(), Value::String(c.note.clone()));
                    m.insert("env".into(), Value::String(c.env.clone()));
                    m.insert("expect_key".into(), Value::String(c.expect_key.clone()));
                    m.insert("expect_value".into(), Value::String(c.expect_value.clone()));
                    // Emitted only when set: the client must be able to
                    // tell "unspecified" from an explicit empty list.
                    if let Some(policies) = c.policies.as_ref() {
                        m.insert("policies".into(), string_array(policies));
                    }
                    Value::Object(m)
                })
                .collect(),
        );
        let mut data = Map::new();
        data.insert("cases".into(), arr);
        Ok(Some(Response::data_response(Some(data))))
    }

    /// `POST sys/policy-tests/<name>` — overwrite the saved effectivity
    /// test cases attached to a policy. An empty array clears them.
    pub async fn handle_policy_tests_write(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        use crate::modules::policy::policy_store::PolicyTestCase;

        let name = req.get_data_as_str("name")?;
        let ns = crate::modules::namespace::policy_scope::writer_namespace_path(req.headers.as_ref());

        let cases: Vec<PolicyTestCase> = match req.get_data("cases") {
            Ok(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| {
                    let o = v.as_object()?;
                    let path = o.get("path")?.as_str()?.to_string();
                    let capability = o.get("capability")?.as_str()?.to_string();
                    // Default to "allow" so a malformed/absent expectation
                    // fails closed toward the stricter assertion at gate time.
                    let expect = o
                        .get("expect")
                        .and_then(|v| v.as_str())
                        .filter(|s| *s == "allow" || *s == "deny")
                        .unwrap_or("allow")
                        .to_string();
                    let note = o.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let env = o.get("env").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let expect_key = o.get("expect_key").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let expect_value = o.get("expect_value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    // Tri-state, preserved verbatim: absent stays absent
                    // (resolves to `["default"]` at run time), an explicit
                    // empty array stays empty (draft alone). Collapsing the
                    // two would silently change what the saved case — and
                    // therefore the save-time regression gate — asserts.
                    let policies = match o.get("policies") {
                        Some(Value::Array(names)) => Some(
                            names
                                .iter()
                                .filter_map(|n| n.as_str())
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string())
                                .collect(),
                        ),
                        _ => None,
                    };
                    Some(PolicyTestCase {
                        path,
                        capability,
                        expect,
                        note,
                        env,
                        expect_key,
                        expect_value,
                        policies,
                    })
                })
                .collect(),
            _ => Vec::new(),
        };

        self.policy_store.load().set_policy_tests_ns(&name, &cases, &ns).await?;
        Ok(None)
    }
}

/// One parsed dry-run case: the `(path, capability)` assertion, the
/// optional `env` request parameter, and the set of policies a real token
/// would carry alongside the draft.
struct DryRunCase {
    path: String,
    capability: String,
    env: Option<String>,
    /// Already resolved: an absent wire field becomes `["default"]`, an
    /// explicit empty array stays empty (draft alone). See
    /// [`parse_dry_run_case`].
    attached: Vec<String>,
}

/// An ACL built for one distinct attached-policy set, memoized across the
/// cases that share that set.
struct AttachedAcl {
    /// The case's `attached` list joined by NUL — a separator no policy
    /// name can contain, so distinct sets never collide.
    key: String,
    acl: acl::ACL,
    /// Every policy in `acl`, draft first. The draft appears under its own
    /// name, so an operator editing `default` sees a single entry.
    evaluated: Vec<String>,
    /// Attached names that do not exist in this namespace.
    missing: Vec<String>,
}

/// Parse one wire case. Rows missing `path` or `capability` are dropped
/// (the GUI sends partially-filled rows while the operator types).
///
/// The `policies` field is tri-state and the distinction is deliberate:
/// absent means "a normal token", which carries `default`; an explicit
/// empty array means "the draft alone" and is the only way back to the
/// original single-policy dry-run.
fn parse_dry_run_case(v: &Value) -> Option<DryRunCase> {
    let o = v.as_object()?;
    let path = o.get("path")?.as_str()?.to_string();
    let capability = o.get("capability")?.as_str()?.to_string();
    let env = o.get("env").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let attached = match o.get("policies") {
        Some(Value::Array(names)) => names
            .iter()
            .filter_map(|n| n.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        _ => vec![policy_store::DEFAULT_POLICY_NAME.to_string()],
    };
    Some(DryRunCase { path, capability, env, attached })
}

fn string_array(values: &[String]) -> Value {
    Value::Array(values.iter().map(|s| Value::String(s.clone())).collect())
}

/// Collect the deduped list of asset-group names referenced via
/// `groups = [...]` across every path rule in the policy. Case is
/// preserved (names are already lowercased at parse time by
/// `policy.rs`).
fn collect_referenced_groups(policy: &Policy) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pr in policy.paths.iter() {
        for g in pr.groups.iter() {
            if !out.iter().any(|x| x == g) {
                out.push(g.clone());
            }
        }
    }
    out
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Best-effort caller identity for audit entries. Prefers the
/// `username` metadata field (populated by UserPass login), then
/// `auth.display_name`, then falls back to `"unknown"`.
fn caller_username(req: &Request) -> String {
    if let Some(auth) = req.auth.as_ref() {
        if let Some(u) = auth.metadata.get("username") {
            if !u.is_empty() {
                return u.clone();
            }
        }
        if !auth.display_name.is_empty() {
            return auth.display_name.clone();
        }
    }
    "unknown".to_string()
}

#[maybe_async::maybe_async]
impl Module for PolicyModule {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn register(self: Arc<Self>, services: &crate::kernel_api::KernelServices) {
        kernel_service::register(self, services);
    }

    fn flush_caches(&self) {
        self.policy_store.load().flush_caches();
    }

    fn setup(&self, _core: &dyn VaultCtx) -> Result<(), RvError> {
        Ok(())
    }

    async fn init(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        let policy_store = PolicyStore::new(&self.core).await?;
        self.policy_store.store(policy_store.clone());

        self.setup_policy().await?;

        core.add_auth_handler(policy_store.clone() as Arc<dyn AuthHandler>)?;
        // Also register as a regular Handler so `Handler::post_route`
        // runs after the backend returns. The post-route pass handles
        // list-filter (keys narrowed to asset-group members) and the
        // KV-delete lifecycle prune from resource-groups.
        core.add_handler(policy_store as Arc<dyn Handler>)?;

        Ok(())
    }

    fn cleanup(&self, core: &dyn VaultCtx) -> Result<(), RvError> {
        core.delete_auth_handler(self.policy_store.load().clone() as Arc<dyn AuthHandler>)?;
        core.delete_handler(self.policy_store.load().clone() as Arc<dyn Handler>)?;
        let policy_store = Arc::new(PolicyStore::default());
        self.policy_store.swap(policy_store);
        Ok(())
    }
}

#[cfg(test)]
mod mod_policy_tests {
    use policy_store::DEFAULT_POLICY;
    use serde_json::json;

    use super::*;
    use crate::{
        logical::{Operation, Request},
        test_utils::{
            new_unseal_test_bastion_vault, test_delete_api, test_list_api, test_mount_api, test_mount_auth_api,
            test_read_api, test_write_api, TestHttpServer,
        },
    };

    #[maybe_async::maybe_async]
    async fn test_write_policy(core: &dyn VaultCtx, token: &str, name: &str, policy: &str) {
        let data = json!({
            "policy": policy,
        })
        .as_object()
        .cloned();

        let resp = test_write_api(core, token, format!("sys/policy/{}", name).as_str(), true, data).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_read_policy(core: &dyn VaultCtx, token: &str, name: &str) -> Result<Option<Response>, RvError> {
        let resp = test_read_api(core, token, format!("sys/policy/{}", name).as_str(), true).await;
        assert!(resp.is_ok());
        resp
    }

    #[maybe_async::maybe_async]
    async fn test_delete_policy(core: &dyn VaultCtx, token: &str, name: &str) {
        let resp = test_delete_api(core, token, format!("sys/policy/{}", name).as_str(), true, None).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_write_user(
        core: &dyn VaultCtx,
        token: &str,
        path: &str,
        username: &str,
        password: &str,
        policy: &str,
        ttl: i32,
    ) {
        let user_data = json!({
            "password": password,
            "token_policies": policy,
            "ttl": ttl,
        })
        .as_object()
        .cloned();

        let resp =
            test_write_api(core, token, format!("auth/{}/users/{}", path, username).as_str(), true, user_data).await;
        assert!(resp.is_ok());
    }

    #[maybe_async::maybe_async]
    async fn test_user_login(
        core: &dyn VaultCtx,
        path: &str,
        username: &str,
        password: &str,
        is_ok: bool,
    ) -> Result<Option<Response>, RvError> {
        let login_data = json!({
            "password": password,
        })
        .as_object()
        .cloned();

        let mut req = Request::new(format!("auth/{}/login/{}", path, username).as_str());
        req.operation = Operation::Write;
        req.body = login_data;

        let resp = core.handle_request(&mut req).await;
        assert!(resp.is_ok());
        if is_ok {
            let resp = resp.as_ref().unwrap();
            assert!(resp.is_some());
        }
        resp
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_curd_api() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_policy_curd_api").await;

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/" {
                capabilities = ["read"]
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;

        // Read
        let policy1 = test_read_policy(&core, &root_token, policy1_name).await;
        assert!(policy1.is_ok());
        let policy1 = policy1.unwrap();
        assert!(policy1.is_some());
        let policy1 = policy1.unwrap();
        assert!(policy1.data.is_some());
        let policy1 = policy1.data.unwrap();
        assert_eq!(policy1["name"], policy1_name);
        assert_eq!(policy1["rules"], policy1_hcl);

        // List
        let policies = test_list_api(&core, &root_token, "sys/policy", true).await;
        assert!(policies.is_ok());
        let policies = policies.unwrap();
        assert!(policies.is_some());
        let policies = policies.unwrap();
        assert!(policies.data.is_some());
        let policies = policies.data.unwrap();
        // Seeded policies — `standard-user`, `standard-user-readonly`,
        // `secret-author`, and the per-engine `*-admin` / `*-user`
        // pairs all ship in the default install (see
        // `policy_store.rs`) alongside `default` and `root`. This
        // list grows whenever a new secret-engine ships its own
        // bundled policies, so update it in lock-step with the
        // additions to `policy_store.rs::seed_default_policies`.
        let expected = json!([
            "administrator",
            "default",
            "ldap-admin",
            "ldap-user",
            "pki-admin",
            "pki-user",
            policy1_name,
            "secret-author",
            "shared-access",
            "standard-user",
            "standard-user-readonly",
            "totp-admin",
            "totp-user",
            "transit-admin",
            "transit-user",
            "root"
        ]);
        assert_eq!(policies["keys"], expected);
        assert_eq!(policies["policies"], expected);

        // Delete
        test_delete_policy(&core, &root_token, policy1_name).await;

        // Read again
        let policy1 = test_read_api(&core, &root_token, format!("sys/policy/{}", policy1_name).as_str(), false).await;
        let policy1 = policy1.unwrap_err();
        assert!(policy1.to_string().contains("status: 404,"));
        assert!(policy1.to_string().contains("No policy named: "));
        assert!(policy1.to_string().contains(policy1_name));

        // List again — same seeded set as before the policy1 round
        // trip, just without policy1 itself. Update in lock-step with
        // `policy_store.rs::seed_default_policies` whenever a new
        // engine adds its bundled policies.
        let policies = test_list_api(&core, &root_token, "sys/policy", true).await;
        let policies = policies.unwrap().unwrap().data.unwrap();
        let seeded_after_delete = json!([
            "administrator", "default", "ldap-admin", "ldap-user", "pki-admin", "pki-user",
            "secret-author", "shared-access", "standard-user", "standard-user-readonly",
            "totp-admin", "totp-user", "transit-admin", "transit-user", "root"
        ]);
        assert_eq!(policies["keys"], seeded_after_delete);
        assert_eq!(policies["policies"], seeded_after_delete);
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_http_api() {
        let mut test_http_server = TestHttpServer::new("test_policy_http_api", true).await;

        // set token
        test_http_server.token = test_http_server.root_token.clone();

        // List policies — `standard-user`, `standard-user-readonly`,
        // `secret-author`, and the per-engine `*-admin` / `*-user`
        // pairs are all seeded alongside the built-ins. This list
        // grows whenever a new secret-engine ships its own bundled
        // policies, so update it in lock-step with
        // `policy_store.rs::seed_default_policies`.
        let ret = test_http_server.read("sys/policy", None);
        assert!(ret.is_ok());
        let seeded = json!([
            "administrator", "default", "ldap-admin", "ldap-user", "pki-admin", "pki-user",
            "secret-author", "shared-access", "standard-user", "standard-user-readonly",
            "totp-admin", "totp-user", "transit-admin", "transit-user", "root"
        ]);
        assert_eq!(
            ret.unwrap().1,
            json!({ "keys": seeded.clone(), "policies": seeded })
        );

        // Read default policy
        let ret = test_http_server.read("sys/policy/default", None);
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap().1, json!({"name": "default", "rules": DEFAULT_POLICY}));

        // Write policy1
        let policy1_hcl = r#"
            path "path1/" {
                capabilities = ["read"]
            }
        "#;
        let data = json!({
            "policy": policy1_hcl,
        })
        .as_object()
        .cloned();
        let ret = test_http_server.write("sys/policy/policy1", data, None);
        assert!(ret.is_ok());

        // Read policy1
        let ret = test_http_server.read("sys/policy/policy1", None);
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap().1, json!({"name": "policy1", "rules": policy1_hcl}));

        // List policies again — seeded set plus policy1.
        let ret = test_http_server.read("sys/policy", None);
        assert!(ret.is_ok());
        let with_policy1 = json!([
            "administrator", "default", "ldap-admin", "ldap-user", "pki-admin", "pki-user", "policy1",
            "secret-author", "shared-access", "standard-user", "standard-user-readonly",
            "totp-admin", "totp-user", "transit-admin", "transit-user", "root"
        ]);
        assert_eq!(
            ret.unwrap().1,
            json!({ "keys": with_policy1.clone(), "policies": with_policy1 })
        );

        // Delete policy1
        let ret = test_http_server.delete("sys/policy/policy1", None, None);
        assert!(ret.is_ok());

        // List policies again — back to the seeded baseline.
        let ret = test_http_server.read("sys/policy", None);
        assert!(ret.is_ok());
        let baseline = json!([
            "administrator", "default", "ldap-admin", "ldap-user", "pki-admin", "pki-user",
            "secret-author", "shared-access", "standard-user", "standard-user-readonly",
            "totp-admin", "totp-user", "transit-admin", "transit-user", "root"
        ]);
        assert_eq!(
            ret.unwrap().1,
            json!({ "keys": baseline.clone(), "policies": baseline })
        );
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_acl_check() {
        let (_bvault, core, root_token) = new_unseal_test_bastion_vault("test_policy_acl_check").await;

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/*" {
                capabilities = ["read"]
            }

            path "path1/kv1" {
                capabilities = ["read", "list", "create", "update", "delete"]
            }
        "#;
        let policy2_name = "policy2";
        let policy2_hcl = r#"
            path "path1/*" {
                capabilities = ["read", "list", "create", "update"]
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;
        test_write_policy(&core, &root_token, policy2_name, policy2_hcl).await;

        // Mount userpass auth
        test_mount_auth_api(&core, &root_token, "userpass", "up1").await;

        // Add user xxx with policy1, add user yyy with policy2
        test_write_user(&core, &root_token, "up1", "xxx", "123qwe!@#", policy1_name, 0).await;
        let resp = test_user_login(&core, "up1", "xxx", "123qwe!@#", true).await;
        assert!(resp.is_ok());
        let xxx_token = resp.unwrap().unwrap().auth.unwrap().client_token;
        test_write_user(&core, &root_token, "up1", "yyy", "123456", policy2_name, 0).await;
        let resp = test_user_login(&core, "up1", "yyy", "123456", true).await;
        assert!(resp.is_ok());
        let yyy_token = resp.unwrap().unwrap().auth.unwrap().client_token;

        // Mount kv to path1/ and path2/
        test_mount_api(&core, &root_token, "kv", "path1/").await;
        test_mount_api(&core, &root_token, "kv", "path2/").await;

        // User xxx write path path1/kv1 should succeed
        let data = json!({
            "aa": "bb",
        })
        .as_object()
        .cloned();
        let resp = test_write_api(&core, &xxx_token, "path1/kv1", true, data.clone()).await;
        assert!(resp.is_ok());

        // User xxx write path1/kv2 should fail
        let resp = test_write_api(&core, &xxx_token, "path1/kv2", false, data.clone()).await;
        assert!(resp.is_err());

        // User yyy write path1/kv2 should succeed
        let resp = test_write_api(&core, &yyy_token, "path1/kv2", true, data).await;
        assert!(resp.is_ok());

        // User xxx read path1/kv1 should succeed
        let resp = test_read_api(&core, &xxx_token, "path1/kv1", true).await;
        assert!(resp.is_ok());

        // User xxx read path1/kv2 should succeed
        let resp = test_read_api(&core, &xxx_token, "path1/kv2", true).await;
        assert!(resp.is_ok());

        // User yyy read path1/kv1 should succeed
        let resp = test_read_api(&core, &yyy_token, "path1/kv1", true).await;
        assert!(resp.is_ok());

        // User yyy read path1/kv2 should succeed
        let resp = test_read_api(&core, &yyy_token, "path1/kv2", true).await;
        assert!(resp.is_ok());

        // User xxx list path1/ should fail
        let resp = test_list_api(&core, &xxx_token, "path1", false).await;
        assert!(resp.is_err());

        // User yyy list path1/ should fail
        let resp = test_list_api(&core, &yyy_token, "path1", false).await;
        assert!(resp.is_err());

        // User yyy delete path1/kv1 should fail
        let resp = test_delete_api(&core, &yyy_token, "path1/kv1", false, None).await;
        assert!(resp.is_err());

        // User yyy delete path1/kv2 should fail
        let resp = test_delete_api(&core, &yyy_token, "path1/kv2", false, None).await;
        assert!(resp.is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_policy_acl_check_with_policy_parameters() {
        let (_bvault, core, root_token) =
            new_unseal_test_bastion_vault("test_policy_acl_check_with_policy_parameters").await;

        let policy1_name = "policy1";
        let policy1_hcl = r#"
            path "path1/*" {
                capabilities = ["read", "list"]
            }

            path "path1/kv1" {
                capabilities = ["read", "list", "create", "update", "delete"]
                allowed_parameters = {"key1" = ["value1", "value2"], "key2" = ["value3", "value4"]}
                required_parameters = ["key1"]
            }

            path "path1/kv2" {
                capabilities = ["read", "list", "create", "update"]
                required_parameters = ["key1", "key2", "key3"]
            }

            path "path1/kv3" {
                capabilities = ["read", "list", "create", "update"]
                denied_parameters = {"*" = []}
            }

            path "path1/kv4" {
                capabilities = ["read", "list", "create", "update"]
                denied_parameters = {"key2" = ["value3", "value4"]}
            }
        "#;

        // Write
        test_write_policy(&core, &root_token, policy1_name, policy1_hcl).await;

        // Mount userpass auth
        test_mount_auth_api(&core, &root_token, "userpass", "up1").await;

        // Add user xxx with policy1
        test_write_user(&core, &root_token, "up1", "xxx", "123qwe!@#", policy1_name, 0).await;
        let resp = test_user_login(&core, "up1", "xxx", "123qwe!@#", true).await;
        assert!(resp.is_ok());
        let xxx_token = resp.unwrap().unwrap().auth.unwrap().client_token;

        // Mount kv to path1/ and path2/
        test_mount_api(&core, &root_token, "kv", "path1/").await;

        // User xxx write path path1/kv1 with parameters key1=value1 should succeed
        let data = json!({
            "key1": "value1",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, data).await;

        // User xxx write path path1/kv1 with parameters key1=value2 should succeed
        let data = json!({
            "key1": "value2",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, data.clone()).await;

        // User xxx write path1/kv2 should fail
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, data).await;

        // User xxx write path path1/kv1 with parameters key1=value1 and key2=value3 should succeed
        let data = json!({
            "key1": "value1",
            "key2": "value3",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, data).await;

        // User xxx write path path1/kv1 with parameters key1=value1 and key2=value4 should succeed
        let data = json!({
            "key1": "value1",
            "key2": "value4",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", true, data).await;

        // User xxx write path path1/kv1 with parameters key1=value2 and key2=value22 should fail
        let data = json!({
            "key1": "value2",
            "key2": "value22",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, data).await;

        // User xxx read path1/kv1 without parameters should fail
        let _ = test_read_api(&core, &xxx_token, "path1/kv1", false).await;

        // User xxx list path1/ should fail
        let _ = test_list_api(&core, &xxx_token, "path1", false).await;

        // User xxx write path path1/kv1 with parameters key1=value3 should fail
        let data = json!({
            "key1": "value3",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, data).await;

        // User xxx write path path1/kv1 with parameters key2=value3 (missing key1) should fail
        let data = json!({
            "key2": "value3",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv1", false, data).await;

        // User xxx write path path1/kv2 with parameters key1 (missing key2 and key3) should fail
        let data = json!({
            "key1": "xx",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, data).await;

        // User xxx write path path1/kv2 with parameters key1 and key2 (missing key3) should fail
        let data = json!({
            "key1": "xx",
            "key2": "yy",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", false, data).await;

        // User xxx write path path1/kv2 with parameters key1、key2 and key3 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy",
            "key3": "zz",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", true, data).await;

        // User xxx write path path1/kv2 with parameters key1、key2、key3 and other param should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy",
            "key3": "zz",
            "key4": "vv",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv2", true, data).await;

        // User xxx write path path1/kv3 with parameters key1 should fail
        let data = json!({
            "key1": "xx",
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv3", false, data).await;

        // User xxx write path path1/kv3 with parameters key1 should fail
        let data = json!({
            "key1": "xx",
            "key2": "yy"
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv3", false, data).await;

        // User xxx write path path1/kv4 with parameters key1 should succeed
        let data = json!({
            "key1": "xx"
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", true, data).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=yy should succeed
        let data = json!({
            "key1": "xx",
            "key2": "yy"
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", true, data).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=value3 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "value3"
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", false, data).await;

        // User xxx write path path1/kv4 with parameters key1 and key2=value4 should succeed
        let data = json!({
            "key1": "xx",
            "key2": "value4"
        })
        .as_object()
        .cloned();
        let _ = test_write_api(&core, &xxx_token, "path1/kv4", false, data).await;
    }
}

/// Parity between the policy tester (`sys/policies/acl/test`) and the request
/// pipeline.
///
/// The invariant: for one policy, one namespace, one principal and one logical
/// target, the verdict the tester renders and the verdict the pipeline renders
/// must be the same — and the tester's verdict must not depend on which of the
/// two equivalent spellings the operator typed, because the pipeline cannot
/// tell them apart.
///
/// Written as the general invariant rather than as a string match on one path:
/// the defect was the *divergence*, and pinning a single path would let it
/// reappear on the next one.
#[cfg(test)]
mod tester_pipeline_parity_tests {
    use serde_json::json;

    use crate::test_utils::TestHttpServer;

    const NS: &str = "dti/esi";
    const POLICY_NAME: &str = "github-fgv-esi-apps";

    /// The policy as shipped in the incident: every rule namespace-prefixed
    /// (the only shape `refuse_cross_namespace_paths` accepts inside a
    /// namespace), including a `docker/hub/*` rule that is a descendant of
    /// `docker/*`.
    const POLICY_HCL: &str = r#"
path "dti/esi/secret/data/github/*"     { capabilities = ["create","read","update","delete","list"] }
path "dti/esi/secret/data/docker/*"     { capabilities = ["create","read","update","delete","list"] }
path "dti/esi/secret/data/docker/hub/*" { capabilities = ["create","read","update","delete","list"] }
"#;

    /// Mount-relative targets the invariant is checked against. `docker/hub`
    /// is the incident path; `docker/hub/nested` exercises the descendant
    /// rule; the rest are controls.
    const GRANTED: &[&str] = &["docker/hub", "docker/hub/nested", "github/nessus", "docker/other"];
    /// Inside the same mount but matched by no rule in the policy.
    const UNGRANTED: &[&str] = &["gitlab/token"];

    struct Fixture {
        server: TestHttpServer,
        root: String,
        /// Logged in with no namespace header, so its token binds to root and
        /// `auth/token/lookup-self` reports `(root)`. It reaches `dti/esi`
        /// through a namespace assignment — the route the GUI's namespace
        /// switcher takes, and the principal in the report.
        root_bound: String,
        /// The same principal, same policies, bound to `NS` at login.
        ns_bound: String,
    }

    async fn setup(name: &str) -> Fixture {
        let mut server = TestHttpServer::new(name, true).await;
        let root = server.root_token.clone();
        server.token = root.clone();
        server.url_prefix = server.url_prefix.trim_end_matches("/v1").to_string();

        for path in ["dti", "dti/esi"] {
            let (s, r) = server
                .write(&format!("v1/sys/namespaces/{path}"), json!({}).as_object().cloned(), Some(&root))
                .unwrap();
            assert!((200..300).contains(&s), "ns create {path}: {s} {r:?}");
        }

        let (s, r) = server
            .request_with_headers(
                "POST",
                &format!("v1/sys/policies/acl/{POLICY_NAME}"),
                json!({ "policy": POLICY_HCL }).as_object().cloned(),
                Some(&root),
                None,
                &[("X-BastionVault-Namespace", NS)],
            )
            .unwrap();
        assert!((200..300).contains(&s), "policy write: {s} {r:?}");

        server
            .write("v1/sys/auth/userpass", json!({ "type": "userpass" }).as_object().cloned(), Some(&root))
            .unwrap();
        let (s, r) = server
            .write(
                "v1/auth/userpass/users/svc",
                json!({ "password": "hunter22XX!", "token_policies": format!("default,{POLICY_NAME}"), "ttl": 0 })
                    .as_object()
                    .cloned(),
                Some(&root),
            )
            .unwrap();
        assert!((200..300).contains(&s), "user create: {s} {r:?}");

        let (s, r) = server
            .write(
                "v1/sys/identity/ns-assignment/userpass/svc",
                json!({ "namespaces": ["", "dti", "dti/esi"] }).as_object().cloned(),
                Some(&root),
            )
            .unwrap();
        assert!((200..300).contains(&s), "ns-assignment: {s} {r:?}");

        for leaf in GRANTED.iter().chain(UNGRANTED.iter()) {
            let (s, r) = server
                .request_with_headers(
                    "POST",
                    &format!("v1/secret/data/{leaf}"),
                    json!({ "data": { "k": "v" } }).as_object().cloned(),
                    Some(&root),
                    None,
                    &[("X-BastionVault-Namespace", NS)],
                )
                .unwrap();
            assert!((200..300).contains(&s), "seed {leaf}: {s} {r:?}");
        }

        let (s, r) = server
            .write("v1/auth/userpass/login/svc", json!({ "password": "hunter22XX!" }).as_object().cloned(), None)
            .unwrap();
        assert_eq!(s, 200, "root-bound login: {r:?}");
        assert_eq!(
            r["auth"]["metadata"]["namespace_path"],
            json!(""),
            "this principal must be root-bound for the test to model the report"
        );
        let root_bound = r["auth"]["client_token"].as_str().unwrap().to_string();

        let (s, r) = server
            .request_with_headers(
                "POST",
                "v1/auth/userpass/login/svc",
                json!({ "password": "hunter22XX!" }).as_object().cloned(),
                None,
                None,
                &[("X-BastionVault-Namespace", NS)],
            )
            .unwrap();
        assert_eq!(s, 200, "ns-bound login: {r:?}");
        assert_eq!(r["auth"]["metadata"]["namespace_path"], json!(NS));
        let ns_bound = r["auth"]["client_token"].as_str().unwrap().to_string();

        Fixture { server, root, root_bound, ns_bound }
    }

    /// May this token read `secret/data/<leaf>` in `NS`? Sent as the report
    /// describes: namespace header plus a mount-relative path.
    fn pipeline_allows(f: &Fixture, token: &str, leaf: &str) -> bool {
        let (status, body) = f
            .server
            .request_with_headers(
                "GET",
                &format!("v1/secret/data/{leaf}"),
                None,
                Some(token),
                None,
                &[("X-BastionVault-Namespace", NS)],
            )
            .unwrap();
        assert!(status == 200 || status == 403, "unexpected pipeline status {status} for {leaf}: {body:?}");
        status == 200
    }

    /// One tester row for `path`, addressed to `NS`.
    fn tester_row(f: &Fixture, path: &str) -> serde_json::Value {
        let (status, body) = f
            .server
            .request_with_headers(
                "POST",
                "v2/sys/policies/acl/test",
                json!({
                    "policy": POLICY_HCL,
                    "name": POLICY_NAME,
                    "cases": [ { "path": path, "capability": "read" } ],
                })
                .as_object()
                .cloned(),
                Some(&f.root),
                None,
                &[("X-BastionVault-Namespace", NS)],
            )
            .unwrap();
        assert_eq!(status, 200, "tester on {path}: {body:?}");
        body["results"][0].clone()
    }

    /// The regression.
    ///
    /// Before the fix the tester matched the case path verbatim and resolved
    /// its policy set by hand from the request namespace, so
    /// `dti/esi/secret/data/docker/hub` reported `allowed` while
    /// `secret/data/docker/hub` — the string a client actually sends —
    /// reported `denied — no rule matched`, and neither was checked against
    /// what the pipeline does.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tester_verdict_matches_pipeline_verdict() {
        let f = setup("tester_pipeline_parity").await;

        let mut problems = Vec::new();
        for leaf in GRANTED.iter().chain(UNGRANTED.iter()) {
            // The tester models a token bound to the namespace under test, so
            // that is the pipeline verdict it must reproduce. The root-bound
            // principal's divergence is a separate, deliberate behaviour —
            // see `named_namespace_policy_reaches_only_namespace_bound_tokens`.
            let pipeline = pipeline_allows(&f, &f.ns_bound, leaf);

            let relative = tester_row(&f, &format!("secret/data/{leaf}"));
            let prefixed = tester_row(&f, &format!("{NS}/secret/data/{leaf}"));

            for (form, row) in [("mount-relative", &relative), ("namespace-prefixed", &prefixed)] {
                // A verdict must be available: `default` does not exist in a
                // non-root namespace, and the tester must recognise the
                // implicit namespace policies as that namespace's effective
                // default rather than declining or guessing.
                assert_eq!(
                    row["verdict_available"],
                    json!(true),
                    "secret/data/{leaf} ({form}): tester declined to answer: {row}"
                );
                // Both spellings must normalise to the string the router
                // authorizes.
                assert_eq!(
                    row["resolved_path"],
                    json!(format!("{NS}/secret/data/{leaf}")),
                    "secret/data/{leaf} ({form}): unexpected resolved path: {row}"
                );
                let allowed = row["allowed"].as_bool().unwrap_or(false);
                if allowed != pipeline {
                    problems.push(format!(
                        "secret/data/{leaf} ({form}): tester says {allowed}, pipeline says {pipeline}; row: {row}"
                    ));
                }
            }

            if relative["allowed"] != prefixed["allowed"] {
                problems.push(format!(
                    "secret/data/{leaf}: the tester's verdict depends on how the path was typed \
                     ({} vs {}); the pipeline cannot tell the two spellings apart",
                    relative["allowed"], prefixed["allowed"]
                ));
            }
        }

        assert!(
            problems.is_empty(),
            "the policy tester and the request pipeline disagree about the same policy, \
             namespace and principal:\n  {}",
            problems.join("\n  ")
        );
    }

    /// The tester must not render a verdict it cannot compute.
    ///
    /// A named policy that does not exist in the namespace makes the modelled
    /// ACL strictly narrower than the token it claims to represent, so any
    /// verdict from it is a guess. Previously the row carried
    /// `missing_policies: ["…"]` *and* `allowed: false` — indistinguishable
    /// from a real deny.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tester_declines_when_an_attached_policy_does_not_resolve() {
        let f = setup("tester_declines_unresolved").await;

        let (status, body) = f
            .server
            .request_with_headers(
                "POST",
                "v2/sys/policies/acl/test",
                json!({
                    "policy": POLICY_HCL,
                    "name": POLICY_NAME,
                    "cases": [ {
                        "path": "secret/data/docker/hub",
                        "capability": "read",
                        "policies": ["no-such-policy"],
                    } ],
                })
                .as_object()
                .cloned(),
                Some(&f.root),
                None,
                &[("X-BastionVault-Namespace", NS)],
            )
            .unwrap();
        assert_eq!(status, 200, "tester: {body:?}");
        let row = &body["results"][0];
        assert_eq!(row["verdict_available"], json!(false), "must decline: {row}");
        assert_eq!(row["allowed"], json!(null), "must not emit a verdict: {row}");
        assert_eq!(row["missing_policies"], json!(["no-such-policy"]), "{row}");
        assert!(
            row["error"].as_str().unwrap_or_default().contains("no-such-policy"),
            "the reason must name the policy: {row}"
        );
    }

    /// A case in a non-root namespace must resolve that namespace's *effective*
    /// default — the implicit `namespace-self` / `namespace-shared` pair — and
    /// not report `no such policy: default` while answering anyway.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn tester_resolves_the_effective_default_in_a_namespace() {
        let f = setup("tester_effective_default").await;

        // `policies` absent means ["default"], the set a real token carries.
        let row = tester_row(&f, "secret/data/docker/hub");
        assert_eq!(row["verdict_available"], json!(true), "{row}");
        assert_eq!(row["missing_policies"], json!([]), "`default` is not missing in a namespace: {row}");
        let evaluated = row["evaluated_policies"].as_array().cloned().unwrap_or_default();
        for expected in ["namespace-self", "namespace-shared"] {
            assert!(
                evaluated.iter().any(|v| v == expected),
                "the namespace's effective default must be reported as evaluated: {row}"
            );
        }
    }

    /// The authorization gap the divergence was hiding, pinned on its own so
    /// it is not mistaken for a tester bug and cannot change unnoticed.
    ///
    /// Same principal, same policy names, same policy document, same request.
    /// The only difference is whether the token bound to the namespace at login
    /// or reaches it through a namespace assignment: `new_acl_inner` resolves a
    /// token's named policies from its *binding* namespace, so the root-bound
    /// form silently carries none of `dti/esi`'s policies.
    ///
    /// This is current, deliberate behaviour — the supported way to give a
    /// root-bound principal reach into a namespace is a root-authored
    /// `{{request.namespace}}`-templated policy (`SHARED_ACCESS_POLICY`), not
    /// a policy authored inside the tenant. The test exists to make the
    /// asymmetry explicit rather than to bless it; changing it is a
    /// privilege expansion and must be a deliberate, separately reviewed call.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn named_namespace_policy_reaches_only_namespace_bound_tokens() {
        let f = setup("tester_pipeline_ns_binding").await;

        for leaf in GRANTED {
            assert!(
                pipeline_allows(&f, &f.ns_bound, leaf),
                "a namespace-bound token carrying {POLICY_NAME} must read secret/data/{leaf}"
            );
            assert!(
                !pipeline_allows(&f, &f.root_bound, leaf),
                "a root-bound token reaching {NS} by assignment does NOT resolve {POLICY_NAME} \
                 (it lives in the {NS} keyspace); if this now passes, authorization was widened \
                 — see the doc comment"
            );
        }
    }
}
