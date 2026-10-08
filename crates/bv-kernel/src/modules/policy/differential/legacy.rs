//! The ACL evaluator exactly as it was before T31 Phase 3.4, frozen as the
//! oracle of the differential suite.
//!
//! Copied verbatim from `acl.rs` / `policy.rs` at the commit that introduced
//! `bv-policy-core`: methods rewritten as free functions over the same pub
//! fields, comments and two empty `// TODO` wrapping-TTL blocks dropped,
//! logic untouched. It is the definition of "no behaviour change" for
//! the delegation: the production evaluator must agree with it on every
//! generated case. **Do not fix anything here.** A deliberate behaviour
//! change (F6, F7, F8 in the roadmap) changes this file in the same commit,
//! with the reason, so the suite keeps describing what shipped.
//!
//! Changed since it was frozen: F6 (T119) — the governing rule's and each
//! layered rule's own bitmap decides whether it is a deny, and a deny yields
//! exactly `deny` in both modes (`denied`), marked `T119 (F6)` below.

use std::{sync::Arc, time::Duration};

use radix_trie::{Trie, TrieCommon};

use super::super::{
    acl::{ACLResults, GroupGatedRule, ScopedRule, ACL},
    policy::{to_granting_capabilities, Capability},
    Permissions, Policy, PolicyPathRules, PolicyType,
};
use crate::{
    bv_error_string,
    errors::RvError,
    logical::{auth::PolicyInfo, Operation, Request},
    utils::string::{ensure_no_leading_slash, GlobContains},
};

#[derive(Debug, Clone, Default)]
struct WcPathDescr {
    first_wc_or_glob: isize,
    wc_path: String,
    is_prefix: bool,
    wildcards: usize,
    perms: Option<Permissions>,
}

impl PartialEq for WcPathDescr {
    fn eq(&self, other: &Self) -> bool {
        self.first_wc_or_glob == other.first_wc_or_glob
            && self.wc_path == other.wc_path
            && self.is_prefix == other.is_prefix
            && self.wildcards == other.wildcards
    }
}

impl Eq for WcPathDescr {}

impl PartialOrd for WcPathDescr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WcPathDescr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.first_wc_or_glob
            .cmp(&other.first_wc_or_glob)
            .then_with(|| other.is_prefix.cmp(&self.is_prefix))
            .then_with(|| other.wildcards.cmp(&self.wildcards))
            .then_with(|| self.wc_path.len().cmp(&other.wc_path.len()))
            .then_with(|| self.wc_path.cmp(&other.wc_path))
    }
}

pub fn new_acl(policies: &[Arc<Policy>]) -> Result<ACL, RvError> {
    let mut acl = ACL::default();
    for policy in policies.iter() {
        if policy.policy_type == PolicyType::Rgp {
            acl.rgp_policies.push(policy.clone());
            continue;
        } else if policy.policy_type != PolicyType::Acl {
            return Err(bv_error_string!("unable to parse policy (wrong type)"));
        }

        if policy.name == "root" {
            if policies.len() != 1 {
                return Err(bv_error_string!("other policies present along with root"));
            }
            acl.root = true;
        }

        for pr in policy.paths.iter() {
            if !pr.groups.is_empty() {
                let mut cloned_perms = pr.permissions.clone();
                cloned_perms.add_granting_policy_to_map(policy, pr.permissions.capabilities_bitmap)?;
                acl.grouped_rules.push(GroupGatedRule {
                    path: pr.path.clone(),
                    is_prefix: pr.is_prefix,
                    has_segment_wildcards: pr.has_segment_wildcards,
                    permissions: cloned_perms,
                });
                continue;
            }

            if !pr.scopes.is_empty() {
                let mut cloned_perms = pr.permissions.clone();
                cloned_perms.add_granting_policy_to_map(policy, pr.permissions.capabilities_bitmap)?;
                acl.scoped_rules.push(ScopedRule {
                    path: pr.path.clone(),
                    is_prefix: pr.is_prefix,
                    has_segment_wildcards: pr.has_segment_wildcards,
                    permissions: cloned_perms,
                });
                continue;
            }

            if let Some(mut existing_perms) = get_permissions(&acl, pr)? {
                let deny = Capability::Deny.to_bits();
                if existing_perms.capabilities_bitmap & deny != 0 {
                    continue;
                }

                merge(&mut existing_perms, &pr.permissions)?;
                existing_perms.add_granting_policy_to_map(policy, pr.permissions.capabilities_bitmap)?;
                insert_permissions(&mut acl, pr, existing_perms)?;
            } else {
                let mut cloned_perms = pr.permissions.clone();
                cloned_perms.add_granting_policy_to_map(policy, pr.permissions.capabilities_bitmap)?;
                insert_permissions(&mut acl, pr, cloned_perms)?;
            }
        }
    }

    Ok(acl)
}

fn get_permissions(acl: &ACL, pr: &PolicyPathRules) -> Result<Option<Permissions>, RvError> {
    if pr.has_segment_wildcards {
        if let Some(existing_perms) = acl.segment_wildcard_paths.get(&pr.path) {
            return Ok(Some(existing_perms.value().clone()));
        }
    } else {
        let tree = if pr.is_prefix { &acl.prefix_rules } else { &acl.exact_rules };

        if let Some(existing_perms) = tree.get(&pr.path) {
            return Ok(Some(existing_perms.clone()));
        }
    }

    Ok(None)
}

fn insert_permissions(acl: &mut ACL, pr: &PolicyPathRules, perm: Permissions) -> Result<(), RvError> {
    if pr.has_segment_wildcards {
        acl.segment_wildcard_paths.insert(pr.path.clone(), perm);
    } else {
        let tree = if pr.is_prefix { &mut acl.prefix_rules } else { &mut acl.exact_rules };

        tree.insert(pr.path.clone(), perm);
    }

    Ok(())
}

pub fn allow_operation(acl: &ACL, req: &Request, check_only: bool) -> Result<ACLResults, RvError> {
    if acl.root {
        return Ok(ACLResults {
            allowed: true,
            root_privs: true,
            is_root: true,
            granting_policies: vec![PolicyInfo {
                name: "root".into(),
                namespace_id: "root".into(),
                policy_type: "acl".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
    }

    if req.operation == Operation::Help {
        return Ok(ACLResults { allowed: true, ..Default::default() });
    }

    let path = ensure_no_leading_slash(&req.path);

    let governing = if let Some(perm) = acl.exact_rules.get(&path) {
        Some(perm.clone())
    } else if req.operation == Operation::List {
        if let Some(perm) = acl.exact_rules.get(path.trim_end_matches('/')) {
            Some(perm.clone())
        } else {
            get_none_exact_paths_permissions(acl, &path, false)
        }
    } else {
        get_none_exact_paths_permissions(acl, &path, false)
    };
    let mut base = match &governing {
        Some(perm) => check(perm, req, check_only)?,
        None => ACLResults::default(),
    };

    // T119 (F6): whether a rule denies is read from its bitmap, not from its
    // check's output, which on enforcement reports no capability for a deny.
    if governing.is_some_and(|perm| perm.capabilities_bitmap & Capability::Deny.to_bits() != 0) {
        return Ok(denied(base, check_only));
    }

    let is_list = req.operation == Operation::List;
    if !acl.grouped_rules.is_empty() && base.capabilities_bitmap & Capability::Deny.to_bits() == 0 {
        for rule in acl.grouped_rules.iter() {
            if !grouped_rule_matches(rule, &path) {
                continue;
            }
            let gate_passes = is_list || rule_gate_passes(rule, req);
            if !gate_passes {
                continue;
            }
            // T119 (F6): the rule's bitmap, not `sub`, decides it is a deny.
            if rule.permissions.capabilities_bitmap & Capability::Deny.to_bits() != 0 {
                return Ok(denied(base, check_only));
            }
            let sub = check(&rule.permissions, req, check_only)?;
            base.capabilities_bitmap |= sub.capabilities_bitmap;
            if sub.allowed {
                base.allowed = true;
            }
            if sub.root_privs {
                base.root_privs = true;
            }
            for g in sub.granting_policies {
                if !base.granting_policies.iter().any(|p| p.name == g.name) {
                    base.granting_policies.push(g);
                }
            }
            if is_list && sub.capabilities_bitmap & Capability::List.to_bits() != 0 {
                for g in rule.permissions.groups.iter() {
                    if !base.list_filter_groups.iter().any(|x| x == g) {
                        base.list_filter_groups.push(g.clone());
                    }
                }
            }
        }
    }

    if !acl.scoped_rules.is_empty() && base.capabilities_bitmap & Capability::Deny.to_bits() == 0 {
        for rule in acl.scoped_rules.iter() {
            if !scoped_rule_matches(rule, &path) {
                continue;
            }
            let scope_passes = is_list || scope_passes(rule, req);
            if !scope_passes {
                continue;
            }
            // T119 (F6): the rule's bitmap, not `sub`, decides it is a deny.
            if rule.permissions.capabilities_bitmap & Capability::Deny.to_bits() != 0 {
                return Ok(denied(base, check_only));
            }
            let sub = check(&rule.permissions, req, check_only)?;
            base.capabilities_bitmap |= sub.capabilities_bitmap;
            if sub.allowed {
                base.allowed = true;
            }
            if sub.root_privs {
                base.root_privs = true;
            }
            for g in sub.granting_policies {
                if !base.granting_policies.iter().any(|p| p.name == g.name) {
                    base.granting_policies.push(g);
                }
            }
            if is_list && sub.capabilities_bitmap & Capability::List.to_bits() != 0 {
                for s in rule.permissions.scopes.iter() {
                    if !base.list_filter_scopes.iter().any(|x| x == s) {
                        base.list_filter_scopes.push(s.clone());
                    }
                }
            }
        }
    }

    if is_list && (!base.list_filter_groups.is_empty() || !base.list_filter_scopes.is_empty()) {
        let ungated_list = matches_ungated_list(acl, &path);
        if ungated_list {
            base.list_filter_groups.clear();
            base.list_filter_scopes.clear();
        }
    }

    Ok(base)
}

/// T119 (F6): a deny that governs or applies yields exactly `deny`; on
/// enforcement it also clears `root_privs`, which a probe keeps.
fn denied(mut base: ACLResults, check_only: bool) -> ACLResults {
    base.allowed = false;
    base.capabilities_bitmap = Capability::Deny.to_bits();
    base.granting_policies.clear();
    base.list_filter_groups.clear();
    base.list_filter_scopes.clear();
    if !check_only {
        base.root_privs = false;
    }
    base
}

pub fn get_none_exact_paths_permissions(acl: &ACL, path: &str, bare_mount: bool) -> Option<Permissions> {
    let mut wc_path_descrs = Vec::with_capacity(acl.segment_wildcard_paths.len() + 1);

    if let Some(item) = acl.prefix_rules.get_ancestor(path) {
        if acl.segment_wildcard_paths.is_empty() {
            return Some(item.value().unwrap().clone());
        }

        let prefix = item.key().unwrap().clone();
        wc_path_descrs.push(WcPathDescr {
            first_wc_or_glob: prefix.len() as isize,
            wc_path: prefix,
            is_prefix: true,
            perms: item.value().cloned(),
            ..Default::default()
        });
    }

    if acl.segment_wildcard_paths.is_empty() {
        return None;
    }

    let path_parts: Vec<&str> = path.split('/').collect();

    for item in acl.segment_wildcard_paths.iter() {
        let (full_wc_path, permissions) = (item.key(), item.value());

        if full_wc_path.is_empty() {
            continue;
        }

        let mut pd = WcPathDescr {
            first_wc_or_glob: full_wc_path.find('+').map(|i| i as isize).unwrap_or(-1),
            ..Default::default()
        };

        let mut curr_wc_path = full_wc_path.as_str();
        if curr_wc_path.ends_with('*') {
            pd.is_prefix = true;
            curr_wc_path = &curr_wc_path[..curr_wc_path.len() - 1];
        }
        pd.wc_path = curr_wc_path.to_string();

        let split_curr_wc_path: Vec<&str> = curr_wc_path.split('/').collect();

        if !bare_mount && path_parts.len() < split_curr_wc_path.len() {
            continue;
        }

        if !bare_mount && !pd.is_prefix && split_curr_wc_path.len() != path_parts.len() {
            continue;
        }

        let mut skip = false;
        let mut segments = Vec::with_capacity(split_curr_wc_path.len());

        for (i, acl_part) in split_curr_wc_path.iter().enumerate() {
            match *acl_part {
                "+" => {
                    if !bare_mount && path_parts[i].is_empty() {
                        skip = true;
                        break;
                    }
                    pd.wildcards += 1;
                    segments.push(path_parts[i]);
                }
                _ if *acl_part == path_parts[i] => {
                    segments.push(path_parts[i]);
                }
                _ if pd.is_prefix && i == split_curr_wc_path.len() - 1 && path_parts[i].starts_with(acl_part) => {
                    segments.extend_from_slice(&path_parts[i..]);
                }
                _ if !bare_mount => {
                    skip = true;
                    break;
                }
                _ => {}
            }

            if bare_mount && i == path_parts.len() - 2 {
                let joined_path = segments.join("/") + "/";
                if joined_path.starts_with(path)
                    && permissions.capabilities_bitmap & Capability::Deny.to_bits() == 0
                    && permissions.capabilities_bitmap > 0
                {
                    return Some(permissions.clone());
                }
                skip = true;
                break;
            }
        }

        if !skip {
            pd.perms = Some(permissions.clone());
            wc_path_descrs.push(pd);
        }
    }

    if bare_mount || wc_path_descrs.is_empty() {
        return None;
    }

    wc_path_descrs.sort();

    wc_path_descrs.into_iter().next_back().and_then(|pd| pd.perms)
}

pub fn capabilities(acl: &ACL, path: &str) -> Vec<String> {
    let mut req = Request::new(path);
    req.operation = Operation::List;

    let deny_response: Vec<String> = vec![Capability::Deny.to_string()];
    let res = match allow_operation(acl, &req, true) {
        Ok(result) => result,
        Err(_) => return deny_response.clone(),
    };

    if res.is_root {
        return vec![Capability::Root.to_string()];
    }

    let capabilities = res.capabilities_bitmap;

    if capabilities & Capability::Deny.to_bits() > 0 {
        return deny_response.clone();
    }

    let path_capabilities = to_granting_capabilities(capabilities);

    if path_capabilities.is_empty() {
        return deny_response.clone();
    }

    path_capabilities
}

pub fn has_mount_access(acl: &ACL, path: &str) -> bool {
    let capabilities = capabilities(acl, path);
    if !capabilities.contains(&Capability::Deny.to_string()) {
        return true;
    }

    let mut acl_cap_given = check_path_capability(&acl.exact_rules, path);
    if !acl_cap_given {
        acl_cap_given = check_path_capability(&acl.prefix_rules, path);
    }

    if !acl_cap_given && get_none_exact_paths_permissions(acl, path, true).is_some() {
        return true;
    }

    acl_cap_given
}

pub fn scope_gated_non_contributors(acl: &ACL, req: &Request) -> Vec<String> {
    let path = ensure_no_leading_slash(&req.path);
    acl.scoped_rules
        .iter()
        .filter(|rule| scoped_rule_matches(rule, &path) && !scope_passes(rule, req))
        .map(|rule| {
            let shape = if rule.is_prefix { "*" } else { "" };
            format!("{}{} (scopes = [{}])", rule.path, shape, rule.permissions.scopes.join(", "))
        })
        .collect()
}

fn grouped_rule_matches(rule: &GroupGatedRule, path: &str) -> bool {
    if rule.has_segment_wildcards {
        segment_wildcard_matches(&rule.path, rule.is_prefix, path)
    } else if rule.is_prefix {
        path.starts_with(&rule.path)
    } else {
        rule.path == path
    }
}

pub fn segment_wildcard_matches(rule_path: &str, is_prefix: bool, req_path: &str) -> bool {
    let rule_parts: Vec<&str> = rule_path.split('/').collect();
    let req_parts: Vec<&str> = req_path.split('/').collect();

    if !is_prefix && rule_parts.len() != req_parts.len() {
        return false;
    }
    if is_prefix && req_parts.len() < rule_parts.len() {
        return false;
    }

    for (i, rp) in rule_parts.iter().enumerate() {
        if *rp == "+" {
            if req_parts[i].is_empty() {
                return false;
            }
            continue;
        }
        if is_prefix && i == rule_parts.len() - 1 {
            if !req_parts[i].starts_with(rp) {
                return false;
            }
        } else if *rp != req_parts[i] {
            return false;
        }
    }
    true
}

fn matches_ungated_list(acl: &ACL, path: &str) -> bool {
    let list_bit = Capability::List.to_bits();
    if let Some(p) = acl.exact_rules.get(path) {
        if p.capabilities_bitmap & list_bit != 0 {
            return true;
        }
    }
    if let Some(p) = acl.exact_rules.get(path.trim_end_matches('/')) {
        if p.capabilities_bitmap & list_bit != 0 {
            return true;
        }
    }
    if let Some(p) = get_none_exact_paths_permissions(acl, path, false) {
        if p.capabilities_bitmap & list_bit != 0 {
            return true;
        }
    }
    false
}

fn scoped_rule_matches(rule: &ScopedRule, path: &str) -> bool {
    if rule.has_segment_wildcards {
        segment_wildcard_matches(&rule.path, rule.is_prefix, path)
    } else if rule.is_prefix {
        path.starts_with(&rule.path)
    } else {
        rule.path == path
    }
}

fn scope_passes(rule: &ScopedRule, req: &Request) -> bool {
    let caller_id = match req.auth.as_ref().and_then(|a| a.metadata.get("entity_id")) {
        Some(id) if !id.is_empty() => id.as_str(),
        _ => return false,
    };
    for s in rule.permissions.scopes.iter() {
        match s.as_str() {
            "owner" => {
                if !req.asset_owner.is_empty() && req.asset_owner == caller_id {
                    return true;
                }
                if req.asset_owner.is_empty() && matches!(req.operation, Operation::Write) {
                    return true;
                }
            }
            "shared" => {
                if req.target_shared_caps.is_empty() {
                    continue;
                }
                let required =
                    req.share_capability_override.as_deref().or_else(|| operation_share_capability(req.operation));
                if let Some(cap) = required {
                    if req.target_shared_caps.iter().any(|c| c == cap) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn operation_share_capability(op: Operation) -> Option<&'static str> {
    match op {
        Operation::Read => Some("read"),
        Operation::List => Some("list"),
        Operation::Write => Some("update"),
        Operation::Delete => Some("delete"),
        _ => None,
    }
}

fn rule_gate_passes(rule: &GroupGatedRule, req: &Request) -> bool {
    if rule.permissions.groups.is_empty() {
        return true;
    }
    if req.asset_groups.is_empty() {
        return false;
    }
    for g in rule.permissions.groups.iter() {
        let gl = g.trim().to_lowercase();
        if req.asset_groups.iter().any(|x| x.trim().to_lowercase() == gl) {
            return true;
        }
    }
    false
}

fn check_path_capability(rules: &Trie<String, Permissions>, path: &str) -> bool {
    !path.is_empty()
        && rules
            .iter()
            .filter(|(p, perms)| p.starts_with(path) && perms.capabilities_bitmap & Capability::Deny.to_bits() == 0)
            .any(|(_key, perms)| {
                perms.capabilities_bitmap
                    & (Capability::Create.to_bits()
                        | Capability::Delete.to_bits()
                        | Capability::List.to_bits()
                        | Capability::Read.to_bits()
                        | Capability::Sudo.to_bits()
                        | Capability::Update.to_bits()
                        | Capability::Patch.to_bits())
                    > 0
            })
}

pub fn check(this: &Permissions, req: &Request, check_only: bool) -> Result<ACLResults, RvError> {
    let mut ret = ACLResults::default();
    let _path = ensure_no_leading_slash(&req.path);

    ret.root_privs = (this.capabilities_bitmap & Capability::Sudo.to_bits()) != 0;

    if check_only {
        ret.capabilities_bitmap = this.capabilities_bitmap;
        return Ok(ret);
    }

    let cap = match req.operation {
        Operation::Read => Capability::Read,
        Operation::List => Capability::List,
        Operation::Write => Capability::Update,
        Operation::Delete => Capability::Delete,
        Operation::Renew | Operation::Revoke | Operation::Rollback => Capability::Update,
        _ => return Ok(ret),
    };

    if this.capabilities_bitmap & cap.to_bits() == 0
        && (req.operation != Operation::Write || this.capabilities_bitmap & Capability::Create.to_bits() == 0)
    {
        return Ok(ret);
    }

    if let Some(value) = this.granting_policies_map.get(&cap.to_bits()) {
        ret.granting_policies.clone_from(&value);
    }

    let zero_ttl = Duration::from_secs(0);

    if this.min_wrapping_ttl != zero_ttl
        && this.max_wrapping_ttl != zero_ttl
        && this.max_wrapping_ttl < this.min_wrapping_ttl
    {
        return Ok(ret);
    }

    match req.operation {
        Operation::Read | Operation::Write => {
            for parameter in this.required_parameters.iter() {
                let key = parameter.to_lowercase();
                if let Some(data) = &req.data {
                    if data.get(key.as_str()).is_some() {
                        continue;
                    }
                }
                if let Some(body) = &req.body {
                    if body.get(key.as_str()).is_some() {
                        continue;
                    }
                }

                return Ok(ret);
            }

            if (req.data.is_none() || req.data.as_ref().unwrap().is_empty())
                && (req.body.is_none() || req.body.as_ref().unwrap().is_empty())
            {
                ret.capabilities_bitmap = this.capabilities_bitmap;
                ret.allowed = true;
                return Ok(ret);
            }

            if this.denied_parameters.contains_key("*") {
                return Ok(ret);
            }

            for (param_key, param_value) in req.data_iter() {
                if let Some(denied_parameters) = this.denied_parameters.get(param_key.to_lowercase().as_str()) {
                    if denied_parameters.glob_contains(param_value) {
                        return Ok(ret);
                    }
                }
            }

            let allowed_all = this.allowed_parameters.contains_key("*");

            if this.allowed_parameters.is_empty() || (allowed_all && this.allowed_parameters.len() == 1) {
                ret.capabilities_bitmap = this.capabilities_bitmap;
                ret.allowed = true;
                return Ok(ret);
            }

            for (param_key, param_value) in req.data_iter() {
                if let Some(allowed_parameters) = this.allowed_parameters.get(param_key.to_lowercase().as_str()) {
                    if !allowed_parameters.glob_contains(param_value) {
                        return Ok(ret);
                    }
                } else if !allowed_all {
                    return Ok(ret);
                }
            }
        }
        _ => {}
    }

    ret.capabilities_bitmap = this.capabilities_bitmap;
    ret.allowed = true;

    Ok(ret)
}

pub fn merge(this: &mut Permissions, other: &Permissions) -> Result<(), RvError> {
    let deny = Capability::Deny.to_bits();
    if this.capabilities_bitmap & deny != 0 {
        return Ok(());
    }
    if other.capabilities_bitmap & deny != 0 {
        this.capabilities_bitmap = deny;
        this.allowed_parameters.clear();
        this.denied_parameters.clear();
        return Ok(());
    }

    this.capabilities_bitmap |= other.capabilities_bitmap;

    let zero_ttl = Duration::from_secs(0);

    if other.max_wrapping_ttl > zero_ttl
        && (this.max_wrapping_ttl == zero_ttl || this.max_wrapping_ttl < other.max_wrapping_ttl)
    {
        this.max_wrapping_ttl = other.max_wrapping_ttl;
    }

    if other.min_wrapping_ttl > zero_ttl
        && (this.min_wrapping_ttl == zero_ttl || this.min_wrapping_ttl < other.min_wrapping_ttl)
    {
        this.min_wrapping_ttl = other.min_wrapping_ttl;
    }

    if !other.allowed_parameters.is_empty() {
        if this.allowed_parameters.is_empty() {
            this.allowed_parameters.clone_from(&other.allowed_parameters);
        } else {
            for (key, value) in other.allowed_parameters.iter() {
                if let Some(dst_vec) = this.allowed_parameters.get_mut(key) {
                    if value.is_empty() {
                        dst_vec.clear();
                    } else if !dst_vec.is_empty() {
                        dst_vec.extend(value.iter().cloned());
                    }
                } else {
                    this.allowed_parameters.insert(key.clone(), value.clone());
                }
            }
        }
    }

    if !other.denied_parameters.is_empty() {
        if this.denied_parameters.is_empty() {
            this.denied_parameters.clone_from(&other.denied_parameters);
        } else {
            for (key, value) in other.denied_parameters.iter() {
                if let Some(dst_vec) = this.denied_parameters.get_mut(key) {
                    if value.is_empty() {
                        dst_vec.clear();
                    } else if !dst_vec.is_empty() {
                        dst_vec.extend(value.iter().cloned());
                    }
                } else {
                    this.denied_parameters.insert(key.clone(), value.clone());
                }
            }
        }
    }

    if !other.required_parameters.is_empty() {
        for param in other.required_parameters.iter() {
            if !this.required_parameters.contains(param) {
                this.required_parameters.push(param.clone());
            }
        }
    }

    Ok(())
}
