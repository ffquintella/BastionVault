//! The shares, asset-group membership and attached files of a transferred
//! item (T494, Task 4b). Each is re-created in the destination through its
//! ordinary route, as the caller, or reported as a warning. Never creates a
//! group, never moves a file blob, never widens a share.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Map, Value};

use super::{
    as_caller, call, held, namespace_label, split, status_of, text, warning, IdentityStores, Kind, Place, Plan, Right,
    TransferOp, TransferWarning, CODE_ALL_SHARES_DROPPED, CODE_FILES_NOT_TRANSFERRED, CODE_GROUP_MEMBERSHIP_DROPPED,
    CODE_GROUP_MEMBERSHIP_UNREADABLE, CODE_SHARES_UNREADABLE, CODE_SHARE_NOT_WRITTEN,
};
use crate::{
    bv_error_string,
    errors::RvError,
    kernel_api::VaultCtx,
    logical::{Operation, Request},
    modules::{
        identity::{SecretShare, SHARE_HISTORY_OP_CTX},
        resource_group::REDACTED_MEMBER,
        system::transfer::shares::{self as planner, plan_shares, SharePlan, CODE_CANNOT_GRANT},
    },
};

/// The files engine's mount, the one the GUI and the rename flow use.
const FILES_MOUNT: &str = "files/";

/// What [`carry`] re-created: the shares written (on a dry run, the shares
/// that would be) and one warning per part left behind.
pub(super) struct Carried {
    pub shares: usize,
    pub warnings: Vec<TransferWarning>,
}

/// A read that may legitimately find nothing, and why.
enum Fetched {
    Data(Map<String, Value>),
    /// Nothing there (a 404 or an empty answer).
    Absent,
    /// The caller may not read it (the ACL, or the handler's own 403).
    Denied,
    /// No mount serves the path in that namespace.
    NoEngine,
}

#[maybe_async::maybe_async]
async fn fetch(
    core: &dyn VaultCtx,
    caller: &Request,
    ns: &str,
    operation: Operation,
    path: String,
) -> Result<Fetched, RvError> {
    match call(core, caller, ns, operation, path, None).await {
        Ok(resp) => Ok(resp.and_then(|r| r.data).map_or(Fetched::Absent, Fetched::Data)),
        Err(RvError::ErrPermissionDenied | RvError::ErrResponseStatus(403, _)) => Ok(Fetched::Denied),
        Err(RvError::ErrResponseStatus(404, _)) => Ok(Fetched::Absent),
        Err(RvError::ErrRouterMountNotFound) => Ok(Fetched::NoEngine),
        Err(e) => Err(e),
    }
}

/// A route's refusal of one write (a 4xx, or a validation message the handler
/// raised as a plain string, which maps to 500), as opposed to a storage or
/// server fault, which fails the transfer instead.
// Decision (4b review): a handler's `ErrString` is a refusal, not a fault.
fn is_refusal(e: &RvError) -> bool {
    matches!(e, RvError::ErrString(_)) || status_of(e) < 500
}

/// A failed write for a warning: a refusal (4xx) with the route's own reason,
/// a server fault (5xx) by its status only, since its text is not the
/// caller's to read and may carry storage detail.
fn failure_reason(e: RvError) -> String {
    match split(e) {
        (status, _) if status >= 500 => format!("status {status}"),
        (status, detail) => format!("status {status}: {detail}"),
    }
}

fn strings(data: &Map<String, Value>, field: &str) -> Vec<String> {
    let list = data.get(field).and_then(Value::as_array);
    list.map(|all| all.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default()
}

/// How the share API and asset groups name the item at `place`: a resource
/// name, or a KV secret's `<mount><path>`.
fn relation_key(kind: Kind, place: &Place) -> String {
    match kind {
        Kind::Resource => place.path.clone(),
        Kind::KvSecret => format!("{}{}", place.mount, place.path),
    }
}

/// `identity/sharing/by-target/<kind>/<b64(key)>` for the item at `place`.
fn sharing_path(kind: Kind, place: &Place) -> String {
    let target = URL_SAFE_NO_PAD.encode(relation_key(kind, place));
    format!("identity/sharing/by-target/{}/{target}", kind.share_kind())
}

/// Re-create the source's shares and asset-group membership on the item at
/// `dest`. Runs after the import (on a dry run, after the probes) and before a
/// move deletes the source. A dry run only reads and probes.
#[maybe_async::maybe_async]
pub(super) async fn carry(
    core: &dyn VaultCtx,
    caller: &Request,
    stores: Option<&IdentityStores>,
    plan: &Plan,
    dest: &Place,
) -> Result<Carried, RvError> {
    let (shares, mut warnings) = carry_shares(core, caller, stores, plan, dest).await?;
    warnings.extend(carry_groups(core, caller, plan, dest).await?);
    Ok(Carried { shares, warnings })
}

/// The source's shares through the share API's own listing, which only the
/// item's owner or an administrator may read; `None` when the caller may not.
#[maybe_async::maybe_async]
async fn source_shares(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
) -> Result<Option<Vec<SecretShare>>, RvError> {
    let src = &plan.source;
    let data = match fetch(core, caller, &src.ns, Operation::List, sharing_path(plan.kind, src)).await? {
        Fetched::Data(data) => data,
        Fetched::Absent | Fetched::NoEngine => return Ok(Some(Vec::new())),
        Fetched::Denied => return Ok(None),
    };
    let entries = data.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    let shares = entries.into_iter().map(serde_json::from_value::<SecretShare>).collect::<Result<Vec<_>, _>>();
    Ok(Some(shares.map_err(|_| bv_error_string!(format!("the shares of {} could not be read", src.display())))?))
}

/// The share-API route that grants `grantee` a share on the item at `dest`.
fn grant_path(kind: Kind, dest: &Place, grantee: &str) -> String {
    format!("{}/{}", sharing_path(kind, dest), grantee.trim())
}

/// The planner's verdict, with `caller_may_grant` decided per share by the
/// same ACL check the share API's route makes (the route path names the
/// grantee). The owner-or-administrator check is the write's own.
#[maybe_async::maybe_async]
async fn plan_for(
    core: &dyn VaultCtx,
    caller: &Request,
    stores: Option<&IdentityStores>,
    kind: Kind,
    dest: &Place,
    source: Vec<SecretShare>,
) -> Result<SharePlan, RvError> {
    let checks: Vec<(String, Right)> =
        source.iter().map(|s| (grant_path(kind, dest, &s.grantee_entity_id), Right::Write)).collect();
    let verdicts = held(core, caller, &dest.ns, &checks).await?;
    let (grantable, refused): (Vec<_>, Vec<_>) = source.into_iter().zip(verdicts).partition(|(_, may)| *may);
    let stores =
        stores.ok_or_else(|| bv_error_string!("the identity stores are unavailable, so shares cannot be planned"))?;
    let (entities, groups) = (stores.entities.as_ref(), stores.groups.as_ref());
    let grantable = grantable.into_iter().map(|(s, _)| s).collect();
    let mut plan = plan_shares(grantable, &dest.ns, true, entities, groups).await?;
    let refused = plan_shares(refused.into_iter().map(|(s, _)| s).collect(), &dest.ns, false, entities, groups).await?;
    plan.dropped.extend(refused.dropped);
    Ok(plan)
}

/// Write one planned share through the share API as the caller, so the API's
/// owner check, normalisation and grantee re-pointing all apply, recorded as
/// `op`. A refusal is a warning; a server error is returned.
#[maybe_async::maybe_async]
async fn write_share(
    core: &dyn VaultCtx,
    caller: &Request,
    op: TransferOp,
    kind: Kind,
    dest: &Place,
    share: &SecretShare,
) -> Result<Option<TransferWarning>, RvError> {
    let body = json!({
        "grantee_kind": share.grantee_kind,
        "capabilities": share.capabilities,
        "expires_at": share.expires_at,
    });
    let path = grant_path(kind, dest, &share.grantee_entity_id);
    let mut req = as_caller(caller, &dest.ns, Operation::Write, path, body.as_object().cloned());
    req.ctx.set(SHARE_HISTORY_OP_CTX, Arc::new(op.as_str().to_string()));
    let e = match core.handle_request(&mut req).await {
        Ok(_) => return Ok(None),
        Err(e) => e,
    };
    // The route's own words: its 403 may come from the owner check, the
    // token binding or the sql gate. Share-route messages carry no value.
    if status_of(&e) == 403 {
        let reason = format!("the destination refused the grant: {}", split(e).1);
        return Ok(Some(planner::warning(CODE_CANNOT_GRANT, share, &reason)));
    }
    if !is_refusal(&e) {
        return Err(e);
    }
    let reason = format!("the destination refused it: {}", split(e).1);
    Ok(Some(planner::warning(CODE_SHARE_NOT_WRITTEN, share, &reason)))
}

/// Plan the source's shares against the destination and, unless this is a
/// dry run, write the kept ones; every share left behind is a warning.
#[maybe_async::maybe_async]
async fn carry_shares(
    core: &dyn VaultCtx,
    caller: &Request,
    stores: Option<&IdentityStores>,
    plan: &Plan,
    dest: &Place,
) -> Result<(usize, Vec<TransferWarning>), RvError> {
    let src = &plan.source;
    let Some(source) = source_shares(core, caller, plan).await? else {
        let message = format!(
            "the caller may not list the shares of {} (only its owner or an administrator may), so none was carried",
            src.display()
        );
        return Ok((0, vec![warning(CODE_SHARES_UNREADABLE, src.display(), message)]));
    };
    if source.is_empty() {
        return Ok((0, Vec::new()));
    }
    let total = source.len();
    let planned = plan_for(core, caller, stores, plan.kind, dest, source).await?;
    let mut warnings = planned.dropped;
    let written = match plan.dry_run {
        true => planned.keep.len(),
        false => {
            let mut written = 0;
            for (index, share) in planned.keep.iter().enumerate() {
                match write_share(core, caller, plan.op, plan.kind, dest, share).await {
                    Ok(None) => written += 1,
                    Ok(Some(refused)) => warnings.push(refused),
                    // Counts only: the shares already written stay written.
                    Err(e) => {
                        let (status, detail) = split(e);
                        let planned_count = planned.keep.len();
                        let message = format!(
                            "{written} of {planned_count} planned shares were written before share {} failed: {detail}",
                            index + 1
                        );
                        return Err(RvError::ErrResponseStatus(status, message));
                    }
                }
            }
            written
        }
    };
    if written == 0 {
        let message =
            format!("none of the {total} shares of {} was re-created; each has its own warning", src.display());
        warnings.push(warning(CODE_ALL_SHARES_DROPPED, src.display(), message));
    }
    Ok((written, warnings))
}

/// The asset groups of the source's own namespace that list the item;
/// `None` when the caller may not read that.
#[maybe_async::maybe_async]
async fn source_groups(core: &dyn VaultCtx, caller: &Request, plan: &Plan) -> Result<Option<Vec<String>>, RvError> {
    let src = &plan.source;
    let path = match plan.kind {
        Kind::Resource => format!("resource-group/by-resource/{}", src.path),
        Kind::KvSecret => format!("resource-group/by-secret/{}", URL_SAFE_NO_PAD.encode(relation_key(plan.kind, src))),
    };
    match fetch(core, caller, &src.ns, Operation::Read, path).await? {
        Fetched::Data(data) => Ok(Some(strings(&data, "groups"))),
        Fetched::Absent | Fetched::NoEngine => Ok(Some(Vec::new())),
        Fetched::Denied => Ok(None),
    }
}

#[maybe_async::maybe_async]
async fn carry_groups(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    dest: &Place,
) -> Result<Vec<TransferWarning>, RvError> {
    let src = &plan.source;
    let Some(groups) = source_groups(core, caller, plan).await? else {
        let message =
            format!("the caller may not read which asset groups list {}, so no membership was carried", src.display());
        return Ok(vec![warning(CODE_GROUP_MEMBERSHIP_UNREADABLE, src.display(), message)]);
    };
    let mut warnings = Vec::new();
    for group in groups {
        warnings.extend(carry_group(core, caller, plan, dest, &group).await?);
    }
    Ok(warnings)
}

/// Add the item at `dest` to the destination's own asset group `name`, through
/// the group route as the caller. Dropped with a warning when there is no such
/// group, it is only inherited, the caller cannot see all of it, or may not
/// modify it: a group is never created and no other member is changed.
#[maybe_async::maybe_async]
async fn carry_group(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    dest: &Place,
    name: &str,
) -> Result<Option<TransferWarning>, RvError> {
    let dropped = |reason: &str| {
        let message = format!("membership of asset group {name} not re-created: {reason}");
        Some(warning(CODE_GROUP_MEMBERSHIP_DROPPED, name, message))
    };
    let path = format!("resource-group/groups/{name}");
    let group = match fetch(core, caller, &dest.ns, Operation::Read, path.clone()).await? {
        Fetched::Data(group) => group,
        Fetched::Absent => return Ok(dropped("no group of that name exists in the destination, and none is created")),
        Fetched::Denied => return Ok(dropped("the caller may not read that group in the destination")),
        Fetched::NoEngine => return Ok(dropped("the destination namespace has no asset-group engine")),
    };
    if group.get("inherited").and_then(Value::as_bool).unwrap_or(false) {
        let reason = "the destination only inherits it from an ancestor namespace, where it is read-only";
        return Ok(dropped(reason));
    }
    let field = match plan.kind {
        Kind::Resource => "members",
        Kind::KvSecret => "secrets",
    };
    let mut list = strings(&group, field);
    if list.iter().any(|m| m == REDACTED_MEMBER) {
        return Ok(dropped("the caller cannot see every member, so the list cannot be rewritten without losing one"));
    }
    let may_not_modify = "the caller may not modify that group in the destination";
    if plan.dry_run {
        let may = held(core, caller, &dest.ns, &[(path, Right::Write)]).await?;
        return Ok(if may.first() == Some(&true) { None } else { dropped(may_not_modify) });
    }
    list.push(relation_key(plan.kind, dest));
    // Only the rewritten list is sent: the route leaves every other field.
    let body = Map::from_iter([(field.to_string(), json!(list))]);
    let e = match call(core, caller, &dest.ns, Operation::Write, path, Some(body)).await {
        Ok(_) => return Ok(None),
        Err(e) => e,
    };
    if status_of(&e) == 403 {
        return Ok(dropped(may_not_modify));
    }
    if !is_refusal(&e) {
        return Err(e);
    }
    Ok(dropped(&format!("the destination refused the change: {}", split(e).1)))
}

/// The ids of the files attached to the source resource, and how many file
/// records the caller may not read; `None` when it may not list files.
#[maybe_async::maybe_async]
async fn attached_files(core: &dyn VaultCtx, caller: &Request, src: &Place) -> Result<Option<(usize, usize)>, RvError> {
    let ids = match fetch(core, caller, &src.ns, Operation::List, format!("{FILES_MOUNT}files/")).await? {
        Fetched::Data(data) => strings(&data, "keys"),
        Fetched::Absent | Fetched::NoEngine => return Ok(Some((0, 0))),
        Fetched::Denied => return Ok(None),
    };
    let (mut attached, mut unchecked) = (0, 0);
    for id in ids {
        match fetch(core, caller, &src.ns, Operation::Read, format!("{FILES_MOUNT}files/{id}")).await? {
            Fetched::Data(meta) if text(&meta, "resource").eq_ignore_ascii_case(&src.path) => attached += 1,
            Fetched::Denied => unchecked += 1,
            Fetched::Data(_) | Fetched::Absent | Fetched::NoEngine => {}
        }
    }
    Ok(Some((attached, unchecked)))
}

/// Files attached to a source resource. Each namespace has its own files
/// engine, so they are re-pointed only by a move within one namespace (after
/// the source is deleted); otherwise they stay and a warning says so. Never
/// fails: a fault becomes a warning, since a move may already be complete.
#[maybe_async::maybe_async]
pub(super) async fn carry_files(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    written: &Place,
) -> Vec<TransferWarning> {
    let src = &plan.source;
    let same_ns = src.ns == written.ns;
    // Files name a resource, not a mount: in one namespace they still match.
    if plan.kind != Kind::Resource || (same_ns && src.path.eq_ignore_ascii_case(&written.path)) {
        return Vec::new();
    }
    let not_transferred = |message: String| vec![warning(CODE_FILES_NOT_TRANSFERRED, src.path.clone(), message)];
    // The status only, in the warning and the server log: a fault's text is
    // not the caller's to read, and may carry storage detail.
    let fault = |what: &str, e: &RvError| {
        let status = status_of(e);
        log::warn!(
            target: "security",
            "namespace-transfer: checking {what} of {} failed (status {status}); reported as a warning",
            src.display()
        );
        let message = format!("{what} of {} could not be checked: status {status}", src.display());
        not_transferred(format!("{message}; none was transferred"))
    };
    let found = match attached_files(core, caller, src).await {
        Ok(found) => found,
        Err(e) => return fault("the attached files", &e),
    };
    let Some((attached, unchecked)) = found else {
        let message = format!(
            "the caller may not list files in {}, so files attached to {} were not checked or transferred",
            namespace_label(&src.ns),
            src.display()
        );
        return not_transferred(message);
    };
    if attached == 0 && unchecked == 0 {
        return Vec::new();
    }
    if same_ns && plan.op == TransferOp::Move {
        let repoint = format!("{FILES_MOUNT}files/repoint-resource");
        if plan.dry_run {
            let may = match held(core, caller, &src.ns, &[(repoint, Right::Write)]).await {
                Ok(may) => may,
                Err(e) => return fault("the right to re-point the files", &e),
            };
            let message = format!("the caller may not re-point the files attached to {}", src.display());
            return if may.first() == Some(&true) { Vec::new() } else { not_transferred(message) };
        }
        let body = json!({ "old_resource": src.path, "new_resource": written.path }).as_object().cloned();
        return match call(core, caller, &src.ns, Operation::Write, repoint, body).await {
            Ok(_) => Vec::new(),
            Err(e) => {
                let message = format!(
                    "the move to {} is complete, but re-pointing the files attached to {} failed ({}); they stay \
                     attached to the name '{}'",
                    written.display(),
                    src.display(),
                    failure_reason(e),
                    src.path
                );
                not_transferred(message)
            }
        };
    }
    let reason = match same_ns {
        true => "a file is attached to one resource, and re-pointing it would detach it from the source",
        false => "each namespace has its own files engine, and files are not copied between them",
    };
    let mut message = format!(
        "{attached} file(s) attached to {} were not transferred: {reason}; they stay in {}'s files engine, attached \
         to the name '{}'",
        src.display(),
        namespace_label(&src.ns),
        src.path
    );
    if plan.op == TransferOp::Move {
        message.push_str(", which the move leaves naming no resource there");
    }
    // The scan cannot tell whether a record it may not read is attached.
    if unchecked > 0 {
        message.push_str(&format!("; {unchecked} file(s) in the namespace could not be checked"));
    }
    not_transferred(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(ns: &str, mount: &str, path: &str) -> Place {
        Place { ns: ns.into(), mount: mount.into(), path: path.into() }
    }

    #[test]
    fn relations_name_the_item_as_the_share_api_and_asset_groups_do() {
        let srv = place("dst", "resources/", "srv1");
        let kv = place("dst", "secret/", "team/db");
        assert_eq!(relation_key(Kind::Resource, &srv), "srv1");
        assert_eq!(relation_key(Kind::KvSecret, &kv), "secret/team/db", "a mount-relative KV path, no namespace");
        let kv_target = URL_SAFE_NO_PAD.encode("secret/team/db");
        assert_eq!(sharing_path(Kind::KvSecret, &kv), format!("identity/sharing/by-target/kv-secret/{kv_target}"));
        let srv_target = URL_SAFE_NO_PAD.encode("srv1");
        let grant = format!("identity/sharing/by-target/resource/{srv_target}/ops");
        assert_eq!(grant_path(Kind::Resource, &srv, " ops "), grant);
    }

    #[test]
    fn a_server_fault_is_reported_by_its_status_only() {
        let fault = failure_reason(RvError::ErrResponseStatus(503, "barrier: disk /var/x full".into()));
        assert_eq!(fault, "status 503");
        assert_eq!(
            failure_reason(RvError::ErrBarrierSealed),
            format!("status {}", RvError::ErrBarrierSealed.response_status())
        );
        let refusal = failure_reason(RvError::ErrResponseStatus(409, "a file is locked".into()));
        assert_eq!(refusal, "status 409: a file is locked");
    }

    #[test]
    fn only_a_server_fault_fails_a_relation_write() {
        assert!(is_refusal(&RvError::ErrResponseStatus(400, "invalid".into())));
        assert!(is_refusal(&RvError::ErrResponseStatus(409, "conflict".into())));
        assert!(is_refusal(&RvError::ErrPermissionDenied));
        assert!(is_refusal(&RvError::ErrString("share must grant at least one capability".into())));
        assert!(!is_refusal(&RvError::ErrBarrierSealed));
        assert!(!is_refusal(&RvError::ErrResponseStatus(500, "storage".into())));
    }
}
