//! Qualified segment-wildcard rules with a trailing `*` (T121, finding F8):
//! a `groups`-gated `kv/+/*` used to match no real path, so neither its grant
//! nor its `deny` applied. These drive `pre_route`, the post-route LIST
//! filter, `readable_targets` and `may_connect_target` with the asset groups
//! resolved from storage; here, not in `bv-kernel`, for the reason
//! `kernel_policy_deny` is (see `mod.rs`).

use std::sync::Arc;

use serde_json::json;

use super::kernel_policy_deny::{can_read, may_connect, readable, user, write, write_policy};
use crate::{
    core::Core,
    test_utils::{new_unseal_test_bastion_vault, test_list_api},
};

/// A KV-v1 mount at `kv/` holding `team/alpha`, `team/beta` and `other`,
/// `kv/team/alpha` in the asset group `club`, and a userpass mount.
async fn nested_kv_with_club(core: &Arc<Core>, root: &str) {
    write(core, root, "sys/mounts/kv/", json!({ "type": "kv" })).await;
    write(core, root, "kv/team/alpha", json!({ "v": "1" })).await;
    write(core, root, "kv/team/beta", json!({ "v": "2" })).await;
    write(core, root, "kv/other", json!({ "v": "3" })).await;
    write(core, root, "resource-group/groups/club", json!({ "secrets": "kv/team/alpha" })).await;
    write(core, root, "sys/auth/pass", json!({ "type": "userpass" })).await;
}

/// The keys `token`'s LIST of `path` comes back with.
async fn list_keys(core: &Arc<Core>, token: &str, path: &str) -> Vec<String> {
    let resp = test_list_api(core.as_ref(), token, path, true).await.unwrap().unwrap();
    let data = resp.data.unwrap();
    data["keys"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
}

/// A gated `kv/+/*` grant applies to the targets in its group — read through
/// `pre_route`, `readable_targets`, and a LIST narrowed to the group — and to
/// nothing else. Before T121 every one of these was refused.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_gated_segment_wildcard_glob_grants_its_group() {
    let (_bvault, core, root) =
        new_unseal_test_bastion_vault("test_gated_segment_wildcard_glob_grants_its_group").await;
    nested_kv_with_club(&core, &root).await;
    write_policy(
        &core,
        &root,
        "p-gated-glob",
        "path \"kv/+/*\" {\n  capabilities = [\"read\", \"list\"]\n  groups = [\"club\"]\n}\n",
    )
    .await;

    let token = user(&core, &root, "alice", "p-gated-glob").await;
    assert!(can_read(&core, &token, "kv/team/alpha").await, "the gated `+…*` grant did not apply in pre_route");
    assert!(!can_read(&core, &token, "kv/team/beta").await, "the gated grant applied outside its group");
    assert!(!can_read(&core, &token, "kv/other").await, "the gated grant applied off its shape");
    assert_eq!(
        readable(&core, &["p-gated-glob"], None, &["kv/team/alpha", "kv/team/beta", "kv/other"]).await,
        vec![true, false, false],
        "readable_targets must apply the gated `+…*` grant to its group only"
    );

    let keys = list_keys(&core, &token, "kv/team/").await;
    assert_eq!(keys, vec!["alpha".to_string()], "the LIST must be granted and narrowed to `club`");
}

/// A gated `kv/+/*` deny now applies: it revokes an ungated grant, `sudo`
/// included, for the targets in its group, through `pre_route`,
/// `readable_targets` and `may_connect_target`. Before T121 it matched
/// nothing and the ungated grant stood.
#[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
async fn test_gated_segment_wildcard_glob_deny_revokes() {
    let (_bvault, core, root) = new_unseal_test_bastion_vault("test_gated_segment_wildcard_glob_deny_revokes").await;
    nested_kv_with_club(&core, &root).await;
    write_policy(&core, &root, "p-read", "path \"kv/*\" {\n  capabilities = [\"read\", \"sudo\"]\n}\n").await;
    write_policy(
        &core,
        &root,
        "p-gated-glob-deny",
        "path \"kv/+/*\" {\n  capabilities = [\"deny\"]\n  groups = [\"club\"]\n}\n",
    )
    .await;

    let control = user(&core, &root, "control", "p-read").await;
    assert!(can_read(&core, &control, "kv/team/alpha").await, "control: the ungated grant must be live");

    let denied = user(&core, &root, "denied", "p-read,p-gated-glob-deny").await;
    assert!(!can_read(&core, &denied, "kv/team/alpha").await, "the gated `+…*` deny did not apply in pre_route");
    assert!(can_read(&core, &denied, "kv/team/beta").await, "the gated deny must not apply outside its group");
    assert!(can_read(&core, &denied, "kv/other").await, "the gated deny must not apply off its shape");
    assert_eq!(
        readable(&core, &["p-read", "p-gated-glob-deny"], None, &["kv/team/alpha", "kv/team/beta"]).await,
        vec![false, true],
        "readable_targets must honour the gated `+…*` deny and only it"
    );
    assert!(
        !may_connect(&core, &["p-read", "p-gated-glob-deny"], None, "kv/team/alpha").await,
        "may_connect_target let an ungated read bypass the gated `+…*` deny"
    );
    assert!(
        may_connect(&core, &["p-read", "p-gated-glob-deny"], None, "kv/team/beta").await,
        "may_connect_target applied the gated deny outside its group"
    );
}
