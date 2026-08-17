//! Target resolution + recipient contact lookup.
//!
//! Targeting a notification means turning a [`NotificationTarget`] into a
//! concrete set of entity ids (for the always-on in-app inbox), and —
//! for external channels — decorating each with a contact address.
//!
//! Contact addresses live on the userpass user record (`email` / `phone`
//! fields, informational-only there). Usernames are global across
//! userpass mounts at the identity-alias layer (aliases are keyed by the
//! fixed mount tag `"userpass/"`, see `path_login::resolve_entity_id`),
//! so we read `user/<name>` from every userpass auth mount and take the
//! first record that carries the address we need. Recipients with no
//! address are still returned — the in-app channel needs only the entity
//! id, and address-based channels skip them and report them as failed.


use serde_json::Value;

use crate::kernel_api::{identity::GroupKind, VaultCtx};
use crate::{
    errors::RvError,
    storage::{barrier_view::BarrierView, Storage},
};

use super::types::{NotificationTarget, Recipient};

/// The fixed alias mount tag userpass logins register under.
const USERPASS_ALIAS_MOUNT: &str = "userpass/";
/// The auth backend `logical_type` for userpass mounts.
const USERPASS_LOGICAL_TYPE: &str = "userpass";

/// Resolve a target into the set of entity ids that should receive the
/// notification within `ns_path`. Unresolvable members are skipped
/// rather than failing the whole send.
pub async fn resolve_target_entities(
    core: &dyn VaultCtx,
    target: &NotificationTarget,
    ns_path: &str,
) -> Result<Vec<String>, RvError> {
    let Some(identity) = core.identity() else {
        // No identity module. A target that is already an entity id still
        // resolves — it needs no lookup — and every other kind is a name with
        // nothing to resolve it against.
        return Ok(match target {
            NotificationTarget::User { entity_id } if !entity_id.trim().is_empty() => {
                vec![entity_id.clone()]
            }
            _ => vec![],
        });
    };

    match target {
        NotificationTarget::User { entity_id } => {
            if entity_id.trim().is_empty() {
                return Ok(vec![]);
            }
            Ok(vec![entity_id.clone()])
        }
        NotificationTarget::Username { name } => Ok(identity
            .entity_id_for_alias(USERPASS_ALIAS_MOUNT, &name.to_lowercase(), ns_path)
            .await?
            .into_iter()
            .collect()),
        NotificationTarget::Group { group_kind, name } => {
            let gkind = GroupKind::parse(group_kind)?;
            let mut seen = std::collections::BTreeSet::new();
            for member in identity.group_members(gkind, name, ns_path).await? {
                if let Some(id) = identity
                    .entity_id_for_alias(USERPASS_ALIAS_MOUNT, &member.to_lowercase(), ns_path)
                    .await?
                {
                    seen.insert(id);
                }
            }
            Ok(seen.into_iter().collect())
        }
        NotificationTarget::AllUsers => identity.list_entity_ids(ns_path).await,
    }
}

/// Decorate a set of entity ids with display names and contact addresses
/// for channel delivery. Best-effort: a missing entity or address leaves
/// the corresponding field empty.
pub async fn resolve_recipients(
    core: &dyn VaultCtx,
    entity_ids: &[String],
    _ns_path: &str,
) -> Result<Vec<Recipient>, RvError> {
    let identity = core.identity();

    let userpass_views = collect_userpass_views(core)?;

    let mut out = Vec::with_capacity(entity_ids.len());
    for id in entity_ids {
        let mut recipient = Recipient {
            entity_id: id.clone(),
            display_name: String::new(),
            email: String::new(),
            phone: String::new(),
        };

        if let Some(identity) = &identity {
            if let Some(entity) = identity.entity_profile(id).await? {
                recipient.display_name = entity.primary_name.clone();

                // Prefer the userpass alias name; fall back to primary.
                let username = entity.name_on_mount(USERPASS_ALIAS_MOUNT).to_lowercase();

                if !username.is_empty() {
                    let key = format!("user/{username}");
                    for view in &userpass_views {
                        let Some(se) = view.get(&key).await? else {
                            continue;
                        };
                        let Ok(v) = serde_json::from_slice::<Value>(&se.value) else {
                            continue;
                        };
                        if recipient.email.is_empty() {
                            if let Some(e) = v.get("email").and_then(|e| e.as_str()) {
                                if !e.is_empty() {
                                    recipient.email = e.to_string();
                                }
                            }
                        }
                        if recipient.phone.is_empty() {
                            if let Some(p) = v.get("phone").and_then(|p| p.as_str()) {
                                if !p.is_empty() {
                                    recipient.phone = p.to_string();
                                }
                            }
                        }
                        if !recipient.email.is_empty() {
                            break;
                        }
                    }
                }
            }
        }

        out.push(recipient);
    }

    Ok(out)
}

/// Build a barrier view over every userpass auth mount's storage so we
/// can read `user/<name>` records for contact addresses.
fn collect_userpass_views(core: &dyn VaultCtx) -> Result<Vec<BarrierView>, RvError> {
    let mut views = Vec::new();
    let Some(auth_mounts) = core.auth_mounts() else {
        return Ok(views);
    };
    views = auth_mounts.auth_mount_views(USERPASS_LOGICAL_TYPE)?;
    Ok(views)
}
