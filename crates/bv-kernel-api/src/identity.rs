//! Identity, as an engine sees it.
//!
//! Engines need four things from the identity kernel: the entity id behind a
//! login alias, the policies a principal inherits from its groups, the admin
//! user-audit trail, and the owner/share bookkeeping that follows an object
//! when it is created or renamed.
//!
//! What they do **not** need is `EntityStore`, `GroupStore`, `OwnerStore`,
//! `ShareStore` or `UserAuditStore` — five concrete types, each holding
//! `BarrierView`s, each living in `bv-kernel`. Reaching them meant naming
//! `IdentityModule`, which is why every auth backend and half the engines had
//! `bv-kernel` in their compile unit. This trait is the whole surface they
//! actually used, expressed in owned data.
//!
//! The methods are deliberately *whole operations*, not store handles. The
//! resource rename below is the reason: it used to be twenty lines of
//! namespace-key scoping, share renaming and owner moving inlined in the
//! resource engine, which meant the engine had to know how owner records are
//! keyed. Now it asks for the outcome and the identity module owns the how.

use serde::{Deserialize, Serialize};

use bv_errors::RvError;
use bv_logical::Request;

/// Which kind of identity group a membership lookup is about.
///
/// Mirrors `modules::identity::group_store::GroupKind`, which converts to and
/// from this. Two definitions rather than a move, because the store side
/// carries `strum` derives and storage-format concerns an engine has no
/// business seeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupKind {
    /// Groups keyed by username (userpass, FIDO2, OIDC, SAML logins).
    User,
    /// Groups keyed by role name (AppRole logins).
    App,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::User => "user",
            GroupKind::App => "app",
        }
    }

    /// Parse the wire form (`"user"` / `"app"`).
    pub fn parse(s: &str) -> Result<Self, RvError> {
        match s {
            "user" => Ok(GroupKind::User),
            "app" => Ok(GroupKind::App),
            other => Err(bv_errors::bv_error_string!(&format!(
                "unknown group kind {other:?}: expected \"user\" or \"app\""
            ))),
        }
    }
}

impl std::fmt::Display for GroupKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kind of object an owner or share record points at.
///
/// Owner and share records are keyed by kind so a file and a resource of the
/// same name never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    File,
    Resource,
}

/// One entity alias: the login mount it came from and the name on that mount.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AliasRef {
    pub mount: String,
    pub name: String,
}

/// The parts of an entity an engine reads — a display name and the aliases it
/// can be addressed by. Deliberately not the stored `Entity`: engines never
/// write entities, so `created_at`, `namespace` and the storage shape stay
/// inside the identity module.
#[derive(Debug, Clone, Default)]
pub struct EntityProfile {
    pub id: String,
    pub primary_name: String,
    pub aliases: Vec<AliasRef>,
}

impl EntityProfile {
    /// Name of the alias on `mount`, falling back to the primary name.
    ///
    /// Every caller wanted this and each wrote its own `iter().find()`.
    pub fn name_on_mount(&self, mount: &str) -> String {
        self.aliases
            .iter()
            .find(|a| a.mount == mount)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| self.primary_name.clone())
    }
}

/// One admin user-audit record: who did what to which principal.
///
/// Field-for-field the stored `UserAuditEntry`; kept as a separate type so the
/// storage struct can grow a field without changing what engines may write.
/// `ts` empty means "stamp it on append".
#[derive(Debug, Clone, Default)]
pub struct UserAuditRecord {
    pub ts: String,
    /// `entity_id` of the caller, or empty for root-token operations.
    pub actor_entity_id: String,
    /// `"create" | "update" | "delete" | "password-change"`.
    pub op: String,
    /// Auth mount the target lives on: `"userpass/"` or `"approle/"`.
    pub mount: String,
    /// Target principal name.
    pub target: String,
    pub details: String,
}

/// Identity operations available to any module holding a
/// [`VaultCtx`](super::VaultCtx).
///
/// Every method is best-effort-friendly: a vault with no identity module
/// registered simply has no `identity()` service, and callers already had to
/// handle that (the previous `get_module` returned `Option`). Nothing here
/// fails a request on its own.
#[maybe_async::maybe_async]
pub trait IdentityService: Send + Sync {
    /// Entity id for an existing alias, or `None` when the alias is unknown.
    async fn entity_id_for_alias(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<Option<String>, RvError>;

    /// Entity id for a login, creating the entity on first sight.
    ///
    /// This is the login path: an auth backend calls it after a successful
    /// credential check so the issued token carries an `entity_id`.
    async fn ensure_entity_id(
        &self,
        mount: &str,
        name: &str,
        ns_path: &str,
    ) -> Result<String, RvError>;

    /// Drop the `(mount, name)` → entity lookup index for a deleted principal.
    ///
    /// The entity record itself survives: shares and owner records still point
    /// at its `entity_id`, and vaporising it would take the audit history with
    /// it. Only the alias index goes, which is what makes the principal
    /// disappear from user pickers.
    async fn forget_alias(&self, mount: &str, name: &str) -> Result<(), RvError>;

    /// Display name and aliases of an entity, or `None` if it is gone.
    async fn entity_profile(&self, entity_id: &str) -> Result<Option<EntityProfile>, RvError>;

    /// `direct` plus every policy the member inherits from its groups.
    ///
    /// Returns the union; the caller substitutes `direct` unchanged on error,
    /// which is the fail-closed direction (group membership can only add).
    async fn expand_group_policies(
        &self,
        kind: GroupKind,
        member: &str,
        direct: &[String],
        ns_path: &str,
    ) -> Result<Vec<String>, RvError>;

    /// Members of an identity group, or an empty vector when the group does
    /// not exist. Members are alias names, not entity ids.
    async fn group_members(
        &self,
        kind: GroupKind,
        name: &str,
        ns_path: &str,
    ) -> Result<Vec<String>, RvError>;

    /// Every entity id in `ns_path`.
    async fn list_entity_ids(&self, ns_path: &str) -> Result<Vec<String>, RvError>;

    /// Append to the admin user-audit trail.
    async fn record_user_audit(&self, entry: UserAuditRecord) -> Result<(), RvError>;

    /// Stamp `actor` as the owner of a newly created object, unless it already
    /// has one. Namespace scoping of the record key happens inside.
    async fn record_owner_if_absent(
        &self,
        kind: ObjectKind,
        name: &str,
        ns_path: Option<&str>,
        actor: &str,
    ) -> Result<(), RvError>;

    /// Move an object's owner and share records to a new name.
    ///
    /// Best-effort by contract: a failure here leaves the rename done and the
    /// bookkeeping stale, which is recoverable, whereas failing the rename
    /// after the data has moved is not. Implementations log and continue.
    async fn rename_object(
        &self,
        kind: ObjectKind,
        old_name: &str,
        new_name: &str,
        ns_path: Option<&str>,
        actor: &str,
    );
}

/// Best-effort caller identity for audit rows.
///
/// Order of preference:
///   1. `auth.metadata["entity_id"]` — the stable UUID
///      (`EntityStore`) for userpass/approle/FIDO2 logins.
///   2. `auth.display_name` — populated for root (`"root"`) and by
///      login handlers as a human label.
///   3. Empty string — no `auth` at all.
///
/// Without this fallback, root-token operations show up as
/// "(unknown)" in the Admin → Audit page because root has no
/// entity_id. The GUI treats a non-UUID value as a literal
/// username and renders it verbatim, so returning `"root"` here is
/// enough to surface the correct actor without schema changes.
pub fn caller_audit_actor(req: &Request) -> String {
    let Some(auth) = req.auth.as_ref() else {
        return String::new();
    };
    if let Some(id) = auth.metadata.get("entity_id") {
        if !id.is_empty() {
            return id.clone();
        }
    }
    if !auth.display_name.is_empty() {
        return auth.display_name.clone();
    }
    String::new()
}
