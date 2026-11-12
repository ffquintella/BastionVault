//! Cucumber suite for the exchange (`.bvx`) export: one scenario per scope
//! type, against a real unsealed vault with real namespaces and real file
//! blobs. Run with `make test-cucumber`.
//!
//! The suite exists because an export that is silently empty looks exactly like
//! a successful one: the operator finds out on restore. Every scenario asserts
//! on what the document *contains*, not on the call having returned `Ok`.
//!
//! `run_export` mirrors the scope/fan-out decision made by
//! `POST sys/exchange/export` (crates/bv-server/src/sys.rs) and the embedded
//! GUI command: `all_namespaces`, or `selective` with namespaces named or a
//! split requested, fans out; anything else is root-only. Keep the three in
//! step.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use base64::Engine;
use bastion_vault::{
    core::Core,
    errors::RvError,
    exchange::{
        self, ConflictPolicy, ExchangeDocument, ExporterInfo, ImportResult, ScopeKind, ScopeSelector, ScopeSpec,
    },
    logical::{Operation, Request, Response},
    test_utils::new_unseal_test_bastion_vault,
    BastionVault,
};
use cucumber::{given, then, when, World};
use serde_json::{json, Map, Value};

const PASSWORD: &str = "correct horse battery staple";

static VAULT_SEQ: AtomicU32 = AtomicU32::new(0);

#[derive(World)]
#[world(init = ExchangeWorld::new)]
struct ExchangeWorld {
    // Held so the on-disk test vault outlives the scenario.
    _bvault: Option<BastionVault>,
    core: Option<Arc<Core>>,
    token: String,
    /// `(namespace, file id)` -> the bytes that were uploaded.
    uploaded: HashMap<(String, String), Vec<u8>>,
    /// The vault a restore is applied to: a second, independent vault, so a
    /// restore can never "pass" by finding the data still sitting in the source.
    dest_bvault: Option<BastionVault>,
    dest_core: Option<Arc<Core>>,
    dest_token: String,
    restore: Option<ImportResult>,
    document: Option<ExchangeDocument>,
    split_parts: Option<Vec<(String, ExchangeDocument)>>,
    error: Option<String>,
}

impl std::fmt::Debug for ExchangeWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeWorld").field("error", &self.error).finish_non_exhaustive()
    }
}

impl ExchangeWorld {
    fn new() -> Self {
        Self {
            _bvault: None,
            core: None,
            token: String::new(),
            uploaded: HashMap::new(),
            dest_bvault: None,
            dest_core: None,
            dest_token: String::new(),
            restore: None,
            document: None,
            split_parts: None,
            error: None,
        }
    }

    fn core(&self) -> Arc<Core> {
        self.core.clone().expect("vault not created")
    }

    fn doc(&self) -> &ExchangeDocument {
        self.document.as_ref().unwrap_or_else(|| panic!("no export document; error: {:?}", self.error))
    }

    async fn request(
        &self,
        op: Operation,
        path: &str,
        ns: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
        request_on(&self.core(), &self.token, op, path, ns, body).await
    }

    async fn dest_request(
        &self,
        op: Operation,
        path: &str,
        ns: &str,
        body: Option<Map<String, Value>>,
    ) -> Result<Option<Response>, RvError> {
        let core = self.dest_core.clone().expect("no destination vault");
        request_on(&core, &self.dest_token, op, path, ns, body).await
    }

    /// Create a mount, tolerating one that already exists (the root namespace
    /// ships a default `files/` mount).
    async fn ensure_mount(&self, ns: &str, mount: &str, ty: &str) {
        let _ = self
            .request(Operation::Write, &format!("sys/mounts/{mount}"), ns, json!({ "type": ty }).as_object().cloned())
            .await;
    }
}

async fn request_on(
    core: &Arc<Core>,
    token: &str,
    op: Operation,
    path: &str,
    ns: &str,
    body: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = op;
    req.client_token = token.to_string();
    req.body = body;
    if ns != "root" && !ns.is_empty() {
        let mut h = HashMap::new();
        h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
        req.headers = Some(h);
    }
    core.handle_request(&mut req).await
}

/// Push the document through the same file format an operator would carry it
/// in, so a restore exercises serialisation and (for bvx) the envelope too.
fn through_format(doc: &ExchangeDocument, format: &str) -> ExchangeDocument {
    let inner = exchange::canonical::to_canonical_vec(doc).unwrap();
    let opened = match format {
        "bvx" => exchange::decrypt_bvx(&exchange::encrypt_bvx(&inner, PASSWORD, "", None).unwrap(), PASSWORD).unwrap(),
        "json" => inner,
        other => panic!("unknown format {other:?}"),
    };
    serde_json::from_slice(&opened).unwrap()
}

fn policy_hcl(ns: &str) -> &'static str {
    if ns == "root" {
        "path \"secret/*\" { capabilities = [\"read\"] }"
    } else {
        "path \"tenant-a/cubby/*\" { capabilities = [\"read\"] }"
    }
}

/// Deterministic, non-compressible-looking content so a truncated or shifted
/// blob cannot compare equal.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 251) % 251) as u8).collect()
}

fn csv(s: &str) -> Vec<String> {
    s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
}

fn namespace_items<'a>(doc: &'a ExchangeDocument, ns: &str) -> &'a exchange::ExchangeItems {
    if ns == "root" {
        return &doc.items;
    }
    &doc.items
        .namespaces
        .iter()
        .find(|b| b.path == ns)
        .unwrap_or_else(|| panic!("no bundle for namespace {ns:?}; have {:?}", exchange::document_namespaces(doc)))
        .items
}

fn parse_selector(raw: &str) -> Option<ScopeSelector> {
    match raw {
        "none" => None,
        s if s.starts_with("engine:") => Some(ScopeSelector::EngineType { engine: s["engine:".len()..].to_string() }),
        s if s.starts_with("mount:") => Some(ScopeSelector::Mount { mount: s["mount:".len()..].to_string() }),
        s if s.starts_with("kv:") => {
            let (mount, path) = s["kv:".len()..].split_once('/').expect("kv:<mount>/<path>");
            Some(ScopeSelector::KvPath { mount: format!("{mount}/"), path: path.to_string() })
        }
        other => panic!("unknown selector {other:?}"),
    }
}

async fn run_export(world: &mut ExchangeWorld, kind: &str, selecting: &str, namespaces: &str, split: bool) {
    let kind = match kind {
        "selective" => ScopeKind::Selective,
        "full" => ScopeKind::Full,
        "all_namespaces" => ScopeKind::AllNamespaces,
        other => panic!("unknown scope kind {other:?}"),
    };
    let scope = ScopeSpec { kind, include: parse_selector(selecting).into_iter().collect() };
    let namespaces = if namespaces == "none" { Vec::new() } else { csv(namespaces) };

    let core = world.core();
    let fan_out =
        kind == ScopeKind::AllNamespaces || (kind == ScopeKind::Selective && (split || !namespaces.is_empty()));
    let doc = if fan_out {
        exchange::export_namespaces(&core, ExporterInfo::default(), scope, &namespaces).await
    } else {
        let mounts = exchange::scope::MountIndex::from_core(&core).unwrap();
        exchange::export_to_document(core.barrier.as_storage(), &mounts, ExporterInfo::default(), scope).await
    };
    world.document = None;
    world.split_parts = None;
    world.error = None;
    match doc.and_then(|d| exchange::ensure_not_empty(&d).map(|_| d)) {
        Ok(d) => {
            if split {
                world.split_parts = Some(exchange::split_by_namespace(&d));
            }
            world.document = Some(d);
        }
        Err(e) => world.error = Some(format!("{e}")),
    }
}

#[given(expr = "a fresh vault with namespaces {string} and {string}")]
async fn fresh_vault(world: &mut ExchangeWorld, a: String, b: String) {
    let n = VAULT_SEQ.fetch_add(1, Ordering::SeqCst);
    let (bvault, core, token) = new_unseal_test_bastion_vault(&format!("test_cucumber_exchange_{n}")).await;
    world._bvault = Some(bvault);
    world.core = Some(core);
    world.token = token;
    // Parents first, so `tenant-a/child` has somewhere to live.
    for ns in [a, b] {
        world
            .request(Operation::Write, &format!("sys/namespaces/{ns}"), "root", json!({}).as_object().cloned())
            .await
            .unwrap();
    }
}

#[given(expr = "namespace {string} has a kv mount {string} with secret {string} = {string}")]
async fn kv_secret(world: &mut ExchangeWorld, ns: String, mount: String, name: String, value: String) {
    world.ensure_mount(&ns, &mount, "kv").await;
    world
        .request(Operation::Write, &format!("{mount}{name}"), &ns, json!({ "v": value }).as_object().cloned())
        .await
        .unwrap();
}

#[given(expr = "namespace {string} has a files mount {string} holding file {string} of {int} bytes")]
async fn files_mount(world: &mut ExchangeWorld, ns: String, mount: String, id: String, len: usize) {
    world.ensure_mount(&ns, &mount, "files").await;
    let bytes = pattern(len);
    let body = json!({
        "name": format!("{id}.bin"),
        "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
    });
    world.request(Operation::Write, &format!("{mount}files/{id}"), &ns, body.as_object().cloned()).await.unwrap();
    world.uploaded.insert((ns, id), bytes);
}

#[when(expr = "I export scope {string} selecting {string} from namespaces {string}")]
async fn export(world: &mut ExchangeWorld, kind: String, selecting: String, namespaces: String) {
    run_export(world, &kind, &selecting, &namespaces, false).await;
}

#[when(expr = "I export scope {string} selecting {string} from namespaces {string} split by namespace")]
async fn export_split(world: &mut ExchangeWorld, kind: String, selecting: String, namespaces: String) {
    run_export(world, &kind, &selecting, &namespaces, true).await;
}

#[when(expr = "file {string} is deleted from namespace {string}")]
async fn delete_file(world: &mut ExchangeWorld, id: String, ns: String) {
    world.request(Operation::Delete, &format!("files/files/{id}"), &ns, None).await.unwrap();
    let gone = world.request(Operation::Read, &format!("files/files/{id}"), &ns, None).await;
    assert!(matches!(gone, Ok(None)) || gone.is_err(), "file must be gone before the restore");
}

#[when("I import the export")]
async fn import(world: &mut ExchangeWorld) {
    let doc = world.doc().clone();
    exchange::import_all_namespaces(&world.core(), &doc, ConflictPolicy::Overwrite, false).await.unwrap();
}

#[then(expr = "the export carries namespaces {string}")]
async fn carries(world: &mut ExchangeWorld, expected: String) {
    let mut want = csv(&expected);
    let mut got: Vec<String> = exchange::document_namespaces(world.doc())
        .into_iter()
        .map(|n| if n.is_empty() { "root".to_string() } else { n })
        .collect();
    want.sort();
    got.sort();
    assert_eq!(got, want, "warnings: {:?}", world.doc().warnings);
}

#[then(expr = "namespace {string} holds {int} kv items")]
async fn kv_count(world: &mut ExchangeWorld, ns: String, n: usize) {
    let doc = world.doc();
    // An engine-scoped export of a namespace that holds no KV need not carry a
    // bundle at all for it; zero then means "absent" as well as "empty".
    let have = if ns != "root" && !doc.items.namespaces.iter().any(|b| b.path == ns) {
        0
    } else {
        namespace_items(doc, &ns).kv.len()
    };
    assert_eq!(have, n, "kv items in {ns}");
}

#[then(expr = "namespace {string} holds file {string} with {int} bytes")]
async fn holds_file(world: &mut ExchangeWorld, ns: String, id: String, len: usize) {
    let items = namespace_items(world.doc(), &ns);
    let file = items.files.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("file {id} not exported from {ns}"));
    let got = base64::engine::general_purpose::STANDARD.decode(&file.content_b64).unwrap();
    assert_eq!(got.len(), len, "exported byte length of {id} (an empty blob means the content was not read)");
    let original = world.uploaded.get(&(ns, id)).expect("scenario never uploaded that file");
    assert!(&got == original, "exported bytes differ from the uploaded bytes");
}

#[then(expr = "the split parts are for namespaces {string}")]
async fn split_parts(world: &mut ExchangeWorld, expected: String) {
    let parts = world.split_parts.as_ref().expect("not a split export");
    let mut got: Vec<String> =
        parts.iter().map(|(n, _)| if n.is_empty() { "root".to_string() } else { n.clone() }).collect();
    let mut want = csv(&expected);
    got.sort();
    want.sort();
    assert_eq!(got, want);
    // Each part must stand on its own: exactly one namespace per document.
    for (ns, part) in parts {
        assert_eq!(exchange::document_namespaces(part).len(), 1, "part {ns:?} must carry exactly one namespace");
    }
}

#[then("the export is refused as empty")]
async fn refused_empty(world: &mut ExchangeWorld) {
    let err = world.error.as_deref().unwrap_or_else(|| panic!("an empty export was produced: {:?}", world.document));
    assert!(err.contains("matched no data"), "{err}");
}

#[then(expr = "the export warns about {string}")]
async fn warns(world: &mut ExchangeWorld, needle: String) {
    assert!(world.doc().warnings.iter().any(|w| w.contains(&needle)), "{:?}", world.doc().warnings);
}

#[then(expr = "the export round-trips through format {string}")]
async fn round_trip(world: &mut ExchangeWorld, format: String) {
    let inner = exchange::canonical::to_canonical_vec(world.doc()).unwrap();
    let file = match format.as_str() {
        "bvx" => exchange::encrypt_bvx(&inner, PASSWORD, "", None).unwrap(),
        "json" => inner.clone(),
        other => panic!("unknown format {other:?}"),
    };
    let opened = if format == "bvx" { exchange::decrypt_bvx(&file, PASSWORD).unwrap() } else { file };
    let parsed: ExchangeDocument = serde_json::from_slice(&opened).unwrap();
    assert_eq!(exchange::canonical::to_canonical_vec(&parsed).unwrap(), inner, "document changed in transit");
}

#[then("the bvx export cannot be opened with a wrong password")]
async fn wrong_password(world: &mut ExchangeWorld) {
    let inner = exchange::canonical::to_canonical_vec(world.doc()).unwrap();
    let file = exchange::encrypt_bvx(&inner, PASSWORD, "", None).unwrap();
    assert!(exchange::decrypt_bvx(&file, "a different password!").is_err());
    assert!(exchange::decrypt_bvx(&file, PASSWORD).is_ok());
}

#[then(expr = "file {string} in namespace {string} reads back {int} bytes identical to the original")]
async fn reads_back(world: &mut ExchangeWorld, id: String, ns: String, len: usize) {
    let resp = world
        .request(Operation::Read, &format!("files/files/{id}/content"), &ns, None)
        .await
        .unwrap()
        .expect("file content missing after restore");
    let b64 = resp.data.unwrap()["content_base64"].as_str().unwrap().to_string();
    let got = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    assert_eq!(got.len(), len);
    assert!(&got == world.uploaded.get(&(ns, id)).unwrap(), "restored bytes differ");
}

// ---- restore ---------------------------------------------------------------

#[given(expr = "namespace {string} has a policy {string}")]
async fn has_policy(world: &mut ExchangeWorld, ns: String, name: String) {
    let body = json!({ "policy": policy_hcl(&ns) });
    world.request(Operation::Write, &format!("sys/policy/{name}"), &ns, body.as_object().cloned()).await.unwrap();
}

async fn build_destination(world: &mut ExchangeWorld, namespaces: &str, with_mounts: bool) {
    let n = VAULT_SEQ.fetch_add(1, Ordering::SeqCst);
    let (bvault, core, token) = new_unseal_test_bastion_vault(&format!("test_cucumber_exchange_dest_{n}")).await;
    world.dest_bvault = Some(bvault);
    world.dest_core = Some(core);
    world.dest_token = token;
    let mut all = vec!["root".to_string()];
    if namespaces != "none" {
        for ns in csv(namespaces) {
            world
                .dest_request(Operation::Write, &format!("sys/namespaces/{ns}"), "root", json!({}).as_object().cloned())
                .await
                .unwrap();
            all.push(ns);
        }
    }
    if with_mounts {
        for ns in &all {
            for mount in ["cubby/", "other/"] {
                let body = json!({ "type": "kv" }).as_object().cloned();
                world.dest_request(Operation::Write, &format!("sys/mounts/{mount}"), ns, body).await.unwrap();
            }
        }
    }
}

#[given(expr = "an empty destination vault with namespaces {string}")]
async fn destination_vault(world: &mut ExchangeWorld, namespaces: String) {
    build_destination(world, &namespaces, true).await;
}

#[given(expr = "an empty destination vault without mounts with namespaces {string}")]
async fn destination_vault_no_mounts(world: &mut ExchangeWorld, namespaces: String) {
    build_destination(world, &namespaces, false).await;
}

#[given(expr = "the destination namespace {string} has a kv mount {string} with secret {string} = {string}")]
async fn dest_secret(world: &mut ExchangeWorld, ns: String, mount: String, name: String, value: String) {
    let _ = world
        .dest_request(
            Operation::Write,
            &format!("sys/mounts/{mount}"),
            &ns,
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
    world
        .dest_request(Operation::Write, &format!("{mount}{name}"), &ns, json!({ "v": value }).as_object().cloned())
        .await
        .unwrap();
}

async fn restore(world: &mut ExchangeWorld, doc: &ExchangeDocument, policy: ConflictPolicy, dry_run: bool) {
    let core = world.dest_core.clone().expect("no destination vault");
    world.restore = Some(exchange::import_all_namespaces(&core, doc, policy, dry_run).await.unwrap());
}

#[when(expr = "I restore the export into the destination as {string}")]
async fn restore_as(world: &mut ExchangeWorld, format: String) {
    let doc = through_format(world.doc(), &format);
    restore(world, &doc, ConflictPolicy::Overwrite, false).await;
}

#[when(expr = "I restore the export into the destination with conflict policy {string}")]
async fn restore_with_policy(world: &mut ExchangeWorld, policy: String) {
    let policy = match policy.as_str() {
        "skip" => ConflictPolicy::Skip,
        "overwrite" => ConflictPolicy::Overwrite,
        "rename" => ConflictPolicy::Rename,
        other => panic!("unknown conflict policy {other:?}"),
    };
    let doc = through_format(world.doc(), "bvx");
    restore(world, &doc, policy, false).await;
}

#[when("I preview the restore into the destination")]
async fn preview_restore(world: &mut ExchangeWorld) {
    let doc = world.doc().clone();
    restore(world, &doc, ConflictPolicy::Overwrite, true).await;
}

#[when(expr = "I restore only namespaces {string} into the destination")]
async fn restore_only_namespaces(world: &mut ExchangeWorld, only: String) {
    let mut doc = world.doc().clone();
    exchange::retain_namespaces(&mut doc, &csv(&only));
    restore(world, &doc, ConflictPolicy::Overwrite, false).await;
}

#[when(expr = "I restore only mounts {string} into the destination")]
async fn restore_only_mounts(world: &mut ExchangeWorld, only: String) {
    let mut doc = world.doc().clone();
    exchange::retain_mounts(&mut doc, &csv(&only));
    restore(world, &doc, ConflictPolicy::Overwrite, false).await;
}

#[when("I restore every split part into the destination")]
async fn restore_split_parts(world: &mut ExchangeWorld) {
    let parts = world.split_parts.clone().expect("not a split export");
    let mut total = ImportResult::default();
    for (_, part) in parts {
        let part = through_format(&part, "bvx");
        let core = world.dest_core.clone().expect("no destination vault");
        let r = exchange::import_all_namespaces(&core, &part, ConflictPolicy::Overwrite, false).await.unwrap();
        total.written += r.written;
        total.skipped += r.skipped;
        total.renamed += r.renamed;
        total.warnings.extend(r.warnings);
    }
    world.restore = Some(total);
}

async fn dest_read(world: &ExchangeWorld, ns: &str, path: &str) -> Option<Map<String, Value>> {
    match world.dest_request(Operation::Read, path, ns, None).await {
        Ok(Some(resp)) => resp.data,
        _ => None,
    }
}

#[then(expr = "the destination namespace {string} secret {string} reads {string}")]
async fn dest_secret_reads(world: &mut ExchangeWorld, ns: String, path: String, expected: String) {
    let data = dest_read(world, &ns, &path).await.unwrap_or_else(|| panic!("{path} missing from {ns} after restore"));
    assert_eq!(data["v"].as_str(), Some(expected.as_str()), "{path} in {ns}");
}

#[then(expr = "the destination namespace {string} has no secret {string}")]
async fn dest_secret_absent(world: &mut ExchangeWorld, ns: String, path: String) {
    assert!(dest_read(world, &ns, &path).await.is_none(), "{path} must not exist in {ns}");
}

#[then(expr = "the destination namespace {string} file {string} reads back {int} bytes identical to the original")]
async fn dest_file(world: &mut ExchangeWorld, ns: String, id: String, len: usize) {
    let data = dest_read(world, &ns, &format!("files/files/{id}/content"))
        .await
        .unwrap_or_else(|| panic!("file {id} missing from {ns} after restore"));
    let got = base64::engine::general_purpose::STANDARD.decode(data["content_base64"].as_str().unwrap()).unwrap();
    assert_eq!(got.len(), len, "restored length of {id}");
    // The original was uploaded to the source under the same namespace.
    assert!(&got == world.uploaded.get(&(ns, id)).unwrap(), "restored bytes differ from the original upload");
}

#[then(expr = "the destination namespace {string} has no file {string}")]
async fn dest_file_absent(world: &mut ExchangeWorld, ns: String, id: String) {
    assert!(dest_read(world, &ns, &format!("files/files/{id}/content")).await.is_none(), "{id} must not exist in {ns}");
}

#[then(expr = "the destination namespace {string} policy {string} matches the source")]
async fn dest_policy(world: &mut ExchangeWorld, ns: String, name: String) {
    let data =
        dest_read(world, &ns, &format!("sys/policy/{name}")).await.unwrap_or_else(|| panic!("policy {name} missing"));
    assert_eq!(data["rules"].as_str(), Some(policy_hcl(&ns)), "policy {name} in {ns}");
}

#[then(expr = "the restore wrote at least {int} items")]
async fn restore_wrote(world: &mut ExchangeWorld, n: u64) {
    let r = world.restore.as_ref().expect("no restore ran");
    assert!(r.written >= n, "wrote {} (warnings: {:?})", r.written, r.warnings);
}

#[then("the preview classified items as new")]
async fn preview_classified(world: &mut ExchangeWorld) {
    let r = world.restore.as_ref().expect("no restore ran");
    // Counters on a dry run describe what *would* be written; the scenario
    // separately asserts the destination really is untouched.
    let (new, _, _) = r.classification_counts();
    assert!(new > 0, "the preview should still classify items as new");
}

#[then(expr = "the restore skipped at least {int} items")]
async fn restore_skipped(world: &mut ExchangeWorld, n: u64) {
    assert!(world.restore.as_ref().unwrap().skipped >= n);
}

#[then(expr = "the restore renamed at least {int} items")]
async fn restore_renamed(world: &mut ExchangeWorld, n: u64) {
    assert!(world.restore.as_ref().unwrap().renamed >= n);
}

#[then(expr = "the restore warns about {string}")]
async fn restore_warns(world: &mut ExchangeWorld, needle: String) {
    let r = world.restore.as_ref().unwrap();
    assert!(r.warnings.iter().any(|w| w.contains(&needle)), "{:?}", r.warnings);
}

#[tokio::main]
async fn main() {
    // One vault at a time: each scenario builds an on-disk vault, and the
    // harness is a plain process, not a nextest-isolated one.
    ExchangeWorld::cucumber().max_concurrent_scenarios(1).run_and_exit("tests/features/exchange_export.feature").await;
}
