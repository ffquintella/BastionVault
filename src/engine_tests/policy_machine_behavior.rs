//! Behaviour suite: policy evaluation x user profiles x machine identity.
//! Every case drives a real vault through `Core::handle_request` with real
//! tokens: userpass users, FerroGate machine tokens (signed child token + DPoP
//! proof, then approval) and AppRole/AppID logins presenting a machine token.

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ferro_child_verify::{jwk_thumbprint_ed25519, CHILD_ALG, CHILD_SIGNING_CONTEXT, CHILD_TYP};
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
use serde_json::{json, Value};

use crate::{
    core::Core,
    errors::RvError,
    logical::{connection::Connection, Auth, Operation, Request, Response},
    modules::credential::ferrogate::machine_id,
    test_utils::{new_unseal_test_bastion_vault, test_delete_api, test_mount_auth_api, test_write_api},
    BastionVault,
};

const AUD: &str = "https://vault.example.com";
const KID: &str = "host-bhv";
const PASSWORD: &str = "hunter22XX!";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn jwks_json(kid: &str, pk: &CompositePublicKey) -> String {
    json!({ "keys": [ { "kty": "FERROGATE-COMPOSITE", "kid": kid, "pub": b64(&pk.to_concat_bytes()) } ] }).to_string()
}

/// `path "<p>" { capabilities = [..] }`: one rule.
fn rule(path: &str, caps: &[&str]) -> String {
    let caps = caps.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(", ");
    format!("path \"{path}\" {{\n  capabilities = [{caps}]\n}}\n")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Read,
    Write,
    Delete,
    List,
}

impl Op {
    fn op(self) -> Operation {
        match self {
            Op::Read => Operation::Read,
            Op::Write => Operation::Write,
            Op::Delete => Operation::Delete,
            Op::List => Operation::List,
        }
    }
}

/// A FerroGate machine: its login material and, once approved and logged in,
/// the token it was issued.
struct Machine {
    iss: String,
    id: String,
    jws: String,
    proof: String,
    token: String,
}

struct Env {
    _bvault: BastionVault,
    core: Arc<Core>,
    root: String,
    sk: CompositeSecretKey,
    pk: CompositePublicKey,
    seq: AtomicU32,
}

#[maybe_async::maybe_async]
impl Env {
    /// A vault with userpass, approle and ferrogate mounted, a KV v2 mount at
    /// `kv/` holding a small tree, and a FerroGate trust anchor configured.
    async fn new(name: &str) -> Env {
        let (bvault, core, root) = new_unseal_test_bastion_vault(name).await;
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let env = Env { _bvault: bvault, core, root, sk, pk, seq: AtomicU32::new(1) };

        test_mount_auth_api(&env.core, &env.root, "userpass", "userpass").await;
        test_mount_auth_api(&env.core, &env.root, "approle", "approle").await;
        test_mount_auth_api(&env.core, &env.root, "ferrogate", "ferrogate").await;
        env.root_write("sys/mounts/kv/", json!({ "type": "kv-v2" })).await;

        for (path, val) in [
            ("kv/data/app/db", "db-secret"),
            ("kv/data/app/api", "api-secret"),
            ("kv/data/apple/x", "apple-secret"),
            ("kv/data/team/a/secret", "team-a-secret"),
            ("kv/data/team/b/secret", "team-b-secret"),
            ("kv/data/public/readme", "public-readme"),
            ("kv/data/admin/root-secret", "admin-secret"),
        ] {
            env.root_write(path, json!({ "data": { "pw": val } })).await;
        }
        env.root_write(
            "kv/data/svc",
            json!({
                "data": { "host": "db.base" },
                "envs": {
                    "prod": { "host": "db.prod" },
                    "prod-1": { "host": "db.prod1" },
                    "staging": { "host": "db.staging" },
                    "dev": { "host": "db.dev" },
                }
            }),
        )
        .await;

        env.ferro_config(json!({})).await;
        env
    }

    // plumbing

    async fn root_write(&self, path: &str, body: Value) {
        test_write_api(self.core.as_ref(), &self.root, path, true, body.as_object().cloned()).await.unwrap();
    }

    async fn root_delete(&self, path: &str) {
        test_delete_api(self.core.as_ref(), &self.root, path, true, None).await.unwrap();
    }

    async fn req_with(
        &self,
        token: &str,
        op: Op,
        path: &str,
        body: Option<Value>,
        data: Option<Value>,
    ) -> Result<Option<Response>, RvError> {
        let mut r = Request::new(path);
        r.operation = op.op();
        r.client_token = token.to_string();
        r.body = body.and_then(|b| b.as_object().cloned());
        r.data = data.and_then(|d| d.as_object().cloned());
        self.core.handle_request(&mut r).await
    }

    /// The default body for a write is a KV v2 payload.
    async fn req(&self, token: &str, op: Op, path: &str) -> Result<Option<Response>, RvError> {
        let body = (op == Op::Write).then(|| json!({ "data": { "pw": "written" } }));
        self.req_with(token, op, path, body, None).await
    }

    async fn can(&self, token: &str, op: Op, path: &str) -> bool {
        self.req(token, op, path).await.is_ok()
    }

    async fn can_read(&self, token: &str, path: &str) -> bool {
        self.can(token, Op::Read, path).await
    }

    /// True only for the typed permission refusal, so an unrelated failure
    /// (404, 500, malformed request) cannot masquerade as a policy verdict.
    async fn refused(&self, token: &str, op: Op, path: &str) -> bool {
        matches!(self.req(token, op, path).await, Err(RvError::ErrPermissionDenied))
    }

    /// The `pw` value a KV read returned, if the read succeeded.
    async fn secret(&self, token: &str, path: &str) -> Option<String> {
        let resp = self.req(token, Op::Read, path).await.ok().flatten()?;
        resp.data?["data"]["pw"].as_str().map(str::to_string)
    }

    async fn policy(&self, name: &str, hcl: &str) {
        self.root_write(&format!("sys/policy/{name}"), json!({ "policy": hcl })).await;
    }

    /// A userpass user carrying exactly `policies`; returns its token.
    async fn user(&self, name: &str, policies: &str) -> String {
        self.root_write(
            &format!("auth/userpass/users/{name}"),
            json!({ "password": PASSWORD, "token_policies": policies, "ttl": 0 }),
        )
        .await;
        self.user_login(name, PASSWORD).await.unwrap().unwrap().auth.unwrap().client_token
    }

    async fn user_login(&self, name: &str, password: &str) -> Result<Option<Response>, RvError> {
        let mut r = Request::new(format!("auth/userpass/login/{name}"));
        r.operation = Operation::Write;
        r.body = json!({ "password": password }).as_object().cloned();
        self.core.handle_request(&mut r).await
    }

    /// A user whose only policy, `p-<name>`, holds `hcl`.
    async fn profile(&self, name: &str, hcl: &str) -> String {
        self.policy(&format!("p-{name}"), hcl).await;
        self.user(name, &format!("p-{name}")).await
    }

    /// A caller with no token at all.
    fn anon() -> &'static str {
        ""
    }

    // FerroGate

    async fn ferro_config(&self, extra: Value) {
        let mut cfg = json!({
            "trust_domain": "ferrogate.test",
            "expected_audience": AUD,
            "jwks_source": "static_jwks",
            "static_jwks": jwks_json(KID, &self.pk),
        });
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            cfg[k] = v;
        }
        self.root_write("auth/ferrogate/config", cfg).await;
    }

    fn mint_child(&self, sk: &CompositeSecretKey, iss: &str, aud: &str, jkt: &str, iat: i64, exp: i64) -> String {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let header = json!({ "alg": CHILD_ALG, "typ": CHILD_TYP, "kid": KID });
        let claims = json!({
            "iss": iss,
            "sub": format!("{iss}#app:abababababababab"),
            "aud": aud,
            "exp": exp,
            "iat": iat,
            "jti": format!("{n:032x}"),
            "cnf": { "jkt": jkt },
            "ferrogate": {
                "parent_svid": "33".repeat(48),
                "actor_pid": 1234u32,
                "actor_uid": 1001u32,
                "actor_bin": "ab".repeat(48),
            },
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(CHILD_SIGNING_CONTEXT, signing_input.as_bytes()).unwrap();
        format!("{signing_input}.{}", b64(&sig.to_concat_bytes()))
    }

    fn mint_dpop(&self, ed: &SigningKey, htm: &str, htu: &str, iat: i64) -> (String, String) {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let x = b64(ed.verifying_key().as_bytes());
        let jkt = jwk_thumbprint_ed25519(&x);
        let header = json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x } });
        let claims = json!({ "jti": format!("dpop-{n}"), "htm": htm, "htu": htu, "iat": iat });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = ed.sign(signing_input.as_bytes());
        (format!("{signing_input}.{}", b64(&sig.to_bytes())), jkt)
    }

    /// Login material for host `name` (not yet known to the vault).
    fn material(&self, name: &str) -> Machine {
        let n = self.seq.fetch_add(1, Ordering::Relaxed) as u8;
        let iss = format!("spiffe://ferrogate.test/host/{name}");
        let ed = SigningKey::from_bytes(&[n.wrapping_add(7); 32]);
        let now = now_secs();
        let (proof, jkt) = self.mint_dpop(&ed, "POST", AUD, now);
        let jws = self.mint_child(&self.sk, &iss, AUD, &jkt, now, now + 3600);
        Machine { id: machine_id(&iss), iss, jws, proof, token: String::new() }
    }

    async fn ferro_login(
        &self,
        jws: &str,
        proof: Option<&str>,
        user_token: Option<&str>,
    ) -> Result<Option<Response>, RvError> {
        let mut r = Request::new("auth/ferrogate/login");
        r.operation = Operation::Write;
        let mut body = serde_json::Map::new();
        body.insert("token".into(), json!(jws));
        if let Some(p) = proof {
            body.insert("dpop".into(), json!(p));
        }
        if let Some(u) = user_token {
            body.insert("user_token".into(), json!(u));
        }
        r.body = Some(body);
        self.core.handle_request(&mut r).await
    }

    fn token_of(res: Result<Option<Response>, RvError>) -> Option<String> {
        res.ok().flatten().and_then(|r| r.auth).map(|a| a.client_token).filter(|t| !t.is_empty())
    }

    /// Record `m` (pending) with the vault.
    async fn register(&self, m: &Machine) {
        let _ = self.ferro_login(&m.jws, Some(&m.proof), None).await;
    }

    async fn approve(&self, m: &Machine, policies: &str) {
        self.root_write(
            &format!("auth/ferrogate/machines/{}/approve", m.id),
            json!({ "policies": policies, "ttl_seconds": 600 }),
        )
        .await;
    }

    /// An approved machine with `policies`, already logged in.
    async fn machine(&self, name: &str, policies: &str) -> Machine {
        let mut m = self.material(name);
        self.register(&m).await;
        self.approve(&m, policies).await;
        m.token = Self::token_of(self.ferro_login(&m.jws, Some(&m.proof), None).await)
            .expect("an approved machine must receive a token");
        m
    }

    /// Server-wide `require_machine_identity`.
    async fn gate(&self, on: bool) {
        self.ferro_config(json!({ "require_machine_identity": on })).await;
    }

    // AppRole / AppID

    async fn role(&self, role: &str, policies: &str, extra: Value) {
        let mut body = json!({
            "role_id": format!("{role}-id"),
            "policies": policies,
            "secret_id_num_uses": 10,
            "secret_id_ttl": 300,
            "token_ttl": 400,
            "token_max_ttl": 500,
        });
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            body[k] = v;
        }
        self.root_write(&format!("auth/approle/role/{role}"), body).await;
    }

    async fn bind(&self, role: &str, m: &Machine, environments: &str) {
        self.root_write(
            &format!("auth/approle/role/{role}/machine/"),
            json!({ "machine_id": m.id, "environments": environments }),
        )
        .await;
    }

    async fn secret_id(&self, role: &str, environments: Option<&str>) -> String {
        let body = environments.map(|e| json!({ "environments": e }));
        let resp = test_write_api(
            self.core.as_ref(),
            &self.root,
            &format!("auth/approle/role/{role}/secret-id"),
            true,
            body.and_then(|b| b.as_object().cloned()),
        )
        .await
        .unwrap()
        .unwrap();
        resp.data.unwrap()["secret_id"].as_str().unwrap().to_string()
    }

    async fn appid_login(
        &self,
        role: &str,
        secret_id: &str,
        machine_token: Option<&str>,
        conn: Option<Connection>,
    ) -> Result<Option<Response>, RvError> {
        let mut body = json!({ "role_id": format!("{role}-id"), "secret_id": secret_id });
        if let Some(t) = machine_token {
            body["machine_token"] = json!(t);
        }
        let mut r = Request::new("auth/approle/login");
        r.operation = Operation::Write;
        r.body = body.as_object().cloned();
        r.connection = conn;
        self.core.handle_request(&mut r).await
    }

    fn auth_of(res: Result<Option<Response>, RvError>) -> Option<Auth> {
        res.ok().flatten().and_then(|r| r.auth)
    }

    /// A role bound to machine `m`, then a login with a fresh secret ID.
    async fn appid(&self, role: &str, policies: &str, m: &Machine, environments: &str) -> Option<Auth> {
        self.role(role, policies, json!({})).await;
        self.bind(role, m, environments).await;
        let sid = self.secret_id(role, None).await;
        Self::auth_of(self.appid_login(role, &sid, Some(&m.token), None).await)
    }

    /// An AppID token for a role holding policy `p-kv`, with the given scopes.
    async fn appid_token(&self, role: &str, m: &Machine, machine_env: &str, secret_env: Option<&str>) -> String {
        self.role(role, "p-kv", json!({})).await;
        self.bind(role, m, machine_env).await;
        let sid = self.secret_id(role, secret_env).await;
        Self::auth_of(self.appid_login(role, &sid, Some(&m.token), None).await)
            .expect("the AppID login must succeed")
            .client_token
    }

    async fn read_env(&self, token: &str, env: Option<&str>) -> Result<Option<Response>, RvError> {
        let data = env.map(|e| json!({ "env": e }));
        self.req_with(token, Op::Read, "kv/data/svc", None, data).await
    }
}

macro_rules! bv_test {
    (ignore $why:literal, $name:ident, |$e:ident| $body:block) => {
        #[ignore = $why]
        #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
        async fn $name() {
            let $e = Env::new(stringify!($name)).await;
            $body
        }
    };
    ($name:ident, |$e:ident| $body:block) => {
        #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
        async fn $name() {
            let $e = Env::new(stringify!($name)).await;
            $body
        }
    };
}

// A. policy grammar and evaluation

bv_test!(a01_user_with_no_policy_cannot_read_kv, |e| {
    let t = e.user("nobody", "").await;
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(a02_default_policy_grants_lookup_self, |e| {
    let t = e.user("nobody", "").await;
    assert!(e.can_read(&t, "auth/token/lookup-self").await, "every token must be able to look itself up");
});

bv_test!(a03_an_unrelated_grant_does_not_open_other_paths, |e| {
    let t = e.profile("other", &rule("kv/data/public/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/public/readme").await, "control: the grant is live");
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(a04_read_capability_allows_read_but_not_write, |e| {
    let t = e.profile("usr-r", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await);
});

bv_test!(a05_write_capabilities_allow_write_but_not_read, |e| {
    let t = e.profile("usr-w", &rule("kv/data/app/*", &["create", "update"])).await;
    assert!(e.can(&t, Op::Write, "kv/data/app/fresh").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(a06_delete_capability_is_independent_of_read_and_write, |e| {
    let t = e.profile("usr-d", &rule("kv/data/app/*", &["delete"])).await;
    assert!(e.can(&t, Op::Delete, "kv/data/app/api").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await);
});

bv_test!(a07_list_capability_lists_but_cannot_read_values, |e| {
    let t = e.profile("usr-l", &rule("kv/metadata/app/", &["list"])).await;
    assert!(e.can(&t, Op::List, "kv/metadata/app/").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(a08_trailing_glob_matches_nested_children, |e| {
    let t = e.profile("usr-g", &rule("kv/data/team/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/team/a/secret").await);
    assert!(e.can_read(&t, "kv/data/team/b/secret").await);
});

bv_test!(a09_glob_does_not_match_a_sibling_sharing_the_prefix, |e| {
    let t = e.profile("usr-g", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    assert!(e.refused(&t, Op::Read, "kv/data/apple/x").await, "`app/*` must not match `apple/...`");
});

bv_test!(a10_exact_rule_matches_only_that_path, |e| {
    let t = e.profile("usr-x", &rule("kv/data/app/db", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/api").await);
});

bv_test!(a11_plus_matches_exactly_one_segment, |e| {
    let t = e.profile("plus", &rule("kv/data/+/readme", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/public/readme").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(a12_plus_does_not_cross_a_segment_boundary, |e| {
    let t = e.profile("plus", &rule("kv/data/+/secret", &["read"])).await;
    assert!(e.refused(&t, Op::Read, "kv/data/team/a/secret").await, "`+` is one segment, not two");
});

bv_test!(a13_plus_in_the_middle_with_a_trailing_glob, |e| {
    let t = e.profile("plus", &rule("kv/data/+/a/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/team/a/secret").await);
    assert!(e.refused(&t, Op::Read, "kv/data/team/b/secret").await);
});

bv_test!(a14_deny_overrides_a_broader_allow, |e| {
    let hcl = format!("{}{}", rule("kv/data/*", &["read"]), rule("kv/data/admin/*", &["deny"]));
    let t = e.profile("usr-d", &hcl).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
});

bv_test!(a15_deny_in_one_policy_overrides_an_allow_in_another, |e| {
    e.policy("allow-all", &rule("kv/data/*", &["read", "list"])).await;
    e.policy("deny-admin", &rule("kv/data/admin/*", &["deny"])).await;
    let t = e.user("both", "allow-all,deny-admin").await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
});

bv_test!(a16_deny_wins_regardless_of_policy_order, |e| {
    e.policy("allow-all", &rule("kv/data/*", &["read"])).await;
    e.policy("deny-admin", &rule("kv/data/admin/*", &["deny"])).await;
    let t = e.user("rev", "deny-admin,allow-all").await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
});

bv_test!(a17_deny_on_an_exact_path_beats_a_glob_allow, |e| {
    let hcl = format!("{}{}", rule("kv/data/app/*", &["read", "update"]), rule("kv/data/app/db", &["deny"]));
    let t = e.profile("usr-d", &hcl).await;
    assert!(e.can_read(&t, "kv/data/app/api").await, "control");
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await);
});

bv_test!(a18_exact_rule_takes_precedence_over_a_glob_it_is_inside, |e| {
    let hcl = format!("{}{}", rule("kv/data/app/*", &["read", "create", "update"]), rule("kv/data/app/db", &["read"]));
    let t = e.profile("usr-x", &hcl).await;
    assert!(e.can(&t, Op::Write, "kv/data/app/api").await, "control: the glob grants write");
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await, "the exact read-only rule governs app/db");
});

bv_test!(a19_longest_prefix_rule_governs, |e| {
    let hcl = format!("{}{}", rule("kv/data/*", &["read", "create", "update"]), rule("kv/data/app/*", &["read"]));
    let t = e.profile("usr-lp", &hcl).await;
    assert!(e.can(&t, Op::Write, "kv/data/public/new").await, "control: the shorter glob grants write");
    assert!(e.refused(&t, Op::Write, "kv/data/app/new").await, "the longer prefix is read-only");
});

bv_test!(a20_capabilities_union_across_policies, |e| {
    e.policy("pr", &rule("kv/data/app/*", &["read"])).await;
    e.policy("pw", &rule("kv/data/app/*", &["create", "update"])).await;
    let t = e.user("usr-u", "pr,pw").await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.can(&t, Op::Write, "kv/data/app/new").await);
    assert!(e.refused(&t, Op::Delete, "kv/data/app/db").await);
});

bv_test!(a21_policy_update_applies_to_an_existing_token, |e| {
    let t = e.profile("live", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Read, "kv/data/public/readme").await);
    e.policy("p-live", &rule("kv/data/public/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/public/readme").await, "policy edits must reach tokens already issued");
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await, "and withdraw what the old text granted");
});

bv_test!(a22_policy_delete_revokes_access_of_an_existing_token, |e| {
    let t = e.profile("gone", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    e.root_delete("sys/policy/p-gone").await;
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await, "a deleted policy grants nothing");
});

bv_test!(a23_root_token_is_unrestricted, |e| {
    assert!(e.can_read(&e.root, "kv/data/admin/root-secret").await);
    assert!(e.can(&e.root, Op::Write, "kv/data/app/anything").await);
});

bv_test!(a24_plain_user_cannot_write_policies, |e| {
    let t = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&t, Op::Write, "sys/policy/evil", Some(json!({ "policy": rule("*", &["read"]) })), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
});

bv_test!(a25_user_cannot_rewrite_the_default_policy, |e| {
    let t = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r =
        e.req_with(&t, Op::Write, "sys/policy/default", Some(json!({ "policy": rule("*", &["read"]) })), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
});

bv_test!(a26_the_default_policy_cannot_be_deleted, |e| {
    let r = e.req(&e.root, Op::Delete, "sys/policy/default").await;
    assert!(r.is_err(), "deleting `default` must be refused even for root");
});

bv_test!(a27_the_root_policy_cannot_be_written, |e| {
    let r =
        e.req_with(&e.root, Op::Write, "sys/policy/root", Some(json!({ "policy": rule("*", &["read"]) })), None).await;
    assert!(r.is_err(), "`root` is reserved");
});

bv_test!(a28_malformed_hcl_is_rejected_and_stores_nothing, |e| {
    let r =
        e.req_with(&e.root, Op::Write, "sys/policy/broken", Some(json!({ "policy": "path \"kv/*\" {" })), None).await;
    assert!(r.is_err());
    let r = e.req(&e.root, Op::Read, "sys/policy/broken").await;
    assert!(r.is_err() || r.unwrap().is_none(), "a rejected policy must not be stored");
});

bv_test!(a29_unknown_capability_is_rejected, |e| {
    let hcl = rule("kv/*", &["read", "teleport"]);
    let r = e.req_with(&e.root, Op::Write, "sys/policy/odd", Some(json!({ "policy": hcl })), None).await;
    assert!(r.is_err(), "an unknown capability must not be silently dropped");
});

bv_test!(a30_a_deny_only_policy_grants_nothing, |e| {
    let t = e.profile("denyonly", &rule("kv/data/admin/*", &["deny"])).await;
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
    assert!(e.refused(&t, Op::Read, "kv/data/public/readme").await);
});

bv_test!(a31_allowed_parameters_reject_an_unlisted_parameter, |e| {
    let hcl = "path \"kv/data/app/*\" {\n  capabilities = [\"create\", \"update\"]\n  allowed_parameters = { \"data\" = [] }\n}\n";
    let t = e.profile("usr-ap", hcl).await;
    let ok = e.req_with(&t, Op::Write, "kv/data/app/p1", Some(json!({ "data": { "pw": "x" } })), None).await;
    assert!(ok.is_ok(), "control: a listed parameter passes: {ok:?}");
    let body = json!({ "data": { "pw": "x" }, "options": { "cas": 0 } });
    let bad = e.req_with(&t, Op::Write, "kv/data/app/p2", Some(body), None).await;
    assert!(matches!(bad, Err(RvError::ErrPermissionDenied)), "{bad:?}");
});

bv_test!(a32_denied_parameters_reject_the_named_parameter, |e| {
    let hcl = "path \"kv/data/app/*\" {\n  capabilities = [\"create\", \"update\"]\n  denied_parameters = { \"options\" = [] }\n}\n";
    let t = e.profile("usr-dp", hcl).await;
    let ok = e.req_with(&t, Op::Write, "kv/data/app/p1", Some(json!({ "data": { "pw": "x" } })), None).await;
    assert!(ok.is_ok(), "control: {ok:?}");
    let body = json!({ "data": { "pw": "x" }, "options": { "cas": 0 } });
    let bad = e.req_with(&t, Op::Write, "kv/data/app/p2", Some(body), None).await;
    assert!(matches!(bad, Err(RvError::ErrPermissionDenied)), "{bad:?}");
});

bv_test!(a33_required_parameters_must_be_present, |e| {
    let hcl = "path \"kv/data/app/*\" {\n  capabilities = [\"create\", \"update\"]\n  required_parameters = [\"options\"]\n}\n";
    let t = e.profile("usr-rp", hcl).await;
    let missing = e.req_with(&t, Op::Write, "kv/data/app/p1", Some(json!({ "data": { "pw": "x" } })), None).await;
    assert!(matches!(missing, Err(RvError::ErrPermissionDenied)), "{missing:?}");
    let body = json!({ "data": { "pw": "x" }, "options": { "cas": 0 } });
    let present = e.req_with(&t, Op::Write, "kv/data/app/p2", Some(body), None).await;
    assert!(present.is_ok(), "control: {present:?}");
});

bv_test!(a34_capabilities_self_agrees_with_the_verdicts, |e| {
    let t = e.profile("cap", &rule("kv/data/app/*", &["read"])).await;
    let body = json!({ "paths": ["kv/data/app/db", "kv/data/admin/root-secret"] });
    let resp = e.req_with(&t, Op::Write, "sys/capabilities-self", Some(body), None).await.unwrap().unwrap();
    let caps = resp.data.unwrap()["capabilities"].clone();
    let list = |p: &str| -> Vec<String> {
        caps[p].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    assert!(list("kv/data/app/db").contains(&"read".to_string()), "{caps}");
    assert!(!list("kv/data/app/db").contains(&"update".to_string()), "{caps}");
    assert!(!list("kv/data/admin/root-secret").contains(&"read".to_string()), "{caps}");
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
});

// B. user profiles

bv_test!(b01_admin_profile_has_full_crud_on_kv, |e| {
    let t = e.profile("admin", &rule("kv/*", &["create", "read", "update", "delete", "list"])).await;
    assert!(e.can(&t, Op::Write, "kv/data/app/adm").await);
    assert!(e.can_read(&t, "kv/data/app/adm").await);
    assert!(e.can(&t, Op::List, "kv/metadata/app/").await);
    assert!(e.can(&t, Op::Delete, "kv/data/app/adm").await);
});

bv_test!(b02_reader_profile_reads_everywhere_and_writes_nowhere, |e| {
    let t = e.profile("reader", &rule("kv/data/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
    assert!(e.can_read(&t, "kv/data/admin/root-secret").await);
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Delete, "kv/data/app/db").await);
});

bv_test!(b03_writer_profile_is_a_dropbox_it_cannot_read_back, |e| {
    let t = e.profile("dropbox", &rule("kv/data/public/*", &["create"])).await;
    assert!(e.can(&t, Op::Write, "kv/data/public/new-drop").await);
    assert!(e.refused(&t, Op::Read, "kv/data/public/new-drop").await);
    assert!(e.refused(&t, Op::Read, "kv/data/public/readme").await);
});

bv_test!(b04_auditor_profile_lists_names_without_values, |e| {
    let t = e.profile("auditor", &rule("kv/metadata/*", &["list", "read"])).await;
    assert!(e.can(&t, Op::List, "kv/metadata/app/").await);
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await, "metadata access is not value access");
});

bv_test!(b05_team_a_user_reads_team_a_not_team_b, |e| {
    let t = e.profile("alice", &rule("kv/data/team/a/*", &["read"])).await;
    assert_eq!(e.secret(&t, "kv/data/team/a/secret").await.as_deref(), Some("team-a-secret"));
    assert!(e.refused(&t, Op::Read, "kv/data/team/b/secret").await);
});

bv_test!(b06_team_b_user_reads_team_b_not_team_a, |e| {
    let t = e.profile("bob", &rule("kv/data/team/b/*", &["read"])).await;
    assert_eq!(e.secret(&t, "kv/data/team/b/secret").await.as_deref(), Some("team-b-secret"));
    assert!(e.refused(&t, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(b07_two_teams_are_isolated_from_each_other, |e| {
    let a = e.profile("alice", &rule("kv/data/team/a/*", &["read"])).await;
    let b = e.profile("bob", &rule("kv/data/team/b/*", &["read"])).await;
    assert_ne!(a, b);
    assert!(e.can_read(&a, "kv/data/team/a/secret").await && e.can_read(&b, "kv/data/team/b/secret").await);
    assert!(e.refused(&a, Op::Read, "kv/data/team/b/secret").await);
    assert!(e.refused(&b, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(b08_user_in_two_profiles_gets_the_union, |e| {
    e.policy("pa", &rule("kv/data/team/a/*", &["read"])).await;
    e.policy("pb", &rule("kv/data/team/b/*", &["read"])).await;
    let t = e.user("both", "pa,pb").await;
    assert!(e.can_read(&t, "kv/data/team/a/secret").await);
    assert!(e.can_read(&t, "kv/data/team/b/secret").await);
    assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
});

bv_test!(b09_a_deny_profile_in_the_union_removes_access, |e| {
    e.policy("pa", &rule("kv/data/team/*", &["read"])).await;
    e.policy("no-b", &rule("kv/data/team/b/*", &["deny"])).await;
    let t = e.user("limited", "pa,no-b").await;
    assert!(e.can_read(&t, "kv/data/team/a/secret").await);
    assert!(e.refused(&t, Op::Read, "kv/data/team/b/secret").await);
});

bv_test!(b10_policy_admin_manages_policies_but_cannot_read_secrets, |e| {
    let t = e.profile("poladmin", &rule("sys/policy/*", &["create", "read", "update", "delete", "list", "sudo"])).await;
    let body = json!({ "policy": rule("kv/data/app/*", &["read"]) });
    let w = e.req_with(&t, Op::Write, "sys/policy/new-one", Some(body), None).await;
    assert!(w.is_ok(), "control: {w:?}");
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
});

bv_test!(b11_mount_admin_can_read_mounts_a_plain_user_cannot, |e| {
    let admin = e.profile("mntadmin", &rule("sys/mounts", &["read"])).await;
    let plain = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can(&admin, Op::Read, "sys/mounts").await, "control");
    assert!(e.refused(&plain, Op::Read, "sys/mounts").await);
});

bv_test!(b12_user_cannot_mount_without_a_grant, |e| {
    let plain = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&plain, Op::Write, "sys/mounts/rogue/", Some(json!({ "type": "kv-v2" })), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
});

bv_test!(b13_wrong_password_fails_login, |e| {
    e.user("carol", "").await;
    assert!(Env::token_of(e.user_login("carol", "not-the-password").await).is_none());
    assert!(Env::token_of(e.user_login("carol", PASSWORD).await).is_some(), "control");
});

bv_test!(b14_unknown_user_cannot_log_in, |e| {
    assert!(Env::token_of(e.user_login("ghost", PASSWORD).await).is_none());
});

bv_test!(b15_user_update_does_not_rewrite_an_issued_token, |e| {
    e.policy("pa", &rule("kv/data/team/a/*", &["read"])).await;
    e.policy("pb", &rule("kv/data/team/b/*", &["read"])).await;
    let old = e.user("shift", "pa").await;
    e.root_write("auth/userpass/users/shift", json!({ "password": PASSWORD, "token_policies": "pb", "ttl": 0 })).await;
    let new = e.user_login("shift", PASSWORD).await.unwrap().unwrap().auth.unwrap().client_token;
    assert!(e.can_read(&new, "kv/data/team/b/secret").await, "a new login carries the new policies");
    assert!(e.refused(&new, Op::Read, "kv/data/team/a/secret").await);
    assert!(e.can_read(&old, "kv/data/team/a/secret").await, "an issued token keeps the policies it was issued with");
    assert!(e.refused(&old, Op::Read, "kv/data/team/b/secret").await);
});

bv_test!(b16_two_logins_of_one_user_carry_the_same_policies, |e| {
    e.policy("pa", &rule("kv/data/team/a/*", &["read"])).await;
    let t1 = e.user("twin", "pa").await;
    let t2 = e.user_login("twin", PASSWORD).await.unwrap().unwrap().auth.unwrap().client_token;
    assert_ne!(t1, t2);
    assert!(e.can_read(&t1, "kv/data/team/a/secret").await && e.can_read(&t2, "kv/data/team/a/secret").await);
});

// C. token lifecycle

bv_test!(c01_empty_token_is_refused_on_a_protected_path, |e| {
    assert!(e.req(Env::anon(), Op::Read, "kv/data/app/db").await.is_err());
});

bv_test!(c02_a_forged_token_is_refused, |e| {
    assert!(e.req("hvs.this-token-was-never-issued", Op::Read, "kv/data/app/db").await.is_err());
});

bv_test!(c03_a_revoked_token_is_refused, |e| {
    let t = e.profile("usr-r", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    e.req_with(&t, Op::Write, "auth/token/revoke-self", None, None).await.unwrap();
    assert!(e.req(&t, Op::Read, "kv/data/app/db").await.is_err());
});

bv_test!(c04_renew_self_is_not_an_authorization_failure, |e| {
    let t = e.profile("usr-ren", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&t, Op::Write, "auth/token/renew-self", None, None).await;
    assert!(!matches!(r, Err(RvError::ErrPermissionDenied)), "the default policy grants renew-self: {r:?}");
});

bv_test!(c05_a_user_cannot_look_up_another_token_without_a_grant, |e| {
    let a = e.profile("alice", &rule("kv/data/app/*", &["read"])).await;
    let b = e.profile("bob", &rule("kv/data/app/*", &["read"])).await;
    let path = format!("auth/token/lookup/{b}");
    assert!(e.req(&e.root, Op::Read, &path).await.is_ok(), "control: the path is live for root");
    assert!(e.refused(&a, Op::Read, &path).await, "lookup of someone else's token needs its own grant");
});

bv_test!(c06_a_user_cannot_revoke_another_token_without_a_grant, |e| {
    let a = e.profile("alice", &rule("kv/data/app/*", &["read"])).await;
    let b = e.profile("bob", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&a, Op::Write, &format!("auth/token/revoke/{b}"), None, None).await;
    assert!(matches!(r, Err(RvError::ErrPermissionDenied)), "{r:?}");
    assert!(e.can_read(&b, "kv/data/app/db").await, "bob's token must survive");
});

bv_test!(c07_token_create_without_a_grant_is_refused, |e| {
    let t = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&t, Op::Write, "auth/token/create", Some(json!({ "policies": ["default"] })), None).await;
    assert!(matches!(r, Err(RvError::ErrPermissionDenied)), "{r:?}");
});

bv_test!(c08_a_child_with_a_subset_of_the_parents_policies_works, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let mint = format!("{}{}", rule("auth/token/create", &["create", "update"]), rule("kv/data/team/*", &["read"]));
    e.policy("p-minter", &mint).await;
    let t = e.user("minter", "p-app,p-minter").await;
    let r = e.req_with(&t, Op::Write, "auth/token/create", Some(json!({ "policies": ["p-app"] })), None).await;
    let child = r.unwrap().unwrap().auth.unwrap().client_token;
    assert!(e.can_read(&child, "kv/data/app/db").await);
    assert!(e.refused(&child, Op::Read, "kv/data/team/a/secret").await, "the child got only what it asked for");
});

bv_test!(c09_a_child_cannot_be_minted_with_a_policy_the_parent_lacks, |e| {
    e.policy("p-minter", &rule("auth/token/create", &["create", "update"])).await;
    e.policy("p-secret", &rule("kv/data/admin/*", &["read"])).await;
    let t = e.user("minter", "p-minter").await;
    let r = e.req_with(&t, Op::Write, "auth/token/create", Some(json!({ "policies": ["p-secret"] })), None).await;
    if let Some(child) = r.ok().flatten().and_then(|r| r.auth).map(|a| a.client_token) {
        assert!(
            e.refused(&child, Op::Read, "kv/data/admin/root-secret").await,
            "privilege escalation: a token minted a child holding a policy the parent does not"
        );
    }
});

bv_test!(c10_a_child_cannot_carry_the_root_policy, |e| {
    e.policy("p-minter", &rule("auth/token/create", &["create", "update"])).await;
    let t = e.user("minter", "p-minter").await;
    let r = e.req_with(&t, Op::Write, "auth/token/create", Some(json!({ "policies": ["root"] })), None).await;
    if let Some(child) = r.ok().flatten().and_then(|r| r.auth).map(|a| a.client_token) {
        assert!(e.refused(&child, Op::Read, "kv/data/admin/root-secret").await, "root policy leaked through create");
    }
});

bv_test!(c11_revoking_a_parent_revokes_its_children, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    e.policy("p-minter", &rule("auth/token/create", &["create", "update"])).await;
    let t = e.user("minter", "p-app,p-minter").await;
    let r = e.req_with(&t, Op::Write, "auth/token/create", Some(json!({ "policies": ["p-app"] })), None).await;
    let child = r.unwrap().unwrap().auth.unwrap().client_token;
    assert!(e.can_read(&child, "kv/data/app/db").await, "control");
    e.req_with(&t, Op::Write, "auth/token/revoke-self", None, None).await.unwrap();
    assert!(e.req(&child, Op::Read, "kv/data/app/db").await.is_err(), "orphaned children must not outlive the parent");
});

// D. FerroGate machine tokens and the server-wide gate

bv_test!(d01_gate_off_a_plain_user_token_works, |e| {
    let t = e.profile("usr-u", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
});

bv_test!(d02_gate_on_a_plain_user_token_is_refused_even_with_a_good_policy, |e| {
    let t = e.profile("usr-u", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control: allowed before the gate");
    e.gate(true).await;
    assert!(e.req(&t, Op::Read, "kv/data/app/db").await.is_err(), "no machine identity, no access");
    assert!(e.req(&t, Op::Read, "auth/token/lookup-self").await.is_err());
});

bv_test!(d03_gate_on_root_stays_exempt, |e| {
    e.gate(true).await;
    assert!(e.can_read(&e.root, "kv/data/app/db").await);
});

bv_test!(d04_gate_on_a_machine_token_passes_the_gate, |e| {
    let m = e.machine("host1", "default").await;
    e.gate(true).await;
    assert!(e.can_read(&m.token, "auth/token/lookup-self").await);
});

bv_test!(d05_gate_on_a_machine_token_is_still_subject_to_policy, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "p-app").await;
    e.gate(true).await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await, "control: the machine grant is live");
    assert!(e.refused(&m.token, Op::Read, "kv/data/admin/root-secret").await, "the gate is not a grant");
});

bv_test!(d06_a_machine_without_policies_gets_nothing_beyond_default, |e| {
    let m = e.machine("bare", "").await;
    assert!(e.can_read(&m.token, "auth/token/lookup-self").await);
    assert!(e.refused(&m.token, Op::Read, "kv/data/app/db").await);
});

bv_test!(d07_machine_policy_deny_wins, |e| {
    e.policy("p-all", &rule("kv/data/*", &["read"])).await;
    e.policy("p-noadmin", &rule("kv/data/admin/*", &["deny"])).await;
    let m = e.machine("host1", "p-all,p-noadmin").await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await);
    assert!(e.refused(&m.token, Op::Read, "kv/data/admin/root-secret").await);
});

bv_test!(d08_machine_read_only_policy_cannot_write, |e| {
    e.policy("p-ro", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "p-ro").await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await);
    assert!(e.refused(&m.token, Op::Write, "kv/data/app/db").await);
});

bv_test!(d09_two_machines_with_different_policies_stay_isolated, |e| {
    e.policy("p-a", &rule("kv/data/team/a/*", &["read"])).await;
    e.policy("p-b", &rule("kv/data/team/b/*", &["read"])).await;
    let ma = e.machine("host-a", "p-a").await;
    let mb = e.machine("host-b", "p-b").await;
    assert!(e.can_read(&ma.token, "kv/data/team/a/secret").await);
    assert!(e.can_read(&mb.token, "kv/data/team/b/secret").await);
    assert!(e.refused(&ma.token, Op::Read, "kv/data/team/b/secret").await);
    assert!(e.refused(&mb.token, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(d10_a_pending_machine_receives_no_token, |e| {
    let m = e.material("pending");
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_none());
});

bv_test!(d11_a_rejected_machine_receives_no_token, |e| {
    let m = e.material("rejected");
    e.register(&m).await;
    e.root_write(&format!("auth/ferrogate/machines/{}/reject", m.id), json!({})).await;
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_none());
});

bv_test!(d12_a_revoked_machine_cannot_log_in_again, |e| {
    let m = e.machine("host1", "default").await;
    e.root_write(&format!("auth/ferrogate/machines/{}/revoke", m.id), json!({})).await;
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_none());
});

bv_test!(d13_a_token_signed_by_an_unknown_key_is_refused, |e| {
    let (rogue, _) = CompositeSecretKey::generate().unwrap();
    let ed = SigningKey::from_bytes(&[42u8; 32]);
    let (proof, jkt) = e.mint_dpop(&ed, "POST", AUD, now_secs());
    let jws = e.mint_child(&rogue, "spiffe://ferrogate.test/host/rogue", AUD, &jkt, now_secs(), now_secs() + 3600);
    assert!(Env::token_of(e.ferro_login(&jws, Some(&proof), None).await).is_none());
});

bv_test!(d14_an_expired_child_token_is_refused, |e| {
    let ed = SigningKey::from_bytes(&[43u8; 32]);
    let (proof, jkt) = e.mint_dpop(&ed, "POST", AUD, now_secs());
    let iss = "spiffe://ferrogate.test/host/stale";
    let jws = e.mint_child(&e.sk, iss, AUD, &jkt, now_secs() - 7200, now_secs() - 3600);
    assert!(Env::token_of(e.ferro_login(&jws, Some(&proof), None).await).is_none());
});

bv_test!(d15_a_token_minted_for_another_audience_is_refused, |e| {
    let ed = SigningKey::from_bytes(&[44u8; 32]);
    let (proof, jkt) = e.mint_dpop(&ed, "POST", AUD, now_secs());
    let iss = "spiffe://ferrogate.test/host/aud";
    let jws = e.mint_child(&e.sk, iss, "https://elsewhere.example.com", &jkt, now_secs(), now_secs() + 3600);
    assert!(Env::token_of(e.ferro_login(&jws, Some(&proof), None).await).is_none());
});

bv_test!(d16_a_dpop_proof_from_a_different_key_is_refused, |e| {
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "default").await;
    let other = SigningKey::from_bytes(&[99u8; 32]);
    let (stolen_proof, _) = e.mint_dpop(&other, "POST", AUD, now_secs());
    assert!(
        Env::token_of(e.ferro_login(&m.jws, Some(&stolen_proof), None).await).is_none(),
        "the proof must be bound to the token's `cnf.jkt`"
    );
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_some(), "control");
});

bv_test!(d17_a_machine_token_cannot_write_policies_without_a_grant, |e| {
    let m = e.machine("host1", "default").await;
    let body = json!({ "policy": rule("*", &["read"]) });
    let r = e.req_with(&m.token, Op::Write, "sys/policy/evil", Some(body), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
});

bv_test!(d18_a_child_of_a_machine_token_does_not_inherit_the_machine_identity, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    e.policy("p-mint", &rule("auth/token/create", &["create", "update"])).await;
    let m = e.machine("host1", "p-app,p-mint").await;
    let r = e.req_with(&m.token, Op::Write, "auth/token/create", Some(json!({ "policies": ["p-app"] })), None).await;
    let child = r.unwrap().unwrap().auth.unwrap().client_token;
    assert!(e.can_read(&child, "kv/data/app/db").await, "control: before the gate the child reads");
    e.gate(true).await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await, "the machine itself passes the gate");
    assert!(e.req(&child, Op::Read, "kv/data/app/db").await.is_err(), "identity is never inherited by descent");
});

bv_test!(d19_gate_toggled_off_restores_plain_user_access, |e| {
    let t = e.profile("usr-u", &rule("kv/data/app/*", &["read"])).await;
    e.gate(true).await;
    assert!(e.req(&t, Op::Read, "kv/data/app/db").await.is_err());
    e.gate(false).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
});

bv_test!(d20_gate_on_user_login_endpoints_stay_reachable, |e| {
    e.user("carol", "").await;
    e.gate(true).await;
    assert!(
        Env::token_of(e.user_login("carol", PASSWORD).await).is_some(),
        "you must be able to log in to obtain a token at all"
    );
});

bv_test!(d21_gate_on_a_user_token_is_refused_on_every_protected_path, |e| {
    let hcl = format!("{}{}", rule("kv/data/*", &["read", "create", "update"]), rule("sys/mounts", &["read"]));
    let t = e.profile("usr-u", &hcl).await;
    e.gate(true).await;
    for (op, path) in [(Op::Read, "kv/data/app/db"), (Op::Write, "kv/data/app/new"), (Op::Read, "sys/mounts")] {
        assert!(e.req(&t, op, path).await.is_err(), "{path} must need a machine identity");
    }
});

bv_test!(d22_gate_flag_round_trips_through_config, |e| {
    e.gate(true).await;
    let r = e.req(&e.root, Op::Read, "auth/ferrogate/config").await.unwrap().unwrap();
    assert_eq!(r.data.unwrap()["require_machine_identity"], true);
    e.gate(false).await;
    let r = e.req(&e.root, Op::Read, "auth/ferrogate/config").await.unwrap().unwrap();
    assert_eq!(r.data.unwrap()["require_machine_identity"], false);
});

bv_test!(d23_the_requirement_endpoint_is_public_and_reflects_the_gate, |e| {
    e.gate(true).await;
    let r = e.req(Env::anon(), Op::Read, "auth/ferrogate/requirement").await.unwrap().unwrap();
    assert_eq!(r.data.unwrap()["require_machine_identity"], true);
});

bv_test!(d24_machine_ids_are_stable_and_distinct, |e| {
    let a = e.material("same");
    let b = e.material("same");
    let c = e.material("other");
    assert_eq!(a.id, b.id, "the id is derived from the SPIFFE id alone");
    assert_ne!(a.id, c.id);
    assert_eq!(a.id.len(), 64);
    assert_eq!(a.iss, b.iss);
});

bv_test!(d25_a_machine_token_revoked_by_itself_is_refused_afterwards, |e| {
    let m = e.machine("host1", "default").await;
    assert!(e.can_read(&m.token, "auth/token/lookup-self").await);
    e.req_with(&m.token, Op::Write, "auth/token/revoke-self", None, None).await.unwrap();
    assert!(e.req(&m.token, Op::Read, "auth/token/lookup-self").await.is_err());
});

// E. combined machine + user binding

bv_test!(e01_bound_token_carries_only_the_intersection, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    e.policy("p-team", &rule("kv/data/team/*", &["read"])).await;
    e.policy("p-pub", &rule("kv/data/public/*", &["read"])).await;
    let mut m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app,p-team").await;
    let u = e.user("alice", "p-app,p-pub").await;
    m.token = Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some(&u)).await).expect("combined login");
    assert!(e.can_read(&m.token, "kv/data/app/db").await, "in both: granted");
    assert!(e.refused(&m.token, Op::Read, "kv/data/team/a/secret").await, "machine-only: dropped");
    assert!(e.refused(&m.token, Op::Read, "kv/data/public/readme").await, "user-only: dropped");
});

bv_test!(e02_the_user_token_is_consumed_by_binding, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app").await;
    let u = e.user("alice", "p-app").await;
    assert!(e.can_read(&u, "kv/data/app/db").await, "control: live before binding");
    Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some(&u)).await).unwrap();
    assert!(e.req(&u, Op::Read, "kv/data/app/db").await.is_err(), "a bound user token must not stay usable");
});

bv_test!(e03_require_user_token_refuses_a_bare_machine_login, |e| {
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "default").await;
    e.ferro_config(json!({ "require_user_token": true })).await;
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_none());
});

bv_test!(e04_require_user_token_accepts_a_login_with_a_user, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app").await;
    e.ferro_config(json!({ "require_user_token": true })).await;
    let u = e.user("alice", "p-app").await;
    let t = Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some(&u)).await).expect("combined login");
    assert!(e.can_read(&t, "kv/data/app/db").await);
});

bv_test!(e05_a_user_with_no_overlap_gets_no_data_access, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    e.policy("p-team", &rule("kv/data/team/*", &["read"])).await;
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app").await;
    let u = e.user("alice", "p-team").await;
    let t = Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some(&u)).await).expect("combined login");
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await);
    assert!(e.refused(&t, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(e06_a_bogus_user_token_does_not_widen_the_machine_token, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app").await;
    let t = Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some("hvs.not-a-real-user-token")).await);
    if let Some(t) = t {
        assert!(
            e.refused(&t, Op::Read, "kv/data/app/db").await,
            "an unverifiable user_token must not silently fall back to the machine's full policies"
        );
    }
});

bv_test!(e07_a_machine_token_cannot_stand_in_for_the_user_token, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m1 = e.machine("host1", "p-app").await;
    let m2 = e.material("host2");
    e.register(&m2).await;
    e.approve(&m2, "p-app").await;
    let t = Env::token_of(e.ferro_login(&m2.jws, Some(&m2.proof), Some(&m1.token)).await);
    if let Some(t) = t {
        assert!(e.refused(&t, Op::Read, "kv/data/admin/root-secret").await);
    }
});

bv_test!(e08_gate_on_a_combined_token_passes_the_gate, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.material("host1");
    e.register(&m).await;
    e.approve(&m, "p-app").await;
    let u = e.user("alice", "p-app").await;
    let t = Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), Some(&u)).await).unwrap();
    e.gate(true).await;
    assert!(e.can_read(&t, "kv/data/app/db").await);
});

// F. AppRole / AppID with a machine token

bv_test!(f01_login_without_a_machine_token_is_refused_by_default, |e| {
    e.role("svc", "default", json!({})).await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, None, None).await.is_err());
});

bv_test!(f02_login_with_a_bound_machine_token_succeeds, |e| {
    let m = e.machine("host1", "default").await;
    assert!(e.appid("svc", "default", &m, "").await.is_some(), "a valid secret_id plus a bound machine must log in");
});

bv_test!(f03_login_with_an_unbound_machine_token_is_refused, |e| {
    let bound = e.machine("host1", "default").await;
    let other = e.machine("host2", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &bound, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&other.token), None).await.is_err());
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&bound.token), None).await.is_ok(), "control");
});

bv_test!(f04_a_garbage_machine_token_is_refused, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some("hvs.garbage"), None).await.is_err());
});

bv_test!(f05_the_root_token_is_not_a_machine_token, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&e.root), None).await.is_err());
});

bv_test!(f06_a_userpass_token_is_not_a_machine_token, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let user = e.user("alice", "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&user), None).await.is_err(), "only FerroGate-issued tokens qualify");
});

bv_test!(f07_a_wrong_secret_id_is_refused_even_with_a_bound_machine, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    assert!(e.appid_login("svc", "not-the-secret-id", Some(&m.token), None).await.is_err());
});

bv_test!(f08_a_wrong_role_id_is_refused, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    let mut r = Request::new("auth/approle/login");
    r.operation = Operation::Write;
    r.body = json!({ "role_id": "nonexistent-id", "secret_id": sid, "machine_token": m.token }).as_object().cloned();
    assert!(e.core.handle_request(&mut r).await.is_err());
});

bv_test!(f09_a_single_use_secret_id_cannot_be_replayed, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({ "secret_id_num_uses": 1 })).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_ok(), "control: first use");
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err(), "second use must fail");
});

bv_test!(f10_unbinding_the_machine_refuses_the_next_login, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_ok(), "control");
    e.root_delete(&format!("auth/approle/role/svc/machine/{}", m.id)).await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f11_several_machines_may_be_bound_to_one_role, |e| {
    let m1 = e.machine("host1", "default").await;
    let m2 = e.machine("host2", "default").await;
    let m3 = e.machine("host3", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m1, "").await;
    e.bind("svc", &m2, "").await;
    for m in [&m1, &m2] {
        let sid = e.secret_id("svc", None).await;
        assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_ok());
    }
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m3.token), None).await.is_err(), "the third is not bound");
});

bv_test!(f12_a_machine_bound_to_one_role_cannot_log_into_another, |e| {
    let m = e.machine("host1", "default").await;
    e.role("alpha", "default", json!({})).await;
    e.role("beta", "default", json!({})).await;
    e.bind("alpha", &m, "").await;
    let sid = e.secret_id("alpha", None).await;
    assert!(e.appid_login("alpha", &sid, Some(&m.token), None).await.is_ok(), "control");
    let sid = e.secret_id("beta", None).await;
    assert!(e.appid_login("beta", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f13_the_appid_token_is_bound_by_its_role_policies, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let auth = e.appid("svc", "p-app", &m, "").await.expect("login");
    assert!(e.can_read(&auth.client_token, "kv/data/app/db").await);
    assert!(e.refused(&auth.client_token, Op::Read, "kv/data/admin/root-secret").await);
    assert!(e.refused(&auth.client_token, Op::Write, "kv/data/app/db").await);
});

bv_test!(f14_the_machine_tokens_own_policies_do_not_flow_into_the_appid_token, |e| {
    e.policy("p-team", &rule("kv/data/team/*", &["read"])).await;
    let m = e.machine("host1", "p-team").await;
    let auth = e.appid("svc", "default", &m, "").await.expect("login");
    assert!(e.can_read(&m.token, "kv/data/team/a/secret").await, "control: the machine itself may");
    assert!(e.refused(&auth.client_token, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(f15_the_appid_token_is_stamped_with_the_machine_identity, |e| {
    let m = e.machine("host1", "default").await;
    let auth = e.appid("svc", "default", &m, "").await.expect("login");
    assert_eq!(auth.metadata.get("spiffe_id").map(String::as_str), Some(m.iss.as_str()));
    assert_eq!(auth.metadata.get("machine_id").map(String::as_str), Some(m.id.as_str()));
});

bv_test!(f16_a_bypass_role_logs_in_without_a_machine, |e| {
    e.role("svc", "default", json!({ "bypass_machine_binding": true })).await;
    let sid = e.secret_id("svc", None).await;
    assert!(Env::auth_of(e.appid_login("svc", &sid, None, None).await).is_some());
});

bv_test!(f17_a_bypass_role_still_needs_a_valid_secret_id, |e| {
    e.role("svc", "default", json!({ "bypass_machine_binding": true })).await;
    assert!(e.appid_login("svc", "forged", None, None).await.is_err());
});

bv_test!(f18_a_bypass_role_does_not_exempt_other_roles, |e| {
    e.role("free", "default", json!({ "bypass_machine_binding": true })).await;
    e.role("strict", "default", json!({})).await;
    let sid = e.secret_id("strict", None).await;
    assert!(e.appid_login("strict", &sid, None, None).await.is_err());
});

bv_test!(f19_the_approle_gate_off_needs_no_machine_but_still_a_secret_id, |e| {
    e.root_write("auth/approle/config", json!({ "require_machine": false })).await;
    e.role("svc", "default", json!({})).await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, None, None).await.is_ok());
    assert!(e.appid_login("svc", "forged", None, None).await.is_err());
});

bv_test!(f20_the_approle_gate_defaults_to_on, |e| {
    let r = e.req(&e.root, Op::Read, "auth/approle/config").await.unwrap().unwrap();
    assert_eq!(r.data.unwrap()["require_machine"], true);
});

bv_test!(f21_a_secret_id_scoped_to_prod_reads_prod_only, |e| {
    e.policy("p-kv", &rule("kv/data/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let t = e.appid_token("svc", &m, "", Some("prod")).await;
    let d = e.read_env(&t, Some("prod")).await.unwrap().unwrap().data.unwrap();
    assert_eq!(d["data"]["host"], "db.prod");
    assert!(matches!(e.read_env(&t, Some("staging")).await, Err(RvError::ErrPermissionDenied)));
    assert!(
        matches!(e.read_env(&t, None).await, Err(RvError::ErrPermissionDenied)),
        "no base secret for a scoped token"
    );
});

bv_test!(f22_a_machine_binding_scoped_by_glob, |e| {
    e.policy("p-kv", &rule("kv/data/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let t = e.appid_token("svc", &m, "prod-*", None).await;
    assert_eq!(e.read_env(&t, Some("prod-1")).await.unwrap().unwrap().data.unwrap()["data"]["host"], "db.prod1");
    assert!(matches!(e.read_env(&t, Some("dev")).await, Err(RvError::ErrPermissionDenied)));
    assert!(
        matches!(e.read_env(&t, Some("prod")).await, Err(RvError::ErrPermissionDenied)),
        "`prod-*` does not match `prod`"
    );
});

bv_test!(f23_secret_and_machine_scopes_intersect, |e| {
    e.policy("p-kv", &rule("kv/data/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let t = e.appid_token("svc", &m, "prod", Some("prod,staging")).await;
    assert!(e.read_env(&t, Some("prod")).await.is_ok(), "in both scopes");
    assert!(
        matches!(e.read_env(&t, Some("staging")).await, Err(RvError::ErrPermissionDenied)),
        "the machine scope excludes it"
    );
});

bv_test!(f24_an_unscoped_appid_reads_any_environment_and_the_base, |e| {
    e.policy("p-kv", &rule("kv/data/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let t = e.appid_token("svc", &m, "", None).await;
    assert!(e.read_env(&t, None).await.is_ok());
    assert!(e.read_env(&t, Some("staging")).await.is_ok());
});

bv_test!(f25_an_env_scoped_token_cannot_escape_through_token_create, |e| {
    let hcl = format!("{}{}", rule("kv/data/*", &["read"]), rule("auth/token/create", &["create", "update"]));
    e.policy("p-kv", &hcl).await;
    let m = e.machine("host1", "default").await;
    let parent = e.appid_token("svc", &m, "", Some("prod")).await;
    let r = e.req_with(&parent, Op::Write, "auth/token/create", Some(json!({ "policies": ["p-kv"] })), None).await;
    let child = r.unwrap().unwrap().auth.unwrap().client_token;
    assert!(e.read_env(&child, Some("prod")).await.is_ok());
    assert!(matches!(e.read_env(&child, None).await, Err(RvError::ErrPermissionDenied)));
});

bv_test!(f26_an_appid_token_with_a_machine_identity_passes_the_server_gate, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "default").await;
    let auth = e.appid("svc", "p-app", &m, "").await.expect("login");
    e.gate(true).await;
    assert!(e.can_read(&auth.client_token, "kv/data/app/db").await);
});

bv_test!(f27_a_bypassed_appid_token_passes_the_server_gate, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    e.role("svc", "p-app", json!({ "bypass_machine_binding": true })).await;
    let sid = e.secret_id("svc", None).await;
    let t = Env::auth_of(e.appid_login("svc", &sid, None, None).await).expect("login").client_token;
    e.gate(true).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "the per-role exemption must carry onto the token");
});

bv_test!(f28_a_destroyed_secret_id_cannot_log_in, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    e.root_write("auth/approle/role/svc/secret-id/destroy", json!({ "secret_id": sid })).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f29_a_deleted_role_cannot_log_in, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    e.root_delete("auth/approle/role/svc").await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f30_a_revoked_machine_token_cannot_be_presented, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    e.req_with(&m.token, Op::Write, "auth/token/revoke-self", None, None).await.unwrap();
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f31_a_machine_revoked_in_ferrogate_cannot_front_an_appid_login, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    e.root_write(&format!("auth/ferrogate/machines/{}/revoke", m.id), json!({})).await;
    assert!(
        e.appid_login("svc", &sid, Some(&m.token), None).await.is_err(),
        "an AppID login must re-check that the machine is still approved"
    );
});

bv_test!(f32_source_ip_filter_applies_on_top_of_the_machine_check, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({ "bound_source_ips": "10.0.0.0/8" })).await;
    e.bind("svc", &m, "").await;
    let from = |ip: &str| Some(Connection { peer_addr: format!("{ip}:41222"), ..Default::default() });
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), from("10.1.2.3")).await.is_ok(), "control");
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), from("203.0.113.9")).await.is_err());
});

bv_test!(f33_source_ip_filter_fails_closed_without_connection_info, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({ "bound_source_ips": "10.0.0.0/8" })).await;
    e.bind("svc", &m, "").await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_err());
});

bv_test!(f34_two_appids_with_different_policies_stay_isolated, |e| {
    e.policy("p-a", &rule("kv/data/team/a/*", &["read"])).await;
    e.policy("p-b", &rule("kv/data/team/b/*", &["read"])).await;
    let m1 = e.machine("host1", "default").await;
    let m2 = e.machine("host2", "default").await;
    let a = e.appid("svc-a", "p-a", &m1, "").await.expect("login a").client_token;
    let b = e.appid("svc-b", "p-b", &m2, "").await.expect("login b").client_token;
    assert!(e.can_read(&a, "kv/data/team/a/secret").await && e.can_read(&b, "kv/data/team/b/secret").await);
    assert!(e.refused(&a, Op::Read, "kv/data/team/b/secret").await);
    assert!(e.refused(&b, Op::Read, "kv/data/team/a/secret").await);
});

bv_test!(f35_the_appid_token_cannot_write_policies, |e| {
    let m = e.machine("host1", "default").await;
    let auth = e.appid("svc", "default", &m, "").await.expect("login");
    let body = json!({ "policy": rule("*", &["read"]) });
    let r = e.req_with(&auth.client_token, Op::Write, "sys/policy/evil", Some(body), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
});

bv_test!(f36_the_machine_binding_survives_a_role_update, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &m, "").await;
    e.role("svc", "default", json!({ "token_ttl": 500 })).await;
    let sid = e.secret_id("svc", None).await;
    assert!(
        e.appid_login("svc", &sid, Some(&m.token), None).await.is_ok(),
        "updating the role must not drop its machines"
    );
});

bv_test!(f37_binding_by_spiffe_id_resolves_to_the_same_machine, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    e.root_write("auth/approle/role/svc/machine/", json!({ "spiffe_id": m.iss })).await;
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&m.token), None).await.is_ok());
});

bv_test!(f38_binding_without_any_identifier_is_rejected, |e| {
    e.role("svc", "default", json!({})).await;
    let r = e
        .req_with(&e.root, Op::Write, "auth/approle/role/svc/machine/", Some(json!({ "environments": "prod" })), None)
        .await;
    assert!(r.is_err());
});

// G. adversarial paths and cross-checks

bv_test!(g01_dot_dot_does_not_escape_a_scoped_grant, |e| {
    let t = e.profile("scoped", &rule("kv/data/app/*", &["read"])).await;
    let got = e.secret(&t, "kv/data/app/../admin/root-secret").await;
    assert_ne!(got.as_deref(), Some("admin-secret"), "path traversal reached a secret outside the grant");
});

bv_test!(g02_double_slash_does_not_escape_a_scoped_grant, |e| {
    let t = e.profile("scoped", &rule("kv/data/app/*", &["read"])).await;
    let got = e.secret(&t, "kv/data//admin/root-secret").await;
    assert_ne!(got.as_deref(), Some("admin-secret"));
});

bv_test!(g03_an_exact_rule_does_not_widen_to_its_neighbours, |e| {
    let t = e.profile("exact", &rule("kv/data/app/db", &["read"])).await;
    assert!(e.can_read(&t, "kv/data/app/db").await, "control");
    assert!(e.secret(&t, "kv/data/app/api").await.is_none());
});

bv_test!(g04_policy_paths_are_case_sensitive, |e| {
    let t = e.profile("case", &rule("kv/data/App/*", &["read"])).await;
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await, "`App/*` must not match `app/...`");
});

bv_test!(g05_a_glob_in_the_middle_of_a_path_is_not_a_wildcard, |e| {
    let t = e.profile("mid", &rule("kv/data/*/db", &["read"])).await;
    assert!(e.refused(&t, Op::Read, "kv/data/app/db").await, "`*` is a trailing glob only; use `+` for a segment");
});

bv_test!(g06_a_denied_request_is_a_permission_error_not_a_server_error, |e| {
    let t = e.profile("usr-u", &rule("kv/data/app/*", &["read"])).await;
    for (op, path) in [
        (Op::Read, "kv/data/admin/root-secret"),
        (Op::Write, "kv/data/admin/root-secret"),
        (Op::Delete, "kv/data/admin/root-secret"),
        (Op::List, "kv/metadata/admin/"),
    ] {
        assert!(e.refused(&t, op, path).await, "{path} must be a typed permission refusal");
    }
});

bv_test!(g07_a_denied_write_changes_nothing, |e| {
    let t = e.profile("usr-ro", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.refused(&t, Op::Write, "kv/data/app/db").await);
    assert_eq!(e.secret(&e.root, "kv/data/app/db").await.as_deref(), Some("db-secret"), "the secret was overwritten");
});

bv_test!(g08_a_denied_delete_leaves_the_secret_readable, |e| {
    let t = e.profile("usr-ro", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.refused(&t, Op::Delete, "kv/data/app/db").await);
    assert_eq!(e.secret(&t, "kv/data/app/db").await.as_deref(), Some("db-secret"));
});

bv_test!(g09_a_user_cannot_grant_itself_more_by_rewriting_its_own_user, |e| {
    e.policy("p-ro", &rule("kv/data/app/*", &["read"])).await;
    let t = e.user("self", "p-ro").await;
    let body = json!({ "password": PASSWORD, "token_policies": "root" });
    let r = e.req_with(&t, Op::Write, "auth/userpass/users/self", Some(body), None).await;
    assert!(matches!(r, Err(RvError::ErrPermissionDenied)), "{r:?}");
});

bv_test!(g10_a_machine_cannot_approve_itself_or_a_peer, |e| {
    let m = e.material("sneaky");
    e.register(&m).await;
    let t = e.machine("host1", "default").await;
    let path = format!("auth/ferrogate/machines/{}/approve", m.id);
    let r = e.req_with(&t.token, Op::Write, &path, Some(json!({ "policies": "default" })), None).await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
    assert!(Env::token_of(e.ferro_login(&m.jws, Some(&m.proof), None).await).is_none());
});

bv_test!(g11_a_user_cannot_bind_a_machine_to_a_role, |e| {
    let m = e.machine("host1", "default").await;
    e.role("svc", "default", json!({})).await;
    let u = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r =
        e.req_with(&u, Op::Write, "auth/approle/role/svc/machine/", Some(json!({ "machine_id": m.id })), None).await;
    assert!(matches!(r, Err(RvError::ErrPermissionDenied)), "{r:?}");
});

bv_test!(g12_a_user_cannot_flip_the_approle_gate, |e| {
    let u = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    let r = e.req_with(&u, Op::Write, "auth/approle/config", Some(json!({ "require_machine": false })), None).await;
    assert!(matches!(r, Err(RvError::ErrPermissionDenied)), "{r:?}");
    let cfg = e.req(&e.root, Op::Read, "auth/approle/config").await.unwrap().unwrap();
    assert_eq!(cfg.data.unwrap()["require_machine"], true);
});

bv_test!(g13_a_machine_cannot_turn_off_the_machine_identity_gate, |e| {
    let m = e.machine("host1", "default").await;
    e.gate(true).await;
    let r = e
        .req_with(
            &m.token,
            Op::Write,
            "auth/ferrogate/config",
            Some(json!({ "require_machine_identity": false })),
            None,
        )
        .await;
    assert!(r.is_err(), "a caller without sudo on a root-protected path must be refused: {r:?}");
    let cfg = e.req(&e.root, Op::Read, "auth/ferrogate/config").await.unwrap().unwrap();
    assert_eq!(cfg.data.unwrap()["require_machine_identity"], true);
});

bv_test!(g14_a_user_cannot_list_the_ferrogate_machine_registry, |e| {
    e.machine("host1", "default").await;
    let u = e.profile("plain", &rule("kv/data/app/*", &["read"])).await;
    assert!(e.req(&u, Op::List, "auth/ferrogate/machines/").await.is_err());
});

bv_test!(g15_a_machine_token_tracks_edits_to_its_policy, |e| {
    e.policy("p-live", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "p-live").await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await);
    e.policy("p-live", &rule("kv/data/public/*", &["read"])).await;
    assert!(e.refused(&m.token, Op::Read, "kv/data/app/db").await, "a machine token must track policy edits");
    assert!(e.can_read(&m.token, "kv/data/public/readme").await);
});

bv_test!(g16_a_deleted_policy_stops_granting_to_a_machine_token, |e| {
    e.policy("p-gone", &rule("kv/data/app/*", &["read"])).await;
    let m = e.machine("host1", "p-gone").await;
    assert!(e.can_read(&m.token, "kv/data/app/db").await);
    e.root_delete("sys/policy/p-gone").await;
    assert!(e.refused(&m.token, Op::Read, "kv/data/app/db").await);
});

bv_test!(g17_gate_and_policy_must_both_pass, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let granted_machine = e.machine("m-ok", "p-app").await;
    let bare_machine = e.machine("m-bare", "default").await;
    let granted_user = e.user("u-ok", "p-app").await;
    let bare_user = e.user("u-bare", "").await;
    e.gate(true).await;
    assert!(e.can_read(&granted_machine.token, "kv/data/app/db").await, "machine + grant");
    assert!(e.req(&bare_machine.token, Op::Read, "kv/data/app/db").await.is_err(), "machine, no grant");
    assert!(e.req(&granted_user, Op::Read, "kv/data/app/db").await.is_err(), "grant, no machine");
    assert!(e.req(&bare_user, Op::Read, "kv/data/app/db").await.is_err(), "neither");
});

bv_test!(g18_appid_needs_machine_secret_and_policy_together, |e| {
    e.policy("p-app", &rule("kv/data/app/*", &["read"])).await;
    let good = e.machine("m-good", "default").await;
    let stranger = e.machine("m-stranger", "default").await;
    e.role("svc", "p-app", json!({})).await;
    e.bind("svc", &good, "").await;
    let sid = e.secret_id("svc", None).await;
    let t = Env::auth_of(e.appid_login("svc", &sid, Some(&good.token), None).await).expect("all hold");
    assert!(e.can_read(&t.client_token, "kv/data/app/db").await);
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, Some(&stranger.token), None).await.is_err(), "machine wrong");
    assert!(e.appid_login("svc", "wrong", Some(&good.token), None).await.is_err(), "secret wrong");
    assert!(e.appid_login("svc", "wrong", Some(&stranger.token), None).await.is_err(), "both wrong");
    let sid = e.secret_id("svc", None).await;
    assert!(e.appid_login("svc", &sid, None, None).await.is_err(), "machine absent");
});

bv_test!(g19_a_login_error_never_echoes_a_secret_id_or_token, |e| {
    let good = e.machine("m-good", "default").await;
    let stranger = e.machine("m-stranger", "default").await;
    e.role("svc", "default", json!({})).await;
    e.bind("svc", &good, "").await;
    let sid = e.secret_id("svc", None).await;
    let wrong_machine = e.appid_login("svc", &sid, Some(&stranger.token), None).await.unwrap_err().to_string();
    let wrong_secret = e.appid_login("svc", "wrong", Some(&good.token), None).await.unwrap_err().to_string();
    for msg in [&wrong_machine, &wrong_secret] {
        assert!(!msg.contains(&sid), "an error must never echo a secret_id: {msg}");
        assert!(!msg.contains(&good.token) && !msg.contains(&stranger.token), "nor a token: {msg}");
    }
});

bv_test!(g20_a_refusal_does_not_echo_the_callers_token, |e| {
    let t = e.profile("usr-u", &rule("kv/data/app/*", &["read"])).await;
    let msg = e.req(&t, Op::Read, "kv/data/admin/root-secret").await.unwrap_err().to_string();
    assert!(!msg.contains(&t), "a refusal must not echo the caller's token: {msg}");
});
