//! Every route the listener serves, as data.
//!
//! Phase 0 (the route inventory) and Phase 1.3 (routes as data, anonymous
//! surface as a golden file) of
//! `roadmaps/formal-verification-and-type-driven-security.md` (T31, S65).
//!
//! [`crate::init_service`] registers [`LISTENER`] and nothing else, and every
//! entry in it carries its [`RouteClass`]. A route that is registered is
//! therefore a route that is listed, with its class next to it where review can
//! see it. The tables themselves live with their handlers
//! (`sys/routes.rs`, `metrics_routes.rs`, …); this module holds the shapes, the
//! one builder that turns them into actix services, and the tests that pin
//! them:
//!
//! - `tests/golden/anonymous-routes.txt` — every route an anonymous caller can
//!   reach, with the written justification. Widening the unauthenticated
//!   surface means editing a file whose only purpose is to be reviewed.
//! - `tests/golden/route-inventory.txt` — the whole inventory: path, method,
//!   class, and the policy path each route is judged on.
//! - a text gate: no module other than this one and [`crate::authz`] calls
//!   actix's registration API directly, so a route cannot be added beside the
//!   tables.
//!
//! The constructors that tie a class to its registration are the `route!`
//! macro's arms: `privileged` registers through
//! [`crate::authz::privileged`], which refuses a handler without the witness;
//! every anonymous arm demands a justification string, and there is no arm
//! without one.

use actix_web::{
    http::{Method, StatusCode},
    web, FromRequest, Handler, HttpResponse, Responder, Route,
};

use crate::{
    authz::{DenialAudit, SysRoute},
    logical::Operation,
};

/// An HTTP method a route answers, as the inventory spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMethod {
    Get,
    Post,
    Put,
    Delete,
    /// The non-standard `LIST` verb the BastionVault clients use for
    /// `Operation::List`, matching the `/v1/{path:.*}` catch-all.
    List,
    /// Every method; the handler dispatches on it (the logical catch-all).
    Any,
}

impl RouteMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteMethod::Get => "GET",
            RouteMethod::Post => "POST",
            RouteMethod::Put => "PUT",
            RouteMethod::Delete => "DELETE",
            RouteMethod::List => "LIST",
            RouteMethod::Any => "ANY",
        }
    }

    /// The actix route guarded on this method.
    fn route(self) -> Route {
        match self {
            RouteMethod::Get => web::get(),
            RouteMethod::Post => web::post(),
            RouteMethod::Put => web::put(),
            RouteMethod::Delete => web::delete(),
            RouteMethod::List => web::method(list_method()),
            RouteMethod::Any => web::route(),
        }
    }
}

/// The `LIST` method token.
pub(crate) fn list_method() -> Method {
    Method::from_bytes(b"LIST").expect("LIST is a valid HTTP method token")
}

/// What a privileged route is judged on, read off its [`SysRoute`] marker.
#[derive(Debug, Clone, Copy)]
pub struct PrivilegedRoute {
    pub marker: &'static str,
    pub policy_path: &'static str,
    pub operation: Operation,
    pub denial: DenialAudit,
}

impl PrivilegedRoute {
    pub const fn of<R: SysRoute>(marker: &'static str) -> Self {
        Self { marker, policy_path: R::POLICY_PATH, operation: R::OPERATION, denial: R::DENIAL_AUDIT }
    }
}

/// How a route is authorized. The Phase 0 classes (`Privileged`, `Tiered`,
/// `PublicProbe`, `ClusterLocal`) plus the shapes the listener actually has
/// beyond `sys`: shims that hand a logical request to `Core::handle_request`,
/// routes that carry caller-chosen logical requests, and the signed webhook.
#[derive(Debug, Clone, Copy)]
pub enum RouteClass {
    /// Inline handler behind the [`crate::authz::Authorized`] witness: token
    /// plus ACL, before the body runs.
    Privileged(PrivilegedRoute),
    /// Shim that builds one logical request on `logical` and dispatches it
    /// through `Core::handle_request`, whose `pre_route` authorizes it.
    Routed { logical: &'static str },
    /// As `Routed`, onto a path the system backend lists in `unauth_paths`.
    RoutedUnauthenticated { logical: &'static str, justification: &'static str },
    /// Carries logical requests the caller chooses (the catch-all, batch,
    /// MCP); each is judged by `pre_route` on its own path.
    Dispatch { justification: &'static str },
    /// Anonymous minimum, authenticated full.
    Tiered { justification: &'static str },
    /// Deliberately anonymous.
    PublicProbe { justification: &'static str },
    /// A token, or a waiver judged on the socket peer (never on
    /// `X-Forwarded-For`).
    ClusterLocal { justification: &'static str },
    /// Authenticated by a signature over the raw body, not by a token.
    SignatureVerified { justification: &'static str },
}

impl RouteClass {
    pub fn label(&self) -> &'static str {
        match self {
            RouteClass::Privileged(_) => "privileged",
            RouteClass::Routed { .. } => "routed",
            RouteClass::RoutedUnauthenticated { .. } => "routed-unauthenticated",
            RouteClass::Dispatch { .. } => "dispatch",
            RouteClass::Tiered { .. } => "tiered",
            RouteClass::PublicProbe { .. } => "public-probe",
            RouteClass::ClusterLocal { .. } => "cluster-local",
            RouteClass::SignatureVerified { .. } => "signature-verified",
        }
    }

    /// False for every route an anonymous caller can reach — the set the
    /// anonymous-surface golden file lists.
    pub fn requires_token(&self) -> bool {
        matches!(self, RouteClass::Privileged(_) | RouteClass::Routed { .. })
    }

    pub fn justification(&self) -> Option<&'static str> {
        match self {
            RouteClass::Privileged(_) | RouteClass::Routed { .. } => None,
            RouteClass::RoutedUnauthenticated { justification, .. }
            | RouteClass::Dispatch { justification }
            | RouteClass::Tiered { justification }
            | RouteClass::PublicProbe { justification }
            | RouteClass::ClusterLocal { justification }
            | RouteClass::SignatureVerified { justification } => Some(justification),
        }
    }

    fn detail(&self) -> String {
        match self {
            RouteClass::Privileged(p) => {
                let denial = match p.denial {
                    DenialAudit::Recorded => "",
                    DenialAudit::NotRecorded => "; denial not audited",
                };
                format!("{} {} ({}{denial})", p.operation, p.policy_path, p.marker)
            }
            RouteClass::Routed { logical } => format!("-> {logical}"),
            RouteClass::RoutedUnauthenticated { logical, justification } => format!("-> {logical} -- {justification}"),
            other => format!("-- {}", other.justification().unwrap_or_default()),
        }
    }
}

/// One method on one resource. Built only by the `route!` macro, which ties
/// the class to the constructor that registers it; the registration gate test
/// rejects a `RouteSpec` literal written anywhere else.
pub struct RouteSpec {
    pub method: RouteMethod,
    pub class: RouteClass,
    pub(crate) register: fn() -> Route,
}

/// Per-resource request-body limit, set as resource app data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimit {
    /// actix's default (256 KiB for `web::Bytes`).
    ActixDefault,
    /// A `PayloadConfig` limit (`web::Bytes` / `String` extractors).
    Payload(usize),
    /// A `JsonConfig` limit (`web::Json` extractors).
    Json(usize),
}

/// What a resource answers for a method it has no route for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// actix's default.
    Default,
    /// An explicit empty `405`.
    MethodNotAllowed,
}

pub struct ResourceSpec {
    pub path: &'static str,
    pub body_limit: BodyLimit,
    pub fallback: Fallback,
    pub routes: &'static [RouteSpec],
}

/// A scope whose one route catches every path below it.
pub struct CatchAllSpec {
    pub scope: &'static str,
    pub path: &'static str,
    pub body_limit: BodyLimit,
    pub route: RouteSpec,
}

pub enum Surface {
    /// A `sys` scope: `prefix` plus the resources of each group, in order.
    Sys {
        prefix: &'static str,
        groups: &'static [&'static [ResourceSpec]],
    },
    /// Resources at absolute paths.
    Resources(&'static [ResourceSpec]),
    CatchAll(&'static CatchAllSpec),
}

/// `/v1/sys` and `/v2/sys` — [`crate::sys::init_sys_service`].
pub const SYS: &[Surface] = &[
    Surface::Sys { prefix: "/v1/sys", groups: &[crate::sys::routes::SHARED] },
    Surface::Sys { prefix: "/v2/sys", groups: &[crate::sys::routes::SHARED, crate::sys::routes::V2_ONLY] },
];

/// The signed Rustion webhook — [`crate::rustion_webhook::init_rustion_webhook_service`].
pub const RUSTION_WEBHOOK: &[Surface] = &[Surface::Resources(crate::rustion_webhook::RESOURCES)];

/// `/v2/mcp` and its token exchange — [`crate::mcp_routes::init_mcp_service`].
pub const MCP: &[Surface] = &[Surface::Resources(crate::mcp_routes::RESOURCES)];

/// The `/v1` and `/v2` logical catch-alls — [`crate::logical_routes::init_logical_service`].
pub const LOGICAL: &[Surface] =
    &[Surface::CatchAll(&crate::logical_routes::V1_CATCH_ALL), Surface::CatchAll(&crate::logical_routes::V2_CATCH_ALL)];

/// `/metrics` — [`crate::metrics_routes::init_metrics_service`].
pub const METRICS: &[Surface] = &[Surface::Resources(crate::metrics_routes::RESOURCES)];

/// The whole listener, in registration order. actix matches resources in
/// registration order, so order is part of the contract: the exact-path
/// webhook and MCP resources precede the `/v1` and `/v2` catch-alls they sit
/// inside.
pub static LISTENER: &[&[Surface]] = &[SYS, RUSTION_WEBHOOK, MCP, LOGICAL, METRICS];

/// Register the whole listener. [`crate::init_service`] is this.
pub(crate) fn register_listener(cfg: &mut web::ServiceConfig) {
    for surfaces in LISTENER {
        register(cfg, surfaces);
    }
}

/// Register `surfaces`, in order.
pub(crate) fn register(cfg: &mut web::ServiceConfig, surfaces: &[Surface]) {
    for surface in surfaces {
        match surface {
            Surface::Sys { prefix, groups } => {
                let mut scope = web::scope(prefix);
                for spec in groups.iter().flat_map(|group| group.iter()) {
                    scope = scope.service(build_resource(spec));
                }
                cfg.service(scope);
            }
            Surface::Resources(specs) => {
                for spec in specs.iter() {
                    cfg.service(build_resource(spec));
                }
            }
            Surface::CatchAll(spec) => {
                let scope = match spec.body_limit {
                    BodyLimit::ActixDefault => web::scope(spec.scope),
                    BodyLimit::Payload(limit) => {
                        web::scope(spec.scope).app_data(web::PayloadConfig::default().limit(limit))
                    }
                    BodyLimit::Json(limit) => web::scope(spec.scope).app_data(web::JsonConfig::default().limit(limit)),
                };
                cfg.service(scope.route(spec.path, (spec.route.register)()));
            }
        }
    }
}

fn build_resource(spec: &ResourceSpec) -> actix_web::Resource {
    let mut resource = match spec.body_limit {
        BodyLimit::ActixDefault => web::resource(spec.path),
        BodyLimit::Payload(limit) => web::resource(spec.path).app_data(web::PayloadConfig::default().limit(limit)),
        BodyLimit::Json(limit) => web::resource(spec.path).app_data(web::JsonConfig::default().limit(limit)),
    };
    for route in spec.routes {
        resource = resource.route((route.register)());
    }
    match spec.fallback {
        Fallback::Default => resource,
        Fallback::MethodNotAllowed => resource.default_service(web::route().to(method_not_allowed)),
    }
}

async fn method_not_allowed() -> HttpResponse {
    crate::response_error(StatusCode::METHOD_NOT_ALLOWED, "")
}

/// Register a route whose class is declared open — `public_probe`, `tiered`,
/// `cluster_local`, `routed`, `routed_unauthenticated`, `dispatch`. Reached
/// only through the `route!` arms that demand the class's justification.
pub(crate) fn open<H, Args>(method: RouteMethod, handler: H) -> Route
where
    H: Handler<Args>,
    Args: FromRequest + 'static,
    H::Output: Responder + 'static,
{
    method.route().to(handler)
}

/// One row of the inventory: a method on a full path pattern.
#[derive(Debug, Clone)]
pub struct InventoryEntry {
    pub method: RouteMethod,
    pub pattern: String,
    pub class: RouteClass,
}

/// Every (method, pattern) the listener serves, in registration order.
pub fn inventory() -> Vec<InventoryEntry> {
    let mut entries = Vec::new();
    let mut push = |prefix: &str, path: &str, route: &RouteSpec| {
        entries.push(InventoryEntry { method: route.method, pattern: format!("{prefix}{path}"), class: route.class });
    };
    for surface in LISTENER.iter().flat_map(|surfaces| surfaces.iter()) {
        match surface {
            Surface::Sys { prefix, groups } => {
                for spec in groups.iter().flat_map(|group| group.iter()) {
                    for route in spec.routes {
                        push(prefix, spec.path, route);
                    }
                }
            }
            Surface::Resources(specs) => {
                for spec in specs.iter() {
                    for route in spec.routes {
                        push("", spec.path, route);
                    }
                }
            }
            Surface::CatchAll(spec) => push(spec.scope, spec.path, &spec.route),
        }
    }
    entries
}

/// The anonymous surface, one line per route.
pub fn render_anonymous_surface(entries: &[InventoryEntry]) -> String {
    let mut out = String::from(
        "# Every route an anonymous caller can reach, and why. Generated from the route table\n\
         # (crates/bv-server/src/routes.rs); regenerate with BV_BLESS_GOLDEN=1 and review the diff.\n",
    );
    for e in entries.iter().filter(|e| !e.class.requires_token()) {
        out.push_str(&format!("{:<6} {} [{}] {}\n", e.method.as_str(), e.pattern, e.class.label(), e.class.detail()));
    }
    out
}

/// The whole inventory, one line per route.
pub fn render_inventory(entries: &[InventoryEntry]) -> String {
    let mut out = String::from(
        "# Every route the listener serves: method, pattern, class, and what it is judged on.\n\
         # Generated from the route table (crates/bv-server/src/routes.rs); regenerate with\n\
         # BV_BLESS_GOLDEN=1 and review the diff.\n",
    );
    for e in entries {
        out.push_str(&format!("{:<6} {} [{}] {}\n", e.method.as_str(), e.pattern, e.class.label(), e.class.detail()));
    }
    out
}

/// The actix method guard for a route that names one. No `Any` arm: a
/// privileged or witness-gated route always names its method.
macro_rules! http_method {
    (Get) => {
        ::actix_web::http::Method::GET
    };
    (Post) => {
        ::actix_web::http::Method::POST
    };
    (Put) => {
        ::actix_web::http::Method::PUT
    };
    (Delete) => {
        ::actix_web::http::Method::DELETE
    };
    (List) => {
        $crate::routes::list_method()
    };
}

/// One route-table entry. Each arm is a class, and each anonymous class
/// requires its justification.
macro_rules! route {
    (privileged $marker:ident: $method:ident => $handler:path) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::Privileged($crate::routes::PrivilegedRoute::of::<$marker>(stringify!(
                $marker
            ))),
            register: || $crate::authz::privileged::<$marker, _, _>($crate::routes::http_method!($method), $handler),
        }
    };
    (routed $method:ident => $handler:path, $logical:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::Routed { logical: $logical },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    (routed_unauthenticated $method:ident => $handler:path, $logical:literal, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::RoutedUnauthenticated { logical: $logical, justification: $why },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    (dispatch $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::Dispatch { justification: $why },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    (tiered $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::Tiered { justification: $why },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    (public_probe $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::PublicProbe { justification: $why },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    (cluster_local $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::ClusterLocal { justification: $why },
            register: || $crate::routes::open($crate::routes::RouteMethod::$method, $handler),
        }
    };
    // A token-or-waiver route whose gate is a witness, not a check in the
    // handler body: registration refuses a handler that does not take it.
    (cluster_local $witness:ident: $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::ClusterLocal { justification: $why },
            register: || $crate::authz::guarded::<$witness, _, _>($crate::routes::http_method!($method), $handler),
        }
    };
    (signature_verified $witness:ident: $method:ident => $handler:path, $why:literal) => {
        $crate::routes::RouteSpec {
            method: $crate::routes::RouteMethod::$method,
            class: $crate::routes::RouteClass::SignatureVerified { justification: $why },
            register: || $crate::authz::guarded::<$witness, _, _>($crate::routes::http_method!($method), $handler),
        }
    };
}

/// One resource: a path, its routes, and optionally a body limit and an
/// explicit 405 fallback.
macro_rules! resource {
    ($path:literal $(, body_limit: $limit:expr)? $(, fallback: $fallback:ident)? => [$($route:expr),+ $(,)?]) => {
        $crate::routes::ResourceSpec {
            path: $path,
            body_limit: $crate::routes::resource!(@limit $($limit)?),
            fallback: $crate::routes::resource!(@fallback $($fallback)?),
            routes: &[$($route),+],
        }
    };
    (@limit) => { $crate::routes::BodyLimit::ActixDefault };
    (@limit $limit:expr) => { $limit };
    (@fallback) => { $crate::routes::Fallback::Default };
    (@fallback $fallback:ident) => { $crate::routes::Fallback::$fallback };
}

pub(crate) use {http_method, resource, route};

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};

    use actix_web::{web, App, HttpRequest, HttpResponse};

    use super::{inventory, render_anonymous_surface, render_inventory, InventoryEntry, RouteClass};

    /// Every source file under `src/`, as (path relative to `src/`, contents).
    pub(crate) fn crate_sources() -> Vec<(String, String)> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, root, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                    out.push((rel, std::fs::read_to_string(&path).unwrap()));
                }
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        walk(&root, &root, &mut out);
        assert!(out.iter().any(|(f, _)| f == "sys.rs"), "source walk found no sys.rs under {}", root.display());
        out
    }

    /// The part of a source file before its first test module.
    pub(crate) fn production_part(source: &str) -> String {
        source
            .lines()
            .take_while(|l| !l.starts_with("#[cfg(test)]") && !l.starts_with("#[cfg(all(test"))
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn golden_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden").join(name)
    }

    /// Compare `actual` with a checked-in golden file, or rewrite the file
    /// when `BV_BLESS_GOLDEN=1`. Either way the change is a reviewable diff.
    fn assert_golden(name: &str, actual: &str) {
        let path = golden_path(name);
        if std::env::var("BV_BLESS_GOLDEN").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, actual).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}; run with BV_BLESS_GOLDEN=1 to create it", path.display()));
        assert!(
            expected == actual,
            "{} no longer matches the route table. If the change is intended, rerun with \
             BV_BLESS_GOLDEN=1 and review the diff.\n--- expected\n{expected}\n--- actual\n{actual}",
            path.display()
        );
    }

    /// Widening the unauthenticated surface requires editing
    /// `tests/golden/anonymous-routes.txt` — the control F1 lacked.
    #[test]
    fn anonymous_surface_matches_golden_file() {
        assert_golden("anonymous-routes.txt", &render_anonymous_surface(&inventory()));
    }

    /// Adding, removing or reclassifying any route changes the inventory.
    #[test]
    fn route_inventory_matches_golden_file() {
        assert_golden("route-inventory.txt", &render_inventory(&inventory()));
    }

    #[test]
    fn no_method_is_registered_twice_on_one_pattern() {
        let entries = inventory();
        let mut seen = std::collections::HashSet::new();
        for e in &entries {
            assert!(
                seen.insert((e.method.as_str(), e.pattern.clone())),
                "{} {} is registered twice; actix would serve only the first",
                e.method.as_str(),
                e.pattern
            );
        }
    }

    /// Every `{name}` a privileged policy path substitutes is a segment its
    /// route captures. A template naming anything else would be judged on an
    /// empty segment — `sys/plugins//config` — instead of the caller's.
    #[test]
    fn privileged_policy_paths_name_only_captured_segments() {
        for e in inventory() {
            let RouteClass::Privileged(p) = e.class else { continue };
            let captures: Vec<&str> = crate::authz::template_params(&e.pattern)
                .into_iter()
                .map(|c| c.split(':').next().unwrap_or(c))
                .collect();
            for param in crate::authz::template_params(p.policy_path) {
                assert!(
                    captures.contains(&param),
                    "{} {}: policy path {} names `{param}`, which the route does not capture",
                    e.method.as_str(),
                    e.pattern,
                    p.policy_path
                );
            }
            assert_eq!(
                p.policy_path.matches('{').count(),
                crate::authz::template_params(p.policy_path).len(),
                "{}: malformed policy path template {}",
                e.pattern,
                p.policy_path
            );
        }
    }

    /// A concrete path that matches `pattern`: every `{...}` segment becomes
    /// `x`.
    fn sample_path(pattern: &str) -> String {
        let mut out = String::new();
        let mut rest = pattern;
        while let Some(open) = rest.find('{') {
            let close = rest[open..].find('}').expect("balanced pattern") + open;
            out.push_str(&rest[..open]);
            out.push('x');
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        out
    }

    async fn resolve_inventory(req: HttpRequest) -> HttpResponse {
        let rmap = req.resource_map();
        let resolved: Vec<(String, Option<String>)> =
            inventory().iter().map(|e| (e.pattern.clone(), rmap.match_pattern(&sample_path(&e.pattern)))).collect();
        HttpResponse::Ok().json(resolved)
    }

    /// Every listed route is served by its own resource, through the real
    /// `init_service`. A resource shadowed by an earlier, broader one — the
    /// `/plugins/{name}` wildcard registered ahead of `/plugins/publishers`,
    /// say — resolves to the wrong pattern and fails here.
    #[actix_web::test]
    async fn every_listed_route_is_served_by_its_own_resource() {
        let app = actix_web::test::init_service(
            App::new().configure(crate::init_service).route("/__inventory_probe", web::get().to(resolve_inventory)),
        )
        .await;
        let req = actix_web::test::TestRequest::get().uri("/__inventory_probe").to_request();
        let resolved: Vec<(String, Option<String>)> = actix_web::test::call_and_read_body_json(&app, req).await;
        assert_eq!(resolved.len(), inventory().len());
        for (pattern, matched) in resolved {
            assert_eq!(matched.as_deref(), Some(pattern.as_str()), "{pattern} is shadowed or unregistered");
        }
    }

    /// The `routed` / `routed_unauthenticated` split must agree with the
    /// system backend's `unauth_paths`, which is what actually decides whether
    /// `pre_route` demands a token for the shim's logical path.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn routed_classes_agree_with_the_logical_unauth_paths() {
        let (_bvault, core, _root) = crate::test_utils::new_unseal_test_bastion_vault("test_routes_unauth_paths").await;
        for InventoryEntry { method, pattern, class } in inventory() {
            let (logical, expect_unauth) = match class {
                RouteClass::Routed { logical } => (logical, false),
                RouteClass::RoutedUnauthenticated { logical, .. } => (logical, true),
                _ => continue,
            };
            let sample = sample_path(logical);
            assert_eq!(
                core.router.is_unauth_path(&sample).unwrap(),
                expect_unauth,
                "{} {pattern} is classed {} but `{sample}` {} in the logical unauth paths",
                method.as_str(),
                class.label(),
                if expect_unauth { "is not" } else { "is" }
            );
        }
    }

    /// Calls into actix's registration API.
    const REGISTRATION: &[&str] = &[
        "web::resource(",
        "web::scope(",
        ".route(",
        ".to(",
        ".default_service(",
        ".service(",
        "web::get()",
        "web::post()",
        "web::put()",
        "web::delete()",
        "web::route()",
        "web::method(",
        // A hand-written spec could pair any class with any registration.
        "RouteSpec {",
    ];

    /// Every line of `source`'s production part that calls actix's
    /// registration API.
    fn registration_offenders(file: &str, source: &str) -> Vec<String> {
        production_part(source)
            .lines()
            .enumerate()
            .filter_map(|(n, line)| {
                REGISTRATION
                    .iter()
                    .find(|t| line.contains(*t))
                    .map(|token| format!("{file}:{}: `{token}` in `{}`", n + 1, line.trim()))
            })
            .collect()
    }

    /// Actix's registration API is called from this module and `authz.rs`
    /// only, so a route cannot be added beside the tables — the text
    /// equivalent of "grep finds no bare `.to(` in `configure_sys_routes`"
    /// (the function the `sys::routes` table replaced), widened to the whole
    /// crate. Test modules are exempt, and so is
    /// `test_support.rs`: the feature-gated harness wraps an `App` around
    /// `init_service` and sets that app's 404 default, which adds no route and
    /// never reaches a shipped build.
    #[test]
    fn no_route_is_registered_outside_the_route_builder() {
        let offenders: Vec<String> = crate_sources()
            .iter()
            .filter(|(file, _)| file != "routes.rs" && file != "authz.rs" && file != "test_support.rs")
            .flat_map(|(file, source)| registration_offenders(file, source))
            .collect();
        assert!(offenders.is_empty(), "route registration outside the route table:\n{}", offenders.join("\n"));
    }

    /// The gate has to be able to fail: a bare registration is caught, while
    /// the same text inside a comment or a test module is not.
    #[test]
    fn the_registration_gate_detects_raw_registration() {
        let raw = "fn init(cfg: &mut web::ServiceConfig) {\n    cfg.service(web::resource(\"/x\").route(web::get().to(h)));\n}\n";
        assert_eq!(registration_offenders("raw.rs", raw).len(), 1);
        let commented = "// cfg.service(web::resource(\"/x\").route(web::get().to(h)));\n";
        assert!(registration_offenders("commented.rs", commented).is_empty());
        let in_tests =
            "fn a() {}\n#[cfg(test)]\nmod tests { fn t() { App::new().route(\"/x\", web::get().to(h)); } }\n";
        assert!(registration_offenders("tests.rs", in_tests).is_empty());
        // The builder itself trips it, so the token list names the real API.
        let sources = crate_sources();
        let builder =
            sources.iter().find(|(f, _)| f == "routes.rs").map(|(f, s)| registration_offenders(f, s)).unwrap();
        assert!(!builder.is_empty(), "the gate no longer matches the builder's own calls; update the token list");
    }
}
