//! Example: surface manifest for a TOTP secret-engine plugin.
//!
//! Run with:
//!
//! ```text
//! cargo run --example totp_surface --features surface,json -p bastion-plugin-sdk
//! ```
//!
//! Prints the JSON the plugin author would ship as `surface.json`
//! in their `.bvplugin` bundle. Plugin Extensibility v1 / Phase 7.
//!
//! The companion form-hook lives in
//! [`tests/totp_validate_create.rs`](../tests/totp_validate_create.rs)
//! (testable on the host via `cargo test --features
//! surface,host_test`); ship the WASM build of that file as
//! `totp-form-hooks.wasm` alongside `surface.json`.

#[cfg(feature = "surface")]
fn main() {
    use bastion_plugin_sdk::surface::{
        surface_builder, SurfaceBinding, SurfaceColumn, SurfaceComponent,
        SurfaceDetail, SurfaceDetailField, SurfaceForm, SurfaceMenu,
        SurfaceOp, SurfacePage, SurfaceRowAction, SurfaceSection,
        SurfaceSubmit, SurfaceTable,
    };

    let mut s = surface_builder("TOTP");
    s.icon = "key-round".to_string();

    s.menus.push(SurfaceMenu {
        id: "totp.main".to_string(),
        label: "TOTP".to_string(),
        icon: "key-round".to_string(),
        section: SurfaceSection::Secrets,
        route: "/plugin/totp/codes".to_string(),
        // UX hint only — server-side ACL is the only gate. We list
        // both the user and the admin baseline so admins also see
        // the entry without configuring extra policies.
        min_policy: "totp-user".to_string(),
    });

    s.pages.push(SurfacePage {
        route: "/plugin/totp/codes".to_string(),
        title: "TOTP codes".to_string(),
        components: vec![
            // List view: one row per registered code.
            SurfaceComponent::Table(SurfaceTable {
                id: "totp.list".to_string(),
                binding: SurfaceBinding {
                    op: SurfaceOp::List,
                    path: "{mount}/codes".to_string(),
                },
                columns: vec![
                    SurfaceColumn {
                        field: "name".to_string(),
                        label: "Name".to_string(),
                    },
                    SurfaceColumn {
                        field: "issuer".to_string(),
                        label: "Issuer".to_string(),
                    },
                ],
                row_actions: vec![SurfaceRowAction {
                    label: "Delete".to_string(),
                    binding: SurfaceBinding {
                        op: SurfaceOp::Delete,
                        path: "{mount}/codes/{name}".to_string(),
                    },
                    confirm: true,
                }],
                empty_text: "No TOTP codes registered yet.".to_string(),
            }),
            // Create form. The `hook` reference points at the
            // form-hook WASM module declared in
            // `manifest.client_assets[]` — its `validate_create`
            // export refuses non-base32 secrets before the request
            // reaches the server (server-side validation still runs
            // as the source of truth).
            SurfaceComponent::Form(SurfaceForm {
                id: "totp.create".to_string(),
                title: "Register a new code".to_string(),
                schema: serde_json::json!({
                    "type": "object",
                    "required": ["name", "secret"],
                    "properties": {
                        "name": {
                            "type": "string",
                            "title": "Name",
                            "description": "Friendly identifier — appears in the table above."
                        },
                        "issuer": {
                            "type": "string",
                            "title": "Issuer",
                            "description": "Service the code is for (e.g. 'AWS', 'GitHub')."
                        },
                        "secret": {
                            "type": "string",
                            "format": "password",
                            "title": "Base32 secret",
                            "description": "The shared secret printed on the QR code."
                        }
                    }
                }),
                submit: SurfaceSubmit {
                    label: "Register".to_string(),
                    binding: SurfaceBinding {
                        op: SurfaceOp::Write,
                        path: "{mount}/codes/{name}".to_string(),
                    },
                },
                hook: "totp-form-hooks.wasm#validate_create".to_string(),
            }),
        ],
    });

    // Optional detail page reachable from the table — illustrates
    // a `live: true` field that polls every 5 s.
    s.pages.push(SurfacePage {
        route: "/plugin/totp/codes/show".to_string(),
        title: "TOTP code".to_string(),
        components: vec![SurfaceComponent::Detail(SurfaceDetail {
            id: "totp.show".to_string(),
            binding: SurfaceBinding {
                op: SurfaceOp::Read,
                path: "{mount}/codes/{name}".to_string(),
            },
            fields: vec![
                SurfaceDetailField {
                    field: "name".to_string(),
                    label: "Name".to_string(),
                    live: false,
                },
                SurfaceDetailField {
                    field: "issuer".to_string(),
                    label: "Issuer".to_string(),
                    live: false,
                },
                SurfaceDetailField {
                    field: "code".to_string(),
                    label: "Current code".to_string(),
                    live: true,
                },
            ],
        })],
    });

    // Validate before printing — this matches what the server-side
    // catalog runs on register, so a malformed surface fails fast
    // at the author's terminal instead of at deploy time.
    let asset_names = std::collections::BTreeSet::from(["totp-form-hooks.wasm"]);
    s.validate("totp", &asset_names).expect("valid surface");

    println!("{}", serde_json::to_string_pretty(&s).expect("serialize"));
}

#[cfg(not(feature = "surface"))]
fn main() {
    eprintln!(
        "this example requires `--features surface,json` — see the file's top \
         comment."
    );
    std::process::exit(2);
}
