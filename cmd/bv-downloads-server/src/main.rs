//! `bv-downloads-server` — the BastionVault client download site.
//!
//! Reads a mounted directory of signed client artefacts plus its
//! `manifest.json`, renders one static landing page from it at startup, and
//! serves that page, the manifest, and exactly the files the manifest names.
//! Nothing else. There is no upload path, no admin surface, no API, and no
//! per-user state; see features/packaging-distribution-website.md.
//!
//! Startup is fail-fast on purpose. A manifest that names a file which is not
//! on disk, a digest that does not match the bytes (with `--verify-hashes`), a
//! path that escapes the served root, or a TLS half-configuration all abort
//! before the listener binds, with one line naming what to fix. An operator
//! should never discover a broken release by a user reporting a 404.

mod manifest;
mod render;
mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

/// Serve the BastionVault client downloads page from a directory of signed
/// artefacts.
#[derive(Debug, Parser)]
#[command(name = "bv-downloads-server", version, about, long_about = None)]
struct Cli {
    /// Directory holding `manifest.json` and the `vX.Y.Z/` artefact directory.
    /// Mounted read-only in the container.
    #[arg(long, default_value = "/srv/bv-downloads", env = "BV_DOWNLOADS_ROOT")]
    root: PathBuf,

    /// Override the built-in branding with a directory holding your own
    /// `style.css` and `logo.svg`. Both are inlined into the generated page.
    /// Unset, the assets compiled into the binary are used; set to a directory
    /// missing either file, startup fails rather than quietly falling back.
    #[arg(long, env = "BV_DOWNLOADS_STATIC")]
    static_dir: Option<PathBuf>,

    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8080", env = "BV_DOWNLOADS_ADDR")]
    addr: SocketAddr,

    /// Re-hash every artefact at startup and refuse to serve a manifest whose
    /// SHA-256 does not match the bytes on disk. Off by default because a full
    /// release directory is gigabytes; worth the seconds on a release host.
    #[arg(long, env = "BV_DOWNLOADS_VERIFY_HASHES")]
    verify_hashes: bool,

    /// Render the index page to stdout and exit without binding a listener.
    /// Useful for a CI check that a manifest renders before it is published.
    #[arg(long)]
    render_only: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // One line, naming what to fix. This is the whole diagnostic an
            // operator gets from `podman logs` on a container that refused to
            // start, so it has to be enough.
            eprintln!("bv-downloads-server: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    // TLS is Phase 3 (features/packaging-distribution-website.md § TLS). Until
    // it lands, a set `BV_DOWNLOADS_TLS_*` is a hard error rather than a
    // silently-ignored variable: an operator who believes they configured
    // HTTPS and got plaintext is exactly the failure mode § Security
    // Considerations exists to prevent.
    let tls_cert = std::env::var_os("BV_DOWNLOADS_TLS_CERT");
    let tls_key = std::env::var_os("BV_DOWNLOADS_TLS_KEY");
    if tls_cert.is_some() || tls_key.is_some() {
        return Err(
            "BV_DOWNLOADS_TLS_CERT / BV_DOWNLOADS_TLS_KEY are set, but built-in TLS is not \
             implemented yet (Phase 3). Refusing to start rather than serving plaintext on a \
             port you believe is HTTPS — terminate TLS at your reverse proxy for now."
                .to_string(),
        );
    }

    let validated = manifest::load_and_validate(&cli.root, cli.verify_hashes)
        .map_err(|e| format!("{e}"))?;
    for warning in &validated.warnings {
        eprintln!("bv-downloads-server: warning: {warning}");
    }

    let index = render::render(&validated, cli.static_dir.as_deref()).map_err(|e| format!("{e}"))?;

    if cli.render_only {
        print!("{}", index.html);
        return Ok(());
    }

    let version = validated.manifest.version.clone();
    let file_count = validated.manifest.files.len();
    let state = Arc::new(serve::AppState::new(validated, index));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(cli.addr)
            .await
            .map_err(|e| format!("cannot bind {}: {e}", cli.addr))?;
        let bound = listener
            .local_addr()
            .map_err(|e| format!("cannot read the bound address: {e}"))?;

        println!(
            "bv-downloads-server: serving BastionVault {version} \
             ({file_count} artefacts, {} servable paths) from {} on http://{bound}/",
            state.asset_count(),
            cli.root.display(),
        );
        if cli.verify_hashes {
            println!("bv-downloads-server: every artefact matched its manifest SHA-256");
        }

        axum::serve(listener, serve::router(state))
            .with_graceful_shutdown(shutdown())
            .await
            .map_err(|e| format!("server error: {e}"))
    })?;

    Ok(())
}

/// SIGTERM (what `podman stop` sends) and Ctrl-C.
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => eprintln!("bv-downloads-server: cannot listen for SIGTERM: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    println!("bv-downloads-server: shutting down");
}
