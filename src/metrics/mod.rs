//! The `bastion_vault::metrics` module instruments BastionVault with
//! Prometheus, allowing it to capture performance metrics.
//!
//! The metric families themselves live in the Tier 0 [`bv_metrics`] crate and
//! are re-exported here, so `bastion_vault::metrics::*` paths are unchanged.
//! Read that crate's module docs for the methodology and for how to add a new
//! metric.
//!
//! The actix-web middleware that times requests and feeds [`http_metrics`] is
//! `bv_server::middleware::metrics` as of Phase 4. Phase 1 refused to let it
//! travel *down* into `bv-metrics` — that would have put actix-web under every
//! crate that records a metric, `bv-storage` included — and Phase 4 gave it
//! somewhere above to go instead.
//!
//! What stays here are the two scrape-level test modules below, which drive a
//! whole `TestHttpServer` from `crate::test_utils`.
//!
//! See roadmaps/workspace-decomposition.md §§ Phase 1, Phase 4.

pub use bv_metrics::{cache_metrics, ferrogate_metrics, http_metrics, manager, system_metrics};

#[cfg(test)]
mod http_metrics_tests;
#[cfg(test)]
mod system_metrics_tests;
