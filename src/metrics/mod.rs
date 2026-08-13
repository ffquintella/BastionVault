//! The `bastion_vault::metrics` module instruments BastionVault with
//! Prometheus, allowing it to capture performance metrics.
//!
//! The metric families themselves live in the Tier 0 [`bv_metrics`] crate and
//! are re-exported here, so `bastion_vault::metrics::*` paths are unchanged.
//! Read that crate's module docs for the methodology and for how to add a new
//! metric.
//!
//! What stays in the root crate is the part that is not substrate:
//!
//! * [`middleware`] — the actix-web middleware that times requests and feeds
//!   [`http_metrics`]. It is assembly-layer code, and keeping it out of
//!   `bv-metrics` keeps actix-web out of the dependency graph of every crate
//!   that records a metric, `bv-storage` included.
//! * the two scrape-level test modules below, which drive a whole
//!   `TestHttpServer` from `crate::test_utils` and so cannot travel.
//!
//! See roadmaps/workspace-decomposition.md § Phase 1.

pub use bv_metrics::{cache_metrics, ferrogate_metrics, http_metrics, manager, system_metrics};

pub mod middleware;

#[cfg(test)]
mod http_metrics_tests;
#[cfg(test)]
mod system_metrics_tests;
