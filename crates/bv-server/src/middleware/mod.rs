//! The actix-web middleware layers, wrapped around the `App` in
//! `bvault-cli`'s `server` command.
//!
//! Both used to live next to the subsystems they read — `bastion_vault::dos`
//! and `bastion_vault::metrics` — where they were the sole reason those
//! modules pulled in actix-web. Phases 1 and 3 already refused to let them
//! travel down into `bv-metrics` and `bv-kernel-api` for exactly that reason;
//! Phase 4 finishes the job by moving them **up**, into the one crate that is
//! allowed to know about a web framework.
//!
//! Order matters at the wrap site: [`dos`] is the outermost layer, so a banned
//! IP is rejected before logging or timing does any work.

pub mod dos;
pub mod metrics;
