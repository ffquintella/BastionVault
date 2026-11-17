//! Cross-namespace copy and move of KV secrets and resources (T494).
//!
//! See `features/cross-namespace-copy-move.md`. [`orchestrate`] runs a
//! transfer behind `sys/namespace-transfer/{copy|move}`; [`shares`] plans
//! which shares the destination can carry.

pub mod orchestrate;
// T494: `plan_shares` is called by Task 4b's `carry_relations`, not yet; only
// `ShareWarning` is used today. Drop the allow once 4b lands.
#[cfg_attr(not(test), allow(dead_code))]
pub mod shares;
#[cfg(test)]
mod vault_tests;

pub use orchestrate::{run_transfer, TransferOp, TransferRequest};
