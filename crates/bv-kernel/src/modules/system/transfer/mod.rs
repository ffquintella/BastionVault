//! Cross-namespace copy and move of KV secrets and resources (T494).
//!
//! See `features/cross-namespace-copy-move.md`. [`orchestrate`] runs a
//! transfer behind `sys/namespace-transfer/{copy|move}`; [`shares`] plans
//! which shares the destination can carry.

pub mod orchestrate;
pub mod shares;
#[cfg(test)]
mod vault_tests;

pub use orchestrate::{run_transfer, IdentityStores, TransferOp, TransferRequest};
