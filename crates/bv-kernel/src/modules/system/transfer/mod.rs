//! Cross-namespace copy and move of KV secrets and resources (T494).
//!
//! See `features/cross-namespace-copy-move.md`. [`orchestrate`] runs a
//! transfer behind `sys/namespace-transfer/{copy|move}`; [`shares`] plans
//! which shares the destination can carry.

pub mod orchestrate;
pub mod shares;

pub use orchestrate::{
    run_transfer, Location, TransferOp, TransferRequest, TransferResult, TransferWarning, Transferred,
};
