//! Cross-namespace copy and move of KV secrets and resources (T494).
//!
//! See `features/cross-namespace-copy-move.md`. Planning only so far: the
//! orchestrator that reads, writes and audits a transfer builds on these.

pub mod shares;
