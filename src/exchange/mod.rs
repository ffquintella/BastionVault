//! Exchange (Import / Export) module.
//!
//! Produces and consumes portable `bvx.v1` JSON documents describing a
//! selected subset of vault data, with an optional password-encrypted
//! `.bvx` envelope (Argon2id KDF + XChaCha20-Poly1305 AEAD).
//!
//! See `features/import-export-module.md` for the full spec. Phase 1 + 2
//! deliverables: KV multi-mount export/import, plaintext JSON, and
//! password-encrypted `.bvx`. File-resource inlining and asset/resource
//! group expansion live in later phases.
//!
//! Distinct from `crate::backup`:
//! - `backup` is the operator-level, full-vault, BVBK-binary path
//!   (HMAC'd against the vault's audit-device key, restorable only on
//!   the same vault's barrier).
//! - `exchange` is the user-level, scope-selectable, JSON-or-`.bvx` path
//!   (password-encrypted, portable across vault instances).

pub mod canonical;
pub mod envelope;
pub mod kdf;
pub mod preview;
pub mod schema;
pub mod scope;

pub use envelope::{decrypt_bvx, encrypt_bvx, Envelope, EnvelopeError, MIN_PASSWORD_LEN};
pub use preview::{PreviewClassificationItem, PreviewStore, PreviewSummary};
pub use schema::{
    AssetGroupItem, ExchangeDocument, ExchangeItems, ExporterInfo, FileItem, KvItem, ResourceGroupItem,
    ResourceItem, ScopeKind, ScopeSelector, ScopeSpec,
};
pub use scope::{
    export_to_document, import_from_document, ConflictPolicy, ImportAction, ImportClassification,
    ImportResult, ImportedItem,
};
