//! The `FileTarget` trait — the pluggable I/O primitive underneath
//! the Encrypted File storage backend.
//!
//! `FileBackend` is responsible for serializing a `BackendEntry` to
//! JSON bytes and handing them to a `FileTarget`; the target decides
//! *where* those bytes live. This indirection is the seam through
//! which cloud targets (S3 / OneDrive / Google Drive / Dropbox —
//! later phases of `features/cloud-storage-backend.md`) will be
//! added without any change to `Backend`, the barrier, or the
//! storage schema.
//!
//! Phase 1 scope (this file): the trait only. The sole implementor
//! today is `LocalFsTarget`, which carries the exact behavior the
//! pre-refactor `FileBackend` had. No new functionality lives here.
//!
//! The trait is deliberately byte-level — targets never see the
//! decrypted `BackendEntry`; the bytes flowing through `write`/`read`
//! are whatever the backend above chose to persist (in production:
//! AEAD ciphertext produced by the barrier above the storage layer).

use std::any::Any;

use crate::errors::RvError;

#[maybe_async::maybe_async]
pub trait FileTarget: Send + Sync + std::fmt::Debug {
    /// Return the raw bytes previously written at `key`, or `None`
    /// if no such key exists.
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError>;

    /// Persist `value` at `key`, overwriting any prior value. The
    /// write is durable iff this call returns `Ok`.
    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError>;

    /// Remove `key`. Returns `Ok(())` whether or not the key existed.
    async fn delete(&self, key: &str) -> Result<(), RvError>;

    /// Enumerate children of `prefix`. Directory-like entries end
    /// with a trailing `/`; leaf entries are returned without one.
    /// Exact shape matches the existing `Backend::list` contract so
    /// callers upstream of `FileBackend` are unaffected.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;

    /// Acquire a target-specific write lock scoped to `lock_name`.
    /// The returned box's `Drop` releases the lock. For targets that
    /// have no meaningful lock primitive (cloud drives today), a
    /// trivial `Ok(Box::new(()))` is acceptable given the spec's
    /// documented single-writer-per-target assumption.
    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any + Send>, RvError>;
}
