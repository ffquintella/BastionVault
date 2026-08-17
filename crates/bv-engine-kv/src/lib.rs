//! The key/value secret engines, both generations in one crate.
//!
//! [`v1`] is the flat, overwrite-in-place store; [`v2`] is the versioned one
//! with metadata, soft-delete and destroy. They share no code — they are one
//! crate because they are one concept and 1,323 lines between them, and
//! because two crates of this size buy nothing.
//!
//! `bastion_vault::modules::{kv, kv_v2}` re-export these two modules, so no
//! path outside this crate changed. See
//! roadmaps/workspace-decomposition.md § Phase 3.

// The substrate, under the names both engines have always spelled it.
// Private: none of it leaks into the public API.
use bv_context as context;
use bv_errors as errors;
use bv_logical as logical;
use bv_storage as storage;
use bv_utils as utils;

// The eight backend-definition macros are `#[macro_export]`ed by `bv-logical`,
// which places them at *that* crate's root; the call sites import them as
// `crate::new_path` and friends. The `_internal` halves are the recursive arms
// the public macros expand into, so they must travel with them.
pub use bv_logical::{
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path,
    new_path_internal, new_secret, new_secret_internal,
};
pub use bv_errors::{bv_error_response, bv_error_response_status, bv_error_string};

pub mod v1;
pub mod v2;
