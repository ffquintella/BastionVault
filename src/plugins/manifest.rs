//! Plugin manifest.
//!
//! The manifest is a small JSON document the operator pins on registration.
//! It declares the plugin's identity, runtime, and capability footprint —
//! the trust contract.
//!
//! The types and the canonical signing-message construction live in the
//! standalone [`bv_plugin_manifest`] crate so the host verifier and the
//! `bv-plugin-pack` signer share a single source of truth: a signed
//! bundle's message is byte-identical on both ends by construction. This
//! module re-exports them so the rest of the host keeps importing
//! `crate::plugins::manifest::*` unchanged.

pub use bv_plugin_manifest::{
    check_abi_compatibility, parse_abi, signing_message, Capabilities, ClientAssetRef,
    ConfigField, ConfigFieldKind, PluginManifest, RuntimeKind, SurfaceRef, HOST_ABI_MAJOR,
    HOST_ABI_MINOR,
};
