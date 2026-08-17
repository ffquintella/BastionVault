//! Create full vault backups as encrypted blob archives with HMAC integrity.

use std::io::Write;

use hmac::Mac;

use crate::{
    errors::RvError,
    storage::Backend,
};

use super::format::{self, BackupHeader};

/// Create a backup of all data in the backend.
///
/// Data is copied as raw encrypted bytes -- no decryption occurs.
/// The HMAC is keyed with the barrier's HMAC key for integrity verification on restore.
pub async fn create_backup(
    backend: &dyn Backend,
    hmac_key: &[u8],
    writer: &mut (dyn Write + Send),
    compressed: bool,
) -> Result<u64, RvError> {
    // First pass: collect all keys and count entries.
    let all_keys = crate::storage::migrate::list_all_keys(backend, "").await?;
    let entry_count = all_keys.len() as u64;

    let header = BackupHeader {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        barrier_type: "chacha20-poly1305".to_string(),
        entry_count,
        compressed,
    };

    // We'll build the entire payload in memory so we can compute the HMAC over it.
    let mut payload = Vec::new();
    format::write_header(&mut payload, &header)?;

    // Second pass: read each entry and write frames.
    let mut actually_copied = 0u64;
    for key in &all_keys {
        if let Some(entry) = backend.get(key).await? {
            if compressed {
                let compressed_value = zstd::encode_all(entry.value.as_slice(), 3)
                    .map_err(|_| RvError::ErrBackupCorrupted)?;
                format::write_entry_frame(&mut payload, key, &compressed_value)?;
            } else {
                format::write_entry_frame(&mut payload, key, &entry.value)?;
            }
            actually_copied += 1;
        }
    }

    // Compute HMAC over the entire payload.
    let mut mac = format::new_hmac(hmac_key)?;
    mac.update(&payload);
    let digest = mac.finalize().into_bytes();

    // Write payload + HMAC to the output writer.
    writer.write_all(&payload)?;
    writer.write_all(&digest)?;
    writer.flush()?;

    Ok(actually_copied)
}

#[cfg(test)]
mod tests {
    use crate::kernel_api::VaultCtx;
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::json;

    use crate::core::Core;
    use crate::logical::{Operation, Request};
    use crate::modules::namespace::{
        router::namespace_logical_prefix, NamespaceModule, NamespaceQuotas, NAMESPACE_MODULE_NAME,
    };
    use crate::test_utils::new_unseal_test_bastion_vault;

    use super::super::format;

    async fn ns_req(
        core: &Arc<Core>,
        token: &str,
        op: Operation,
        path: &str,
        ns: &str,
        body: Option<serde_json::Map<String, serde_json::Value>>,
    ) {
        let mut req = Request::new(path);
        req.operation = op;
        req.client_token = token.to_string();
        req.body = body;
        if !ns.is_empty() {
            let mut h = HashMap::new();
            h.insert("x-bastionvault-namespace".to_string(), ns.to_string());
            req.headers = Some(h);
        }
        core.handle_request(&mut req).await.unwrap();
    }

    /// The operator backup is a raw sweep of the *physical* backend from its
    /// root prefix, so it must capture every namespace's subtree
    /// (`namespaces/<uuid>/…`) and the namespace registry itself — not just the
    /// root tenant. Guards against a future change scoping the sweep to a
    /// prefix, which would silently drop every tenant from operator backups.
    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn backup_captures_every_namespace() {
        let (_bvault, core, root) =
            new_unseal_test_bastion_vault("test_backup_all_namespaces").await;

        let store = core
            .module_manager()
            .get_module::<NamespaceModule>(NAMESPACE_MODULE_NAME)
            .and_then(|m| m.store())
            .expect("namespace store");
        let tenant = store.create("tenant-a", NamespaceQuotas::default(), false).await.unwrap();

        ns_req(
            &core,
            &root,
            Operation::Write,
            "sys/mounts/cubby/",
            "tenant-a",
            json!({ "type": "kv" }).as_object().cloned(),
        )
        .await;
        ns_req(
            &core,
            &root,
            Operation::Write,
            "cubby/foo",
            "tenant-a",
            json!({ "v": "from-a" }).as_object().cloned(),
        )
        .await;

        let hmac_key = core.barrier().derive_hmac_key().unwrap();
        let mut out = Vec::new();
        let copied =
            super::create_backup(core.physical().as_ref(), &hmac_key, &mut out, false).await.unwrap();
        assert!(copied > 0);

        // Walk the frames and collect the keys the backup actually carries.
        // The trailing 32 bytes are the HMAC, not a frame (see `restore_backup`).
        let payload = &out[..out.len() - 32];
        let mut cursor = std::io::Cursor::new(payload);
        format::read_header(&mut cursor).unwrap();
        let mut keys: Vec<String> = Vec::new();
        while let Some((key, _value)) = format::read_entry_frame(&mut cursor).unwrap() {
            keys.push(key);
        }

        let tenant_prefix = namespace_logical_prefix(&tenant.uuid);
        assert!(
            keys.iter().any(|k| k.starts_with(&tenant_prefix)),
            "backup must contain the tenant's logical subtree {tenant_prefix}"
        );
        assert!(
            keys.iter().any(|k| k.starts_with("namespaces/registry/")),
            "backup must contain the namespace registry"
        );
        assert!(
            keys.iter().any(|k| k.contains(&format!("namespaces/{}/core/mounts", tenant.uuid))),
            "backup must contain the tenant's mount table"
        );
    }
}
