use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::SystemTime,
};

use go_defer::defer;

use super::{
    validation::SecretIdAccessorStorageEntry, AppRoleBackend, AppRoleBackendInner, SECRET_ID_ACCESSOR_LOCAL_PREFIX,
    SECRET_ID_ACCESSOR_PREFIX, SECRET_ID_LOCAL_PREFIX, SECRET_ID_PREFIX,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Operation, Path, PathOperation, Request, Response, CTX_KEY_BACKEND_PATH},
    new_path, new_path_internal,
    storage::Storage,
};

pub const CTX_KEY_BACKEND_PATH_INNER: &str = "backend.path.inner";

impl AppRoleBackend {
    pub fn tidy_secret_id_path(&self) -> Path {
        let approle_backend_ref1 = self.inner.clone();
        let approle_backend_ref2 = self.inner.clone();

        let path = new_path!({
            pattern: r"tidy/secret-id$",
            operations: [
                {op: Operation::Write, handler: approle_backend_ref1.handle_tidy_secret_id}
            ],
            help: r#"
SecretIDs will have expiration time attached to them. The periodic function
of the backend will look for expired entries and delete them. This happens once in a minute. Invoking
this endpoint will trigger the clean-up action, without waiting for the backend's periodic function.
"#
        });

        path.ctx.set(CTX_KEY_BACKEND_PATH_INNER, approle_backend_ref2);

        path
    }
}

impl AppRoleBackendInner {
    async fn tidy_secret_id_routine(&self, storage: Arc<dyn Storage>) {
        let check_count = AtomicU32::new(0);

        defer! (
            self.tidy_secret_id_cas_guard.store(0, Ordering::SeqCst);
            log::info!("done checking entries, num_entries: {}", check_count.load(Ordering::SeqCst));
        );

        let salt = self.salt.load();
        if salt.is_none() {
            log::error!("error tidying secret IDs");
            return;
        }

        let salt = salt.as_ref().unwrap().clone();
        #[cfg(not(feature = "sync_handler"))]
        let tidy_func = async move |secret_id_prefix_to_use: &str,
                                    accessor_id_prefix_to_use: &str|
                    -> Result<(), RvError> {
            log::info!("listing accessors, prefix: {accessor_id_prefix_to_use}");
            // List all the accessors and add them all to a map
            // These hashes are the result of salting the accessor id.

            let accessor_hashes = storage.list(accessor_id_prefix_to_use).await?;

            let mut skip_hashes: HashMap<String, bool> = HashMap::new();
            let mut accessor_entry_by_hash: HashMap<String, SecretIdAccessorStorageEntry> = HashMap::new();
            for accessor_hash in accessor_hashes.iter() {
                let Some(storage_entry) = storage.get(&format!("{accessor_id_prefix_to_use}{accessor_hash}")).await?
                else {
                    continue;
                };

                let ret: SecretIdAccessorStorageEntry = serde_json::from_slice(storage_entry.value.as_slice())?;
                accessor_entry_by_hash.insert(accessor_hash.clone(), ret);
            }

            let s = storage.clone();

            let secret_id_cleanup_func = async move |secret_id_hmac: &str,
                                                     role_name_hmac: &str,
                                                     secret_id_prefix_to_use: &str,
                                                     skip_hashes: &mut HashMap<String, bool>|
                        -> Result<(), RvError> {
                let storage = storage.clone();
                let s = Arc::as_ref(&storage);

                let lock_entry = self.secret_id_locks.get_lock(secret_id_hmac);
                let _locked = lock_entry.lock.write().await;

                let secret_id_storage_entry = self
                    .get_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)
                    .await?
                    .ok_or(RvError::ErrResponse(format!(
                        "entry for secret id was nil, secret_id_hmac: {secret_id_hmac}"
                    )))?;

                // If a secret ID entry does not have a corresponding accessor
                // entry, revoke the secret ID immediately
                if self
                    .get_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )
                    .await?
                    .is_none()
                {
                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)
                        .await?;
                    return Ok(());
                }

                // ExpirationTime not being set indicates non-expiring SecretIDs
                if SystemTime::now() > secret_id_storage_entry.expiration_time {
                    log::info!("found expired secret ID");
                    // Clean up the accessor of the secret ID first
                    self.delete_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )
                    .await?;

                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)
                        .await?;

                    return Ok(());
                }

                // At this point, the secret ID is not expired and is valid. Flag
                // the corresponding accessor as not needing attention.
                let salt_id = salt.salt_id(&secret_id_storage_entry.secret_id_accessor)?;
                skip_hashes.insert(salt_id, true);

                Ok(())
            };

            log::info!("listing role HMACs, prefix: {secret_id_prefix_to_use}");

            let role_name_hmacs = s.list(secret_id_prefix_to_use).await?;
            for item in role_name_hmacs.iter() {
                let role_name_hmac = item.trim_end_matches('/');
                log::info!("listing secret id HMACs, role_name: {role_name_hmac}");
                let key = format!("{secret_id_prefix_to_use}{role_name_hmac}/");
                let secret_id_hmacs = s.list(&key).await?;
                for secret_id_hmac in secret_id_hmacs.iter() {
                    secret_id_cleanup_func(secret_id_hmac, role_name_hmac, secret_id_prefix_to_use, &mut skip_hashes)
                        .await?;
                }
            }

            if accessor_hashes.len() > skip_hashes.len() {
                // There is some raciness here because we're querying secretids for
                // roles without having a lock while doing so.  Because
                // accessor_entry_by_hash was populated previously, at worst this may
                // mean that we fail to clean up something we ought to.
                let mut all_secret_id_hmacs: HashMap<String, bool> = HashMap::new();
                for item in role_name_hmacs.iter() {
                    let role_name_hmac = item.trim_end_matches('/');
                    let key = format!("{secret_id_prefix_to_use}{role_name_hmac}/");
                    let secret_id_hmacs = s.list(&key).await?;
                    for secret_id_hmac in secret_id_hmacs.iter() {
                        all_secret_id_hmacs.insert(secret_id_hmac.clone(), true);
                    }
                }

                for (accessor_hash, accessor_entry) in accessor_entry_by_hash.iter() {
                    let lock_entry = self.secret_id_locks.get_lock(&accessor_entry.secret_id_hmac);
                    let _locked = lock_entry.lock.write().await;

                    // Don't clean up accessor index entry if secretid cleanup func
                    // determined that it should stay.
                    if skip_hashes.contains_key(accessor_hash) {
                        continue;
                    }

                    // Don't clean up accessor index entry if referenced in role.
                    if all_secret_id_hmacs.contains_key(&accessor_entry.secret_id_hmac) {
                        continue;
                    }

                    let entry_index = format!("{accessor_id_prefix_to_use}{accessor_hash}");

                    s.delete(&entry_index).await?;
                }
            }

            Ok(())
        };
        #[cfg(feature = "sync_handler")]
        let tidy_func = move |secret_id_prefix_to_use: &str, accessor_id_prefix_to_use: &str| -> Result<(), RvError> {
            log::info!("listing accessors, prefix: {accessor_id_prefix_to_use}");
            // List all the accessors and add them all to a map
            // These hashes are the result of salting the accessor id.

            let accessor_hashes = storage.list(accessor_id_prefix_to_use)?;

            let mut skip_hashes: HashMap<String, bool> = HashMap::new();
            let mut accessor_entry_by_hash: HashMap<String, SecretIdAccessorStorageEntry> = HashMap::new();
            for accessor_hash in accessor_hashes.iter() {
                let Some(storage_entry) = storage.get(&format!("{accessor_id_prefix_to_use}{accessor_hash}"))? else {
                    continue;
                };

                let ret: SecretIdAccessorStorageEntry = serde_json::from_slice(storage_entry.value.as_slice())?;
                accessor_entry_by_hash.insert(accessor_hash.clone(), ret);
            }

            let s = storage.clone();

            let secret_id_cleanup_func = move |secret_id_hmac: &str,
                                               role_name_hmac: &str,
                                               secret_id_prefix_to_use: &str,
                                               skip_hashes: &mut HashMap<String, bool>|
                  -> Result<(), RvError> {
                let storage = storage.clone();
                let s = Arc::as_ref(&storage);

                let lock_entry = self.secret_id_locks.get_lock(secret_id_hmac);
                let _locked = lock_entry.lock.write();

                let secret_id_storage_entry = self
                    .get_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?
                    .ok_or(RvError::ErrResponse(format!(
                        "entry for secret id was nil, secret_id_hmac: {secret_id_hmac}"
                    )))?;

                // If a secret ID entry does not have a corresponding accessor
                // entry, revoke the secret ID immediately
                if self
                    .get_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )?
                    .is_none()
                {
                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?;
                    return Ok(());
                }

                // ExpirationTime not being set indicates non-expiring SecretIDs
                if SystemTime::now() > secret_id_storage_entry.expiration_time {
                    log::info!("found expired secret ID");
                    // Clean up the accessor of the secret ID first
                    self.delete_secret_id_accessor_entry(
                        s,
                        &secret_id_storage_entry.secret_id_accessor,
                        secret_id_prefix_to_use,
                    )?;

                    self.delete_secret_id_storage_entry(s, secret_id_prefix_to_use, role_name_hmac, secret_id_hmac)?;

                    return Ok(());
                }

                // At this point, the secret ID is not expired and is valid. Flag
                // the corresponding accessor as not needing attention.
                let salt_id = salt.salt_id(&secret_id_storage_entry.secret_id_accessor)?;
                skip_hashes.insert(salt_id, true);

                Ok(())
            };

            log::info!("listing role HMACs, prefix: {secret_id_prefix_to_use}");

            let role_name_hmacs = s.list(secret_id_prefix_to_use)?;
            for item in role_name_hmacs.iter() {
                let role_name_hmac = item.trim_end_matches('/');
                log::info!("listing secret id HMACs, role_name: {role_name_hmac}");
                let key = format!("{secret_id_prefix_to_use}{role_name_hmac}/");
                let secret_id_hmacs = s.list(&key)?;
                for secret_id_hmac in secret_id_hmacs.iter() {
                    secret_id_cleanup_func(secret_id_hmac, role_name_hmac, secret_id_prefix_to_use, &mut skip_hashes)?;
                }
            }

            if accessor_hashes.len() > skip_hashes.len() {
                // There is some raciness here because we're querying secretids for
                // roles without having a lock while doing so.  Because
                // accessor_entry_by_hash was populated previously, at worst this may
                // mean that we fail to clean up something we ought to.
                let mut all_secret_id_hmacs: HashMap<String, bool> = HashMap::new();
                for item in role_name_hmacs.iter() {
                    let role_name_hmac = item.trim_end_matches('/');
                    let key = format!("{secret_id_prefix_to_use}{role_name_hmac}/");
                    let secret_id_hmacs = s.list(&key)?;
                    for secret_id_hmac in secret_id_hmacs.iter() {
                        all_secret_id_hmacs.insert(secret_id_hmac.clone(), true);
                    }
                }

                for (accessor_hash, accessor_entry) in accessor_entry_by_hash.iter() {
                    let lock_entry = self.secret_id_locks.get_lock(&accessor_entry.secret_id_hmac);
                    let _locked = lock_entry.lock.write();

                    // Don't clean up accessor index entry if secretid cleanup func
                    // determined that it should stay.
                    if skip_hashes.contains_key(accessor_hash) {
                        continue;
                    }

                    // Don't clean up accessor index entry if referenced in role.
                    if all_secret_id_hmacs.contains_key(&accessor_entry.secret_id_hmac) {
                        continue;
                    }

                    let entry_index = format!("{accessor_id_prefix_to_use}{accessor_hash}");

                    s.delete(&entry_index)?;
                }
            }

            Ok(())
        };

        let tidy_func_cloned = tidy_func.clone();
        #[cfg(not(feature = "sync_handler"))]
        if let Err(err) = tidy_func(SECRET_ID_PREFIX, SECRET_ID_ACCESSOR_PREFIX).await {
            log::error!("error tidying global secret IDs, error: {err}");
            return;
        }
        #[cfg(feature = "sync_handler")]
        if let Err(err) = tidy_func(SECRET_ID_PREFIX, SECRET_ID_ACCESSOR_PREFIX) {
            log::error!("error tidying global secret IDs, error: {err}");
            return;
        }

        #[cfg(not(feature = "sync_handler"))]
        if let Err(err) = tidy_func_cloned(SECRET_ID_LOCAL_PREFIX, SECRET_ID_ACCESSOR_LOCAL_PREFIX).await {
            log::error!("error tidying local secret IDs, error: {err}");
        }
        #[cfg(feature = "sync_handler")]
        if let Err(err) = tidy_func_cloned(SECRET_ID_LOCAL_PREFIX, SECRET_ID_ACCESSOR_LOCAL_PREFIX) {
            log::error!("error tidying local secret IDs, error: {err}");
        }
    }

    pub fn tidy_secret_id(&self, backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        let mut resp = Response::new();
        if self.tidy_secret_id_cas_guard.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            resp.add_warning("Tidy operation already in progress");
            return Ok(Some(resp));
        }

        let storage = req.storage.as_ref().unwrap().clone();

        let ctx = backend.get_ctx().ok_or(RvError::ErrRequestInvalid)?;
        let path: Arc<Path> = ctx
            .get(CTX_KEY_BACKEND_PATH)
            .ok_or(RvError::ErrRequestInvalid)?
            .downcast::<Path>()
            .map_err(|_| RvError::ErrRequestInvalid)?
            .clone();
        let path_inner: Arc<AppRoleBackendInner> = path
            .ctx
            .get(CTX_KEY_BACKEND_PATH_INNER)
            .ok_or(RvError::ErrRequestInvalid)?
            .downcast::<AppRoleBackendInner>()
            .map_err(|_| RvError::ErrRequestInvalid)?
            .clone();

        // Was `actix_rt::spawn`, which *is* `tokio::task::spawn_local` --
        // actix-rt re-exports tokio's `JoinHandle`, which is what
        // `Context::add_task` already stores. Spelled directly so an auth
        // backend does not depend on a web framework.
        //
        // `spawn_local`, not `spawn`: the two are not interchangeable here.
        // The tidy routine holds a CAS guard across its awaits and this
        // endpoint is covered by a race test; moving it from the caller's
        // thread to the runtime's pool changes the interleaving it pins.
        let task = tokio::task::spawn_local(async move {
            path_inner.tidy_secret_id_routine(storage).await;
        });

        req.ctx.add_task(task);

        resp.set_request_id(&req.id);
        resp.add_warning(
            "Tidy operation successfully started. Any information from the operation will be printed to BastionVault's \
             server logs.",
        );

        let ret = Response::respond_with_status_code(Some(resp), 202);

        Ok(Some(ret))
    }

    #[maybe_async::maybe_async]
    pub async fn handle_tidy_secret_id(
        &self,
        backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        self.tidy_secret_id(backend, req)
    }
}

