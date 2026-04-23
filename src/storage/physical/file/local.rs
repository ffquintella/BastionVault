//! Local-filesystem `FileTarget` — the default target kind, carrying
//! the exact behavior `FileBackend` had before the Phase-1 refactor.
//!
//! Key-to-path mapping: a key `a/b/c` lands under `<root>/a/b/_c`.
//! The leading `_` on the leaf distinguishes data files from
//! directory entries at list time so `list()` can return both
//! `leaf-name` (data) and `dir-name/` (subtree) in a single walk —
//! preserving the existing `Backend::list` contract byte-for-byte.
//!
//! Locking is implemented via `lockfile::Lockfile` on a sibling
//! `<leaf>.lock` entry, same as before. This is the only target
//! kind that has a real filesystem lock primitive; cloud targets
//! will use their own arbitration (or explicitly rely on the
//! single-writer documented assumption).

use std::{
    any::Any,
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
    thread::sleep,
    time::Duration,
};

use lockfile::Lockfile;

use crate::errors::RvError;

use super::target::FileTarget;

#[derive(Debug)]
pub struct LocalFsTarget {
    root: PathBuf,
}

impl LocalFsTarget {
    /// Construct a new target rooted at `root`. The directory is
    /// created if it does not already exist — matching the old
    /// `FileBackend::new` behavior so existing configs keep working.
    pub fn new(root: PathBuf) -> Result<Self, RvError> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Split `k` into (parent directory, leaf filename) where the
    /// leaf is prefixed with `_` so `list()` can distinguish a data
    /// file from a nested directory in a single `read_dir` pass.
    fn path_key(&self, k: &str) -> (PathBuf, String) {
        let path = self.root.join(k);
        let parent = path.parent().unwrap().to_owned();
        let key = format!("_{}", path.file_name().unwrap().to_string_lossy());
        (parent, key)
    }
}

#[maybe_async::maybe_async]
impl FileTarget for LocalFsTarget {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let (path, leaf) = self.path_key(key);
        let full = path.join(leaf);

        match File::open(full) {
            Ok(mut file) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(RvError::from(err))
                }
            }
        }
    }

    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let (path, leaf) = self.path_key(key);
        fs::create_dir_all(&path)?;
        let full = path.join(leaf);
        let mut file = File::create(full)?;
        file.write_all(value)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        if key.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendKeyInvalid);
        }

        let (path, leaf) = self.path_key(key);
        let full = path.join(leaf);
        if let Err(err) = fs::remove_file(full) {
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(());
            } else {
                return Err(RvError::from(err));
            }
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if prefix.starts_with('/') {
            return Err(RvError::ErrPhysicalBackendPrefixInvalid);
        }

        let mut path = self.root.clone();
        if !prefix.is_empty() {
            path.push(prefix);
        }

        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut names: Vec<String> = Vec::new();
        let entries = fs::read_dir(path)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stripped) = name.strip_prefix('_') {
                names.push(stripped.to_owned());
            } else {
                names.push(name + "/");
            }
        }
        Ok(names)
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any + Send>, RvError> {
        let (path, leaf) = self.path_key(lock_name);
        let full = path.join(format!("{leaf}.lock"));
        loop {
            if let Ok(lock) = Lockfile::create_with_parents(&full) {
                return Ok(Box::new(lock));
            } else {
                sleep(Duration::from_millis(100));
            }
        }
    }
}
