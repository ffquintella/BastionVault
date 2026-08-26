use std::default::Default;

use bv_errors::RvError;

use crate::{Backend, BackendEntry};

#[derive(Default)]
pub struct MockBackend(());

#[maybe_async::maybe_async]
impl Backend for MockBackend {
    fn backend_kind(&self) -> &'static str {
        "mock"
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>, RvError> {
        Ok(Vec::new())
    }

    async fn get(&self, _k: &str) -> Result<Option<BackendEntry>, RvError> {
        Ok(None)
    }

    async fn put(&self, _entry: &BackendEntry) -> Result<(), RvError> {
        Ok(())
    }

    async fn delete(&self, _k: &str) -> Result<(), RvError> {
        Ok(())
    }
}

impl MockBackend {
    pub fn new() -> Self {
        MockBackend(())
    }
}
