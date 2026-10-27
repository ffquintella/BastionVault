//! `bastion-plugin-postgres`: the process-runtime entry point.

use bastion_plugin_postgres::{target::PgConnector, PostgresBackend};

fn main() {
    bastion_plugin_dynamic_sdk::process::run_main(PostgresBackend::new(PgConnector::default()))
}
