#[derive(Debug, Clone, Default)]
pub enum FailureMode {
    #[default]
    FailOpenFalse,
    FailOpenTrue,
}

#[derive(Debug, Clone, Default)]
pub struct OcspConfig {
    pub enable: bool,
    pub extra_ca_pem: Vec<Vec<u8>>,
    pub servers_override: Vec<String>,
    pub failure_mode: FailureMode,
    pub query_all_servers: bool,
}
