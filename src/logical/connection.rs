use rustls::pki_types::CertificateDer;

#[derive(Default, Clone)]
pub struct Connection {
    pub peer_addr: String,
    pub peer_tls_cert: Option<Vec<CertificateDer<'static>>>,
}
