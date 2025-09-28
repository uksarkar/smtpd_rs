// TLS Configuration
pub enum TlsConfig {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(native_tls::Identity),

    #[cfg(feature = "rustls-backend")]
    Rustls {
        certs: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    },
}
