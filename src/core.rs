use crate::core::auth::AuthMach;
use crate::core::error::Error;
use crate::core::tls::{TlsConfig, TlsMode};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub mod auth;
pub mod error;
pub mod handler;
pub mod response;
pub mod response_error;
pub mod session;
pub mod stream;
pub mod tls;

// SMTP Server Configuration
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub hostname: String,
    pub bind_addr: String,
    pub tls_mode: TlsMode,
    pub require_tls: bool,
    pub max_message_size: Option<usize>,
    pub max_recipients: usize,
    pub timeout: Duration,
    pub auth_machs: Vec<AuthMach>,
    pub require_auth: bool,
    pub disable_reverse_dns: bool,
    pub x_client_allowed: Option<Vec<String>>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        let hostname = hostname::get()
            .map(|s| s.into_string().unwrap_or_default())
            .unwrap_or("unknown".into());

        Self {
            bind_addr: "127.0.0.1:25".to_string(),
            hostname,
            max_message_size: Some(10 * 1024 * 1024), // 10MB
            timeout: Duration::from_secs(30),
            max_recipients: 100,
            auth_machs: vec![],
            require_tls: false,
            require_auth: false,
            disable_reverse_dns: false,
            x_client_allowed: None,
            tls_mode: TlsMode::Disabled,
        }
    }
}

// Use an enum to represent different stream types
pub enum ConnectionStream {
    Tcp(TcpStream),
    #[cfg(feature = "native-tls-backend")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls-backend")]
    Rustls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for ConnectionStream {}

impl ConnectionStream {
    pub fn is_tls(&self) -> bool {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => true,
            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => true,
            Self::Tcp(_) => false,
            #[cfg(not(any(feature = "native-tls-backend", feature = "rustls-backend")))]
            _ => false,
        }
    }

    // TLS upgrade functions
    pub async fn upgrade_to_tls(self, tls_config: &TlsConfig) -> Result<Self, Error> {
        match self {
            Self::Tcp(tcp_stream) => match tls_config {
                #[cfg(feature = "native-tls-backend")]
                TlsConfig::NativeTls(identity) => {
                    use tokio_native_tls::{TlsAcceptor, native_tls};

                    let acceptor = native_tls::TlsAcceptor::builder(identity.clone()).build()?;
                    let acceptor = TlsAcceptor::from(acceptor);
                    let stream = acceptor.accept(tcp_stream).await?;

                    Ok(Self::NativeTls(stream))
                }

                #[cfg(feature = "rustls-backend")]
                TlsConfig::Rustls(config) => {
                    use std::sync::Arc;
                    use tokio_rustls::TlsAcceptor;

                    let acceptor = TlsAcceptor::from(Arc::new(config.clone()));
                    let stream = acceptor.accept(tcp_stream).await?;

                    Ok(Self::Rustls(stream))
                }
            },
            _ => Ok(self),
        }
    }
}
