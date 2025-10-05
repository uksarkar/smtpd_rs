use std::fmt::Debug;

use tokio::net::TcpStream;

use crate::{
    Response,
    core::{ConnectionStream, error::Error},
};

#[derive(Clone)]
pub enum TlsConfig {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(native_tls::Identity),

    #[cfg(feature = "rustls-backend")]
    Rustls(rustls::ServerConfig),
}

impl core::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => write!(f, "TlsConfig::NativeTls(<identity>)"),
            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => write!(f, "TlsConfig::Rustls(<config>)"),
        }
    }
}

#[derive(Clone)]
pub(crate) enum TlsProvider {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(tokio_native_tls::TlsAcceptor),

    #[cfg(feature = "rustls-backend")]
    Rustls(tokio_rustls::TlsAcceptor),
}

impl core::fmt::Debug for TlsProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(_) => f.write_str("TlsProvider::NativeTls"),
            #[cfg(feature = "rustls-backend")]
            Self::Rustls(_) => f.write_str("TlsProvider::Rustls"),
        }
    }
}

impl TryFrom<&TlsConfig> for TlsProvider {
    type Error = Error;

    fn try_from(value: &TlsConfig) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "native-tls-backend")]
            TlsConfig::NativeTls(identity) => {
                use tokio_native_tls::{TlsAcceptor, native_tls};
                let acceptor = native_tls::TlsAcceptor::builder(identity.clone()).build()?;
                Ok(Self::NativeTls(TlsAcceptor::from(acceptor)))
            }

            #[cfg(feature = "rustls-backend")]
            TlsConfig::Rustls(config) => {
                use std::sync::Arc;
                use tokio_rustls::TlsAcceptor;
                Ok(Self::Rustls(TlsAcceptor::from(Arc::new(config.clone()))))
            }

            #[allow(unreachable_patterns)]
            _ => Err(Error::Response(Response::not_implemented())),
        }
    }
}

impl TlsProvider {
    pub async fn accept(&self, stream: TcpStream) -> Result<ConnectionStream, Error> {
        match self {
            #[cfg(feature = "native-tls-backend")]
            Self::NativeTls(acceptor) => {
                Ok(ConnectionStream::NativeTls(acceptor.accept(stream).await?))
            }

            #[cfg(feature = "rustls-backend")]
            Self::Rustls(acceptor) => Ok(ConnectionStream::Rustls(acceptor.accept(stream).await?)),

            #[allow(unreachable_patterns)]
            _ => Err(Error::Response(Response::not_implemented())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TlsMode {
    /// No TLS support at all
    Disabled,

    /// Explicit TLS (STARTTLS supported, but optional)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Explicit(TlsConfig),

    /// Required TLS via STARTTLS (all commands except NOOP, EHLO, STARTTLS, QUIT must be over TLS)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Required(TlsConfig),

    /// Implicit TLS (always TLS, like SMTPS on port 465)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Implicit(TlsConfig),
}

impl TlsMode {
    /// Returns whether this mode involves TLS at all
    pub fn has_tls(&self) -> bool {
        match self {
            Self::Disabled => false,
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Explicit(_) | Self::Required(_) | Self::Implicit(_) => true,
        }
    }

    /// Returns the TLS configuration if applicable
    pub fn config(&self) -> Option<&TlsConfig> {
        match self {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Explicit(cfg) | Self::Required(cfg) | Self::Implicit(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Returns whether the server starts TLS immediately (Direct mode)
    pub fn is_direct_tls(&self) -> bool {
        match self {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Implicit(_) => true,
            _ => false,
        }
    }

    /// Returns whether the client may start TLS (Opportunistic or Required)
    pub fn allows_starttls(&self) -> bool {
        match self {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Explicit(_) | Self::Required(_) => true,
            _ => false,
        }
    }

    /// Returns whether TLS is mandatory for commands (Required)
    pub fn tls_mandatory(&self) -> bool {
        match self {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Required(_) => true,
            _ => false,
        }
    }
}
