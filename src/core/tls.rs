use std::fmt::Debug;

// TLS Configuration
#[derive(Clone)]
pub enum TlsConfig {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(native_tls::Identity),

    #[cfg(feature = "rustls-backend")]
    Rustls(rustls::ServerConfig),
}

impl Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NativeTls(_) => f.debug_tuple("NativeTls").finish(),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TlsMode {
    /// No TLS support at all
    Disabled,

    /// Opportunistic TLS (STARTTLS supported), starts as plain TCP
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Opportunistic(TlsConfig),

    /// Required TLS via STARTTLS (plain TCP allowed initially but every command except NOOP, EHLO, STARTTLS, QUIT must be TLS)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Required(TlsConfig),

    /// Fully TLS listener (implicit TLS, no plain TCP allowed)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    Direct(TlsConfig),
}

impl TlsMode {
    /// Returns whether this mode involves TLS at all
    pub fn has_tls(&self) -> bool {
        match self {
            Self::Disabled => false,
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Opportunistic(_) | Self::Required(_) | Self::Direct(_) => true,
        }
    }

    /// Returns the TLS configuration if applicable
    pub fn config(&self) -> Option<&TlsConfig> {
        match self {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            Self::Opportunistic(cfg) | Self::Required(cfg) | Self::Direct(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Returns whether the server starts TLS immediately (Direct mode)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn is_direct_tls(&self) -> bool {
        matches!(self, Self::Direct(_))
    }

    /// Returns whether the client may start TLS (Opportunistic or Required)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn allows_starttls(&self) -> bool {
        matches!(self, Self::Opportunistic(_) | Self::Required(_))
    }

    /// Returns whether TLS is mandatory for commands (Required)
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    pub fn tls_mandatory(&self) -> bool {
        matches!(self, Self::Required(_))
    }
}
