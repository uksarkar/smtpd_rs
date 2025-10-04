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
