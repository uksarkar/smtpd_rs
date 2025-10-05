use std::borrow::Cow;
use std::fmt::{self, Display, Formatter};

/// Represents an SMTP response that can be written to the client stream.
///
/// Each variant corresponds to a different style of reply.
/// `Display` provides the formatted output suitable for SMTP wire protocol.
///
/// The `Default` variant represents “no reply” and should be skipped when writing.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Response {
    /// A no-op response, ignored when sending.
    #[default]
    Default,

    /// Custom response with status code, message, and optional RFC code.
    Custom {
        status: usize,
        message: Cow<'static, str>,
        rfc: Option<Cow<'static, str>>,
    },

    /// Standard 250 “OK” response.
    Ok(Cow<'static, str>),

    /// 220 informational greeting or connection message.
    Info(Cow<'static, str>),

    /// Raw response for full manual control.
    Raw(Cow<'static, str>),
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Response::Raw(s) => write!(f, "{s}"),
            Response::Custom {
                status,
                message,
                rfc,
            } => {
                let rfc_suffix = rfc
                    .as_ref()
                    .filter(|s| !s.is_empty())
                    .map(|s| format!(" {s}"))
                    .unwrap_or_default();
                write!(f, "{status}{rfc_suffix} {message}")
            }
            Response::Info(msg) => write!(f, "220 {msg}"),
            Response::Ok(msg) => write!(f, "250 2.0.0 {msg}"),
            Response::Default => Ok(()),
        }
    }
}

impl Response {
    /// Create a fully custom SMTP response.
    pub fn new(
        status: usize,
        message: impl Into<Cow<'static, str>>,
        rfc: impl Into<Option<Cow<'static, str>>>,
    ) -> Self {
        Self::Custom {
            status,
            message: message.into(),
            rfc: rfc.into(),
        }
    }

    pub fn ok(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Ok(message.into())
    }

    pub fn info(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Info(message.into())
    }

    pub fn reject(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(530, message, Some("5.7.0".into()))
    }

    pub fn auth_successful() -> Self {
        Self::new(235, "Authentication successful", Some("2.7.0".into()))
    }

    pub fn syntax_error(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(501, message, Some("5.5.4".into()))
    }

    pub fn not_implemented() -> Self {
        Self::new(502, "Command not implemented", Some("5.5.1".into()))
    }

    pub fn bad_sequence(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(503, message, Some("5.5.1".into()))
    }

    #[inline]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }
}
