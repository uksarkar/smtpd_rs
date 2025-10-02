use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone, Default)]
pub enum Response {
    #[default]
    Default,
    Custom {
        status: usize,
        message: Cow<'static, str>,
        rfc: Option<Cow<'static, str>>,
    },
    Ok(Cow<'static, str>),
    Info(Cow<'static, str>),
    Raw(Cow<'static, str>),
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Raw(s) => return write!(f, "{s}"),
            Response::Custom { status, message, rfc } => {
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
}
