use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone)]
pub struct Response {
    pub status: usize,
    pub message: Cow<'static, str>,
    pub rfc: Option<Cow<'static, str>>,
    raw: bool,
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.raw {
            return write!(f, "{}", self.message);
        }

        let rfc = self
            .rfc
            .as_ref()
            .and_then(|s| {
                if !s.is_empty() {
                    Some(format!(" {}", s))
                } else {
                    None
                }
            })
            .unwrap_or_default();

        write!(f, "{}{} {}", self.status, rfc, self.message)
    }
}

impl Response {
    pub fn new(
        status: usize,
        message: impl Into<Cow<'static, str>>,
        rfc: impl Into<Option<Cow<'static, str>>>,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            rfc: rfc.into(),
            raw: false,
        }
    }

    pub fn ok(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(250, message, Some("2.0.0".into()))
    }

    pub fn info(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(220, message, None)
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

    pub(crate) fn raw(res: String) -> Self {
        Self {
            status: 0,
            message: res.into(),
            rfc: None,
            raw: true,
        }
    }
}
