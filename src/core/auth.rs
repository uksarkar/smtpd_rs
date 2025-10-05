use std::fmt::Display;

use crate::{core::error::Error, utils};

/// Represents the supported SMTP authentication mechanisms.
///
/// These variants correspond to the authentication methods
/// that the server can advertise and handle during the SMTP session.
///
/// Currently supported mechanisms:
/// - [`Plain`] — AUTH PLAIN as defined in [RFC 4616].
/// - [`Login`] — AUTH LOGIN (non-standard but widely supported).
/// - [`CramMD5`] — AUTH CRAM-MD5 as defined in [RFC 2195].
///
/// [RFC 4616]: https://datatracker.ietf.org/doc/html/rfc4616
/// [RFC 2195]: https://datatracker.ietf.org/doc/html/rfc2195
#[derive(Debug, Clone, PartialEq)]
pub enum AuthMach {
    Plain,
    Login,
    CramMD5,
}

impl Display for AuthMach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "PLAIN",
                Self::Login => "LOGIN",
                Self::CramMD5 => "CRAM-MD5",
            }
        )
    }
}

impl AuthMach {
    pub(crate) fn from_str(line: &str) -> Result<(Self, Option<&str>), Error> {
        let (mach, credentials) = utils::parser::parse_cmd(line);

        match mach.as_str() {
            "PLAIN" => Ok((Self::Plain, credentials)),
            "LOGIN" => Ok((Self::Login, credentials)),
            "CRAM-MD5" => Ok((Self::CramMD5, credentials)),
            _ => Err(Error::UnrecognizedAuthMach),
        }
    }
}

/// Represents the parsed authentication data provided by the client.
///
/// This enum encapsulates the appropriate data structure for each supported
/// authentication mechanism. It is typically constructed internally by the
/// SMTP server when the client issues an `AUTH` command.
///
/// Passed to the [`SmtpHandler::handle_auth`](crate::core::handler::SmtpHandler::handle_auth) method.
///
/// # Example
///
/// ```
/// use smtpd_rs::{SmtpHandler, Session, AuthData, Response, Error};
///
/// struct MyHandler;
///
/// impl SmtpHandler for MyHandler {
///     fn handle_auth(
///         &mut self,
///         _session: &Session,
///         data: AuthData,
///     ) -> Result<Response, Error> {
///         let (username, password, _) = data.data();
///
///         if username == "abc" && password == "efg" {
///             return Ok(Response::Default);
///         }
///
///         Err(Error::Abort)
///     }
/// }
/// ```
///
/// # Variants
///
/// - [`Plain`] — Represents AUTH PLAIN credentials.
/// - [`Login`] — Represents AUTH LOGIN credentials.
/// - [`CramMD5`] — Represents AUTH CRAM-MD5 credentials, including the shared challenge.
#[derive(Debug, Clone)]
pub enum AuthData {
    Plain {
        username: String,
        password: String,
    },
    Login {
        username: String,
        password: String,
    },
    CramMD5 {
        username: String,
        password: String,
        shared: String,
    },
}

impl AuthData {
    pub fn data(&self) -> (&str, &str, Option<&str>) {
        match self {
            Self::Login { username, password } | Self::Plain { username, password } => {
                (username, password, None)
            }
            Self::CramMD5 {
                username,
                password,
                shared,
            } => (username, password, Some(shared)),
        }
    }
}
