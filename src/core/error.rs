use std::fmt::Display;

use tokio::time::error::Elapsed;

use crate::Response;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidLineEnding,
    MaxSizeExceeded {
        limit: usize,
        got: usize,
    },
    UnrecognizedAuthMach(String),
    InvalidTLSConfiguration,
    Response(Response),
    DecodeErr(base64::DecodeError),
    Timeout,
    #[cfg(feature = "native-tls-backend")]
    NativeTlsErr(native_tls::Error),
}

impl TryInto<Response> for Error {
    type Error = Error;

    fn try_into(self) -> Result<Response, Self::Error> {
        match self {
            Self::InvalidLineEnding => Ok(Response::syntax_error("Invalid line ending")),
            Self::DecodeErr(e) => Ok(Response::syntax_error(format!(
                "Invalid base64 encoding: {e}"
            ))),
            Self::MaxSizeExceeded { limit, got: _ } => Ok(Response::reject(format!(
                "Message size limit {limit} exceeded."
            ))),
            Self::Response(res) => Ok(res),
            Self::Timeout => Ok(Response::Raw(
                "421 4.4.2 ESMTP Service closing transmission channel after timeout exceeded"
                    .into(),
            )),
            _ => Err(self),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::DecodeErr(value)
    }
}

impl From<Elapsed> for Error {
    fn from(_: Elapsed) -> Self {
        Error::Timeout
    }
}

#[cfg(feature = "native-tls-backend")]
impl From<native_tls::Error> for Error {
    fn from(e: native_tls::Error) -> Self {
        Error::NativeTlsErr(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}
