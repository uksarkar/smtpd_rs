use std::fmt::Display;

use crate::Response;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidLineEnding,
    MaxSizeExceeded { limit: usize, got: usize },
    UnrecognizedAuthMach(String),
    InvalidTLSConfiguration,
    Response(Response),
    DecodeErr(base64::DecodeError),
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

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}
