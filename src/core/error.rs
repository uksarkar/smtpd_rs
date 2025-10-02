use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidLineEnding,
    MaxSizeExceeded { limit: usize, got: usize },
    UnrecognizedAuthMach(String),
    InvalidTLSConfiguration,
    InvalidData
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}
