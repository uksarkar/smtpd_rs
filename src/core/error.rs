use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidLineEnding,
    MaxSizeExceeded { limit: usize, got: usize },
    InvalidTCPStream,
    InvalidTLSConfiguration
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl std::error::Error for Error {}
