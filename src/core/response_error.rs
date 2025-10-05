use std::{convert::Infallible, fmt::Display};

use crate::Response;

/// Error for handler operations.
///
/// Can either:
/// - `Abort`: terminate processing silently (no client response)
/// - `Response`: send a custom response to the client
#[derive(Debug, Clone)]
pub enum Error {
    Abort,
    Response(Response),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abort => write!(f, "Aborted"),
            Self::Response(res) => write!(f, "{res}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Response> for Error {
    fn from(res: Response) -> Self {
        Self::Response(res)
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

/// Convenient alias for handler results
pub type Result = std::result::Result<Response, Error>;
