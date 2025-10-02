use std::fmt::Display;

use crate::Response;

#[derive(Debug)]
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
