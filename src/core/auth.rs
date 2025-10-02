use std::fmt::Display;

use crate::{core::error::Error, utils};

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
    pub fn from_str(line: &str) -> Result<(Self, Option<&str>), Error> {
        let (mach, credentials) = utils::parser::parse_cmd(line);

        match mach.as_str() {
            "PLAIN" => Ok((Self::Plain, credentials)),
            "LOGIN" => Ok((Self::Login, credentials)),
            "CRAM-MD5" => Ok((Self::CramMD5, credentials)),
            _ => Err(Error::UnrecognizedAuthMach(mach)),
        }
    }
}

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
