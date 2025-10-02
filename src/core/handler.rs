use crate::{AuthData, Response, Session, core::error::Error};

pub trait SmtpHandler {
    fn on_auth(&mut self, session: &Session, data: &AuthData) -> Result<Response, Error> {
        Ok(Response::default())
    }

    fn on_email(&mut self, session: &Session, data: Vec<u8>) -> Result<Response, Error> {
        Ok(Response::default())
    }

    fn on_rcpt(&mut self, session: &Session, to: &str) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

pub trait SmtpHandlerFactory {
    type Handler: SmtpHandler + Send + 'static;

    fn new_handler(&self, session: &Session) -> Self::Handler;
}
