use crate::{AuthData, Response, Session, core::error::Error};

pub trait SmtpHandler {
    fn handle_auth(&mut self, _: &Session, _: &AuthData) -> Result<Response, Error> {
        Ok(Response::default())
    }

    fn handle_email(&mut self, _: &Session, _: Vec<u8>) -> Result<Response, Error> {
        Ok(Response::default())
    }

    fn handle_rcpt(&mut self, _: &Session, _: &str) -> Result<Response, Error> {
        Ok(Response::default())
    }
}

pub trait SmtpHandlerFactory {
    type Handler: SmtpHandler + Send + 'static;

    fn new_handler(&self, session: &Session) -> Self::Handler;
}
