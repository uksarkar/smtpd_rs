use std::fmt::Debug;

use crate::{SmtpConfig, core::auth::AuthData};

#[derive(Debug)]
pub struct Session<'a> {
    pub authenticated: bool,
    pub from: String,
    pub to: Vec<String>,
    pub smtp_config: &'a super::SmtpConfig,
    pub remote_name: String,
    pub auth_data: Option<AuthData>,
    pub x_client_trust: bool,
    pub x_client: String,
    pub x_client_addr: String,
    pub x_client_name: String,
    pub remote_ip: String,
    pub remote_host: String,
    pub tls: bool,
}

impl<'a> Session<'a> {
    pub fn new(config: &'a SmtpConfig) -> Self {
        Self {
            authenticated: false,
            tls: false,
            from: String::new(),
            remote_name: String::new(),
            smtp_config: config,
            to: vec![],
            auth_data: None,
            remote_host: "".to_string(),
            remote_ip: "".to_string(),
            x_client: "".to_string(),
            x_client_addr: "".to_string(),
            x_client_name: "".to_string(),
            x_client_trust: false,
        }
    }

    pub fn reset(&mut self) {
        self.from = "".to_string();
        self.to = vec![];
    }
}
