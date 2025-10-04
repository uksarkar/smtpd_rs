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
    pub got_from: bool,
}

impl<'a> Session<'a> {
    pub fn new(config: &'a SmtpConfig, remote_ip: String, remote_host: String, is_tls: bool) -> Self {
        let x_client_trust = config
            .x_client_allowed
            .as_ref()
            .is_some_and(|ips| ips.contains(&remote_ip));

        Self {
            authenticated: false,
            tls: is_tls,
            from: String::with_capacity(256),
            remote_name: String::with_capacity(256),
            smtp_config: config,
            to: vec![],
            auth_data: None,
            remote_host,
            remote_ip,
            x_client: "".to_string(),
            x_client_addr: "".to_string(),
            x_client_name: "".to_string(),
            x_client_trust,
            got_from: false,
        }
    }

    pub fn reset(&mut self) {
        self.from.clear();
        self.to.clear();
        self.got_from = false;
    }
}
