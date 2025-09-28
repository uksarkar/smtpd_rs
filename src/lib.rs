use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::core::ConnectionStream;
pub use crate::core::SmtpConfig;
use crate::core::auth::{AuthData, AuthMach};
use crate::core::response::Response;
use crate::core::session::Session;
pub use crate::core::tls::TlsConfig;

mod constants;
mod core;
mod utils;

// SMTP Server
pub struct SmtpServer {
    config: SmtpConfig,
}

impl SmtpServer {
    pub fn new(config: SmtpConfig) -> Self {
        Self { config }
    }

    pub async fn listen_and_serve(self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        println!("SMTP server listening on {}", self.config.bind_addr);

        let config = Arc::new(self.config);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("New connection from {}", peer_addr);

            let config = Arc::clone(&config);

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, config).await {
                    eprintln!("Error handling client {}: {}", peer_addr, e);
                }
            });
        }
    }
}

async fn handle_client(stream: TcpStream, config: Arc<SmtpConfig>) -> Result<()> {
    let mut controller = core::stream::StreamController::new(ConnectionStream::Tcp(stream));
    let mut session = Session::new(&config);

    // Send greeting
    controller
        .write_line("220 localhost ESMTP Service Ready")
        .await?;

    let mut buffer = String::new();

    // Main command loop
    loop {
        buffer.clear();

        // Read command with timeout
        match timeout(config.timeout, controller.read_line_trimmed(&mut buffer)).await {
            Ok(Ok(())) => {
                let (command, args) = utils::parser::parse_cmd(&buffer.trim());

                match command.as_str() {
                    "STARTTLS" => {
                        if controller.stream.is_tls() {
                            controller.write_line("503 Already in TLS mode").await?;
                            // continue;
                        }

                        match &session.smtp_config.tls_config {
                            Some(tls_config) => {
                                controller.write_line("220 Ready to start TLS").await?;

                                let (stream, res) =
                                    controller.stream.upgrade_to_tls(tls_config).await;
                                controller.stream = stream;

                                match res {
                                    Ok(_) => {
                                        println!("TLS upgrade successful");
                                        continue;
                                    }
                                    Err(e) => {
                                        eprintln!("TLS upgrade failed: {}", e);

                                        controller
                                            .write_response(&Response::new(
                                                454,
                                                "TLS negotiation failed",
                                                None,
                                            ))
                                            .await?;

                                        break;
                                    }
                                };
                            }
                            None => {
                                controller
                                    .write_response(&Response::new(502, "TLS not available", None))
                                    .await?;
                            }
                        }
                    }
                    "QUIT" => {
                        controller
                            .write_response(&Response::new(221, "Bye", None))
                            .await?;
                        break;
                    }
                    "HELO" => {
                        // RFC 2821 section 4.1.4 specifies that HELO has the same effect as RSET, so reset for HELO too.
                        session.reset();
                        session.remote_name = args.unwrap_or_default().to_string();

                        controller
                            .write_response(&Response::ok(format!(
                                "{} greets {}",
                                session.smtp_config.hostname, session.remote_name
                            )))
                            .await?;
                    }
                    "EHLO" => {
                        session.reset();
                        session.remote_name = args.unwrap_or_default().to_string();

                        let mut message = String::with_capacity(256);

                        // Hostname + greeting
                        writeln!(
                            message,
                            "250-{} greets {}",
                            session.smtp_config.hostname, session.remote_name
                        )
                        .unwrap();

                        // RFC 1870: "SIZE 0" means no limit
                        writeln!(
                            message,
                            "250-SIZE {}",
                            session.smtp_config.max_message_size.unwrap_or_default()
                        )
                        .unwrap();

                        // STARTTLS if enabled
                        if let Some(_) = session.smtp_config.tls_config {
                            writeln!(message, "250-STARTTLS").unwrap();
                        }

                        // AUTH if mechanisms exist
                        if !session.smtp_config.auth_machs.is_empty() {
                            let joined = session
                                .smtp_config
                                .auth_machs
                                .iter()
                                .map(|m| m.to_string())
                                .collect::<Vec<_>>()
                                .join(" ");

                            writeln!(message, "250-AUTH {}", joined).unwrap();
                        }

                        // Final line must not have "-"
                        message.push_str("250 ENHANCEDSTATUSCODES");

                        controller.write_line(message).await?;
                    }
                    "NOOP" => {
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "RSET" => {
                        session.reset();
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "AUTH" => {
                        let res = AuthMach::from_str(&args.unwrap_or_default());
                        if res.is_err() {
                            controller
                                .write_response(&Response::new(
                                    504,
                                    format!("Unrecognized authentication type"),
                                    Some("5.5.4".into()),
                                ))
                                .await?;
                            break;
                        }

                        let (mach, line) = res.unwrap();

                        let mut line = line.unwrap_or_default().to_string();
                        let mut data: Option<AuthData> = None;

                        match mach {
                            AuthMach::Plain => {
                                if line.is_empty() {
                                    controller
                                        .write_response(&Response::new(334, " ", None))
                                        .await?;

                                    line.clear();
                                    controller.read_line_trimmed(&mut line).await?;
                                }

                                let parsed_data = utils::parser::parse_b64_line(&line)?;

                                let parts: Vec<&[u8]> = parsed_data.split(|&b| b == 0).collect();

                                if parts.len() != 3 {
                                    controller
                                        .write_response(&Response::syntax_error(
                                            "Syntax error (unable to parse)",
                                        ))
                                        .await?;
                                    break;
                                }

                                data = Some(AuthData::Plain {
                                    username: String::from_utf8_lossy(parts[1]).to_string(),
                                    password: String::from_utf8_lossy(parts[2]).to_string(),
                                });
                            }
                            AuthMach::Login => {
                                if line.is_empty() {
                                    let encoded = general_purpose::STANDARD.encode("Username:");
                                    controller
                                        .write_response(&Response::new(334, encoded, None))
                                        .await?;

                                    line.clear();
                                    controller.read_line_trimmed(&mut line).await?;
                                }

                                let username = utils::parser::parse_b64_line(&line)?;

                                let encoded = general_purpose::STANDARD.encode("Password:");
                                controller
                                    .write_response(&Response::new(334, encoded, None))
                                    .await?;

                                line.clear();
                                controller.read_line_trimmed(&mut line).await?;

                                let password = utils::parser::parse_b64_line(&line)?;

                                data = Some(AuthData::Login {
                                    username: String::from_utf8_lossy(&username).to_string(),
                                    password: String::from_utf8_lossy(&password).to_string(),
                                });
                            }
                            AuthMach::CramMD5 => {
                                let shared = format!(
                                    "<{}.{}@{}>",
                                    std::process::id(),
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_nanos(),
                                    session.smtp_config.hostname
                                );

                                let encoded = general_purpose::STANDARD.encode(&shared);
                                controller
                                    .write_response(&Response::new(334, encoded, None))
                                    .await?;

                                line.clear();
                                controller.read_line_trimmed(&mut line).await?;

                                if line == "*" {
                                    controller
                                        .write_response(&Response::syntax_error(
                                            "Authentication cancelled",
                                        ))
                                        .await?;
                                    break;
                                }

                                let buf = utils::parser::parse_b64_line(&line)?;
                                let fields: Vec<&[u8]> = buf.split(|&b| b == b' ').collect();

                                if fields.len() < 2 {
                                    controller
                                        .write_response(&Response::syntax_error(
                                            "Syntax error (unable to parse)",
                                        ))
                                        .await?;
                                    break;
                                }

                                data = Some(AuthData::CramMD5 {
                                    username: String::from_utf8_lossy(fields[0]).to_string(),
                                    password: String::from_utf8_lossy(fields[1]).to_string(),
                                    shared,
                                });
                            }
                        };

                        if data.is_none() {
                            controller
                                .write_response(&Response::new(
                                    535,
                                    "Authentication credentials invalid",
                                    Some("5.7.8".into()),
                                ))
                                .await?;
                            break;
                        }

                        session.auth_data = data;

                        // TODO
                        controller
                            .write_response(&Response::not_implemented())
                            .await?;
                    }
                    "DATA" => {
                        if config.require_tls && !controller.stream.is_tls() {
                            controller
                                .write_response(&Response::reject(
                                    "Must issue a STARTTLS command first",
                                ))
                                .await?;
                            continue;
                        }

                        if config.require_auth && !session.authenticated {
                            controller
                                .write_response(&Response::reject("Authentication required"))
                                .await?;
                            continue;
                        }

                        if session.from.len() == 0 || session.to.len() == 0 {
                            controller
                                .write_response(&Response::bad_sequence(
                                    "Bad sequence of commands (MAIL & RCPT required before DATA)",
                                ))
                                .await?;
                            continue;
                        }

                        controller
                            .write_line("354 Start mail input; end with <CR><LF>.<CR><LF>")
                            .await?;

                        // TODO: handle max message size limit error
                        let data = controller.read_mail_data(config.max_message_size).await?;

                        // TODO: handle data
                        let data_str = String::from_utf8_lossy(&data);
                        println!("{}", data_str);

                        controller
                            .write_response(&Response::ok("Ok: queued"))
                            .await?;
                    }
                    "XCLIENT" => {
                        session.x_client = args.unwrap_or_default().to_string();

                        for item in session.x_client.split_whitespace() {
                            if let Some((k, v)) = item.trim().split_once("=") {
                                let k = k.to_ascii_uppercase();

                                if k == "ADDR" && std::net::IpAddr::from_str(v).is_ok() {
                                    session.x_client_addr.clear();
                                    session.x_client_addr.push_str(v);
                                }

                                if k == "NAME" && !v.is_empty() && v != "[UNAVAILABLE]" {
                                    session.x_client_name.clear();
                                    session.x_client_name.push_str(v);
                                }
                            }
                        }

                        if session.x_client_addr.len() > 7 {
                            session.remote_ip = session.x_client_addr.to_owned();

                            if session.x_client_name.len() > 4 {
                                session.remote_host = session.x_client_name.to_owned();
                            } else {
                                session.remote_host =
                                    std::net::IpAddr::from_str(&session.remote_ip)
                                        .ok()
                                        .and_then(|ip| dns_lookup::lookup_addr(&ip).ok())
                                        .filter(|host| !host.is_empty())
                                        .unwrap_or_else(|| "unknown".to_string());
                            }
                        }

                        controller.write_response(&Response::ok("Ok")).await?;
                    }
                    _ => {
                        controller
                            .write_response(&Response::syntax_error("Unrecognizable command"))
                            .await?;
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("Read error: {}", e);
                break;
            }
            Err(_) => {
                eprintln!("Timeout waiting for command");
                controller.write_line("421 Timeout").await?;
                break;
            }
        }
    }

    Ok(())
}

// Convenience function to create server
pub async fn start_server(config: SmtpConfig) -> Result<()> {
    let server = SmtpServer::new(config);
    server.listen_and_serve().await
}
