use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::core::ConnectionStream;
pub use crate::core::SmtpConfig;
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
                    "NOOP" => {
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "RSET" => {
                        session.reset();
                        controller.write_response(&Response::ok("OK")).await?;
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
