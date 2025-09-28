use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::core::ConnectionStream;
pub use crate::core::SmtpConfig;
pub use crate::core::tls::TlsConfig;

mod core;

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

    // Send greeting
    controller
        .write_line("220 localhost ESMTP Service Ready")
        .await?;

    let mut buffer = String::new();

    // Main command loop
    loop {
        buffer.clear();

        // Read command with timeout
        match timeout(
            config.starttls_timeout,
            controller.read_line_trimmed(&mut buffer),
        )
        .await
        {
            Ok(Ok(())) => {
                // Process command
                let command = buffer.trim().to_uppercase();

                match command.as_str() {
                    "STARTTLS" => {
                        if controller.stream.is_tls() {
                            controller.write_line("503 Already in TLS mode").await?;
                            continue;
                        }

                        match &config.tls_config {
                            Some(tls_config) => {
                                controller.write_line("220 Ready to start TLS").await?;

                                let (stream, res) =
                                    controller.stream.upgrade_to_tls(tls_config).await;
                                controller.stream = stream;

                                match res {
                                    Ok(_) => {
                                        println!("TLS upgrade successful");
                                    }
                                    Err(e) => {
                                        eprintln!("TLS upgrade failed: {}", e);
                                        controller.write_line("454 TLS negotiation failed").await?;
                                        break;
                                    }
                                }
                            }
                            None => {
                                controller.write_line("502 TLS not available").await?;
                            }
                        }
                    }
                    "QUIT" => {
                        controller.write_line("221 Bye").await?;
                        break;
                    }
                    "EHLO" | "HELO" => {
                        let response = if controller.stream.is_tls() {
                            format!("250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN")
                        } else {
                            format!("250-localhost\r\n250-STARTTLS\r\n250 AUTH PLAIN")
                        };
                        controller.write_line(&response).await?;
                    }
                    "NOOP" => {
                        controller.write_line("250 OK").await?;
                    }
                    "RSET" => {
                        controller.write_line("250 OK").await?;
                    }
                    _ => {
                        // Handle other SMTP commands here
                        if controller.stream.is_tls() {
                            controller.write_line("250 OK").await?;
                        } else {
                            // For non-TLS connections, suggest STARTTLS for sensitive commands
                            if is_sensitive_command(&command) {
                                controller
                                    .write_line("530 Must issue STARTTLS first")
                                    .await?;
                            } else {
                                controller.write_line("250 OK").await?;
                            }
                        }
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

fn is_sensitive_command(command: &str) -> bool {
    matches!(command, "AUTH" | "MAIL" | "RCPT" | "DATA")
}

// Convenience function to create server
pub async fn start_server(config: SmtpConfig) -> Result<()> {
    let server = SmtpServer::new(config);
    server.listen_and_serve().await
}
