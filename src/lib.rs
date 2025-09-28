use anyhow::Result;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

// StreamController with proper generics
pub struct StreamController<S> {
    stream: S,
}

impl<S> StreamController<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> StreamController<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn write_line(&mut self, line: impl AsRef<str>) -> Result<()> {
        self.stream.write_all(line.as_ref().as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn write_response(&mut self, res: &impl fmt::Display) -> Result<()> {
        self.write_line(&res.to_string()).await
    }

    pub async fn read_line_trimmed(&mut self, dist: &mut String) -> Result<()> {
        let mut reader = BufReader::new(&mut self.stream);
        dist.clear();
        reader.read_line(dist).await?;

        let start_trimmed = dist.trim_start();
        let start_len_diff = dist.len() - start_trimmed.len();
        if start_len_diff > 0 {
            dist.drain(0..start_len_diff);
        }

        let end_trimmed = dist.trim_end();
        let end_len_diff = dist.len() - end_trimmed.len();
        if end_len_diff > 0 {
            dist.truncate(end_trimmed.len());
        }

        Ok(())
    }

    pub async fn read_line_crlf(&mut self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut reader = BufReader::new(&mut self.stream);
        buffer.clear();
        reader.read_until(b'\n', buffer).await?;

        if buffer.ends_with(b"\r\n") {
            Ok(())
        } else if buffer.ends_with(b"\n") {
            buffer.pop();
            if buffer.ends_with(b"\r") {
                buffer.push(b'\n');
                Ok(())
            } else {
                buffer.push(b'\r');
                buffer.push(b'\n');
                Ok(())
            }
        } else {
            Err(anyhow::anyhow!("Invalid line ending"))
        }
    }

    pub async fn read_mail_data(&mut self, max_size: Option<usize>) -> Result<Vec<u8>> {
        let mut data = vec![];
        let mut line = vec![];
        let mut total_size = 0;

        loop {
            line.clear();
            self.read_line_crlf(&mut line).await?;

            if line == b".\r\n" {
                break;
            }

            let processed_line = if line.starts_with(b".") {
                &line[1..]
            } else {
                &line
            };

            if let Some(max) = max_size {
                if total_size + processed_line.len() > max {
                    return Err(anyhow::anyhow!(
                        "Message size limit exceeded: {} > {}",
                        total_size + processed_line.len(),
                        max
                    ));
                }
            }

            data.extend_from_slice(processed_line);
            total_size += processed_line.len();
        }

        Ok(data)
    }
}

// TLS Configuration
pub enum TlsConfig {
    #[cfg(feature = "native-tls-backend")]
    NativeTls(native_tls::Identity),

    #[cfg(feature = "rustls-backend")]
    Rustls {
        certs: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
    },
}

// SMTP Server Configuration
pub struct SmtpConfig {
    pub bind_addr: String,
    pub tls_config: Option<TlsConfig>,
    pub greeting: String,
    pub max_message_size: Option<usize>,
    pub max_recipients: Option<usize>,
    pub starttls_timeout: Duration,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:25".to_string(),
            tls_config: None,
            greeting: "220 localhost ESMTP Service Ready".to_string(),
            max_message_size: Some(10 * 1024 * 1024), // 10MB
            starttls_timeout: Duration::from_secs(30),
            max_recipients: Some(100),
        }
    }
}

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

// Use an enum to represent different stream types
pub enum ConnectionStream {
    Tcp(TcpStream),
    #[cfg(feature = "native-tls-backend")]
    NativeTls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls-backend")]
    Rustls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            ConnectionStream::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "native-tls-backend")]
            ConnectionStream::NativeTls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "rustls-backend")]
            ConnectionStream::Rustls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for ConnectionStream {}

async fn handle_client(stream: TcpStream, config: Arc<SmtpConfig>) -> Result<()> {
    let mut controller = StreamController::new(ConnectionStream::Tcp(stream));

    // Send greeting
    controller.write_response(&config.greeting).await?;

    let mut buffer = String::new();
    let mut tls_upgraded = false;

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
                        if tls_upgraded {
                            controller.write_line("503 Already in TLS mode").await?;
                            continue;
                        }

                        match &config.tls_config {
                            Some(tls_config) => {
                                controller.write_line("220 Ready to start TLS").await?;

                                // Upgrade to TLS - take ownership and replace
                                let current_stream = std::mem::replace(
                                    &mut controller.stream,
                                    ConnectionStream::Tcp(TcpStream::connect("0.0.0.0:0").await?), // dummy
                                );

                                match upgrade_to_tls(current_stream, tls_config).await {
                                    Ok(tls_stream) => {
                                        controller.stream = tls_stream;
                                        tls_upgraded = true;
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
                        let response = if tls_upgraded {
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
                        if tls_upgraded {
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

// TLS upgrade functions
async fn upgrade_to_tls(
    stream: ConnectionStream,
    tls_config: &TlsConfig,
) -> Result<ConnectionStream> {
    match stream {
        ConnectionStream::Tcp(tcp_stream) => match tls_config {
            #[cfg(feature = "native-tls-backend")]
            TlsConfig::NativeTls(identity) => {
                use tokio_native_tls::{TlsAcceptor, native_tls};

                let acceptor = native_tls::TlsAcceptor::builder(identity.clone()).build()?;
                let acceptor = TlsAcceptor::from(acceptor);
                let tls_stream = acceptor.accept(tcp_stream).await?;

                Ok(ConnectionStream::NativeTls(tls_stream))
            }

            #[cfg(feature = "rustls-backend")]
            TlsConfig::Rustls { certs, key } => {
                use std::sync::Arc;
                use tokio_rustls::{TlsAcceptor, rustls};

                let mut config = rustls::ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(certs.clone(), key.clone())?;

                config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

                let acceptor = TlsAcceptor::from(Arc::new(config));
                let tls_stream = acceptor.accept(tcp_stream).await?;

                Ok(ConnectionStream::Rustls(tls_stream))
            }

            _ => Err(anyhow::anyhow!("TLS backend not compiled")),
        },
        _ => Err(anyhow::anyhow!("Expected TCP stream for TLS upgrade")),
    }
}

// Convenience function to create server
pub async fn start_server(config: SmtpConfig) -> Result<()> {
    let server = SmtpServer::new(config);
    server.listen_and_serve().await
}
