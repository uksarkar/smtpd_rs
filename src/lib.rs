use base64::Engine;
use base64::engine::general_purpose;
use std::fmt::Write;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::system_conf::read_system_conf;

use crate::core::ConnectionStream;
pub use crate::core::SmtpConfig;
pub use crate::core::auth::{AuthData, AuthMach};
use crate::core::error::Error as CoreError;
pub use crate::core::handler::{SmtpHandler, SmtpHandlerFactory};
pub use crate::core::response::Response;
pub use crate::core::response_error::Error;
pub use crate::core::session::Session;
use crate::core::stream::StreamController;
pub use crate::core::tls::TlsConfig;
pub use crate::core::tls::TlsMode;
use crate::core::tls::TlsProvider;

mod constants;
mod core;
mod utils;

// SMTP Server
pub struct SmtpServer<T: SmtpHandlerFactory + Send + Sync + 'static> {
    config: SmtpConfig,
    handler: Arc<T>,
}

impl<T: SmtpHandlerFactory + Send + Sync + 'static> SmtpServer<T> {
    pub fn new(config: SmtpConfig, handler: T) -> Self {
        Self {
            config,
            handler: Arc::new(handler),
        }
    }

    /// Entry point: dispatch based on TLS mode
    pub async fn listen_and_serve(self) -> Result<(), std::io::Error> {
        match &self.config.tls_mode {
            TlsMode::Disabled => self.serve_plain().await,
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            TlsMode::Implicit(_) => self.serve_tls().await,
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            TlsMode::Explicit(_) | TlsMode::Required(_) => self.serve_plain().await,
        }
    }

    /// Plain TCP listener (STARTTLS optional handling done per session)
    async fn serve_plain(self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        println!("SMTP server listening on {}", self.config.bind_addr);

        let config = Arc::new(self.config);
        let handler = Arc::clone(&self.handler);

        let (resolver_config, opts) = read_system_conf()
            .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
        let resolver = Arc::new(TokioAsyncResolver::tokio(resolver_config, opts));

        #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
        let tls_provider: Option<Arc<TlsProvider>> = config
            .tls_mode
            .config()
            .and_then(|cnf| cnf.try_into().ok())
            .map(Arc::new);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("New connection from {}", peer_addr);

            let config = Arc::clone(&config);
            let handler = Arc::clone(&handler);
            let resolver = Arc::clone(&resolver);

            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            let provider = tls_provider.clone();

            let controller = StreamController::new(ConnectionStream::Tcp(stream), config.timeout);

            tokio::spawn(async move {
                if let Err(e) = handle_client(
                    controller,
                    peer_addr,
                    config,
                    handler,
                    resolver,
                    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
                    provider,
                )
                .await
                {
                    eprintln!("Error handling client {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Fully TLS listener (implicit TLS) — feature-gated
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
    async fn serve_tls(self) -> Result<(), std::io::Error> {
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let config = Arc::new(self.config);

        let tls_config = {
            let mode = &config.tls_mode;
            mode.config().expect("Direct TLS must have a TLS config")
        };

        // Bind TCP listener
        let listener = TcpListener::bind(&config.bind_addr).await?;
        println!("SMTP TLS server listening on {}", config.bind_addr);

        let handler = Arc::clone(&self.handler);

        let (resolver_config, opts) = read_system_conf().unwrap();
        let resolver = Arc::new(TokioAsyncResolver::tokio(resolver_config, opts));

        let tls_provider: Arc<TlsProvider> = tls_config
            .try_into()
            .ok()
            .map(Arc::new)
            .expect("Failed initializing tls provider");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            println!("New TLS connection from {}", peer_addr);

            let stream = tls_provider
                .accept(stream)
                .await
                .expect("Failed tls handshake.");

            let config = Arc::clone(&config);
            let handler = Arc::clone(&handler);
            let resolver = Arc::clone(&resolver);

            tokio::spawn(async move {
                // Upgrade TCP to TLS based on feature
                if let Err(e) = handle_client(
                    StreamController::new(stream, config.timeout),
                    peer_addr,
                    config,
                    handler,
                    resolver,
                    None,
                )
                .await
                {
                    eprintln!("Error handling TLS client {}: {}", peer_addr, e);
                }
            });
        }
    }
}

async fn handle_client<T: SmtpHandlerFactory + Send + Sync + 'static>(
    mut controller: StreamController,
    addr: SocketAddr,
    config: Arc<SmtpConfig>,
    handler_factory: Arc<T>,
    resolver: Arc<TokioAsyncResolver>,
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))] provider: Option<
        Arc<TlsProvider>,
    >,
) -> Result<(), CoreError> {
    let remote_host = if !config.disable_reverse_dns {
        get_remote_host(addr.ip(), &resolver).await
    } else {
        "unknown".to_string()
    };

    let mut session = Session::new(
        &config,
        addr.ip().to_string(),
        remote_host,
        controller.is_tls,
    );
    let mut handler = handler_factory.new_handler(&session);

    // Send greeting
    controller
        .write_line(format!(
            "220 {} {} ESMTP Service ready",
            config.hostname, config.appname
        ))
        .await?;

    let mut buffer = String::new();

    // Main command loop
    loop {
        buffer.clear();

        // Read command with timeout
        match controller.read_line_trimmed(&mut buffer).await {
            Ok(()) => {
                let (command, args) = utils::parser::parse_cmd(&buffer.trim());

                match command.as_str() {
                    "STARTTLS" => {
                        match handle_start_tls_cmd(args, &controller, &session) {
                            Ok(()) => {
                                // Inform client we’re ready
                                controller.write_line("220 Ready to start TLS").await?;

                                let stream: ConnectionStream = controller.into();

                                #[cfg(any(
                                    feature = "native-tls-backend",
                                    feature = "rustls-backend"
                                ))]
                                let stream = match stream {
                                    ConnectionStream::Tcp(stream) => match provider.as_ref() {
                                        Some(p) => p.accept(stream).await?,
                                        None => ConnectionStream::Tcp(stream),
                                    },
                                    _ => stream,
                                };

                                controller =
                                    StreamController::new(stream, session.smtp_config.timeout);

                                // RFC 3207 specifies that the server must discard any prior knowledge obtained from the client.
                                session.remote_name.clear();
                                session.reset();
                            }
                            Err(e) => {
                                let res: Response = e.try_into()?;
                                if !res.is_default() {
                                    controller.write_response(&res).await?;
                                    break;
                                }
                            }
                        };
                    }
                    "QUIT" => {
                        controller
                            .write_response(&Response::Raw(
                                format!(
                                    "221 2.0.0 {} {} ESMTP Service closing transmission channel",
                                    session.smtp_config.hostname, session.smtp_config.appname
                                )
                                .into(),
                            ))
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
                        // RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
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
                        if session.smtp_config.tls_mode.has_tls() {
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
                        if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
                            controller
                                .write_line("530 5.7.0 Must issue a STARTTLS command first")
                                .await?;
                            break;
                        }
                        session.reset();
                        controller.write_response(&Response::ok("OK")).await?;
                    }
                    "AUTH" => {
                        match get_auth_data(args, &mut session, &mut controller).await {
                            Ok(()) => {
                                // safe to unwrap, because the Ok() is guaranteed the data having some value
                                let auth_data = session.auth_data.as_ref().unwrap();

                                match handler.handle_auth(&session, auth_data) {
                                    Ok(res) => {
                                        session.authenticated = true;
                                        controller
                                            .write_response(&if res.is_default() {
                                                Response::auth_successful()
                                            } else {
                                                res
                                            })
                                            .await?;
                                    }
                                    Err(e) => {
                                        controller
                                            .write_response(&match e {
                                                Error::Response(res) if !res.is_default() => res,
                                                _ => Response::Raw(
                                                    "535 5.7.8 Authentication credentials invalid"
                                                        .into(),
                                                ),
                                            })
                                            .await?;
                                        break;
                                    }
                                };
                            }
                            Err(err) => {
                                let res: Response = err.try_into()?;
                                controller.write_response(&res).await?;
                                break;
                            }
                        };
                    }
                    "DATA" => {
                        match extract_mail_data(&mut session, &mut controller).await {
                            Ok(data) => {
                                match handler.handle_email(&session, data) {
                                    Ok(r) => {
                                        controller
                                            .write_response(&if r.is_default() {
                                                Response::ok("Ok: queued")
                                            } else {
                                                r
                                            })
                                            .await?;
                                    }
                                    Err(e) => {
                                        controller.write_response(&match e {
                                        Error::Response(res) if !res.is_default() => res,
                                        _ => Response::Raw("451 4.3.0 Requested action aborted: local error in processing"
                                        .into())
                                    }).await?;
                                        break;
                                    }
                                };
                            }
                            Err(err) => {
                                let res: Response = err.try_into()?;
                                controller.write_response(&res).await?;
                                break;
                            }
                        };
                    }
                    "XCLIENT" => {
                        session.x_client = args.unwrap_or_default().to_string();

                        if session.x_client_trust {
                            for item in session.x_client.split_whitespace() {
                                if let Some((k, v)) = item.trim().split_once("=") {
                                    if k.eq_ignore_ascii_case("ADDR")
                                        && std::net::IpAddr::from_str(v).is_ok()
                                    {
                                        session.x_client_addr.clear();
                                        session.x_client_addr.push_str(v);
                                    }

                                    if k.eq_ignore_ascii_case("NAME")
                                        && !v.is_empty()
                                        && !v.eq_ignore_ascii_case("[UNAVAILABLE]")
                                    {
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
                                    if let Ok(ip) = IpAddr::from_str(&session.remote_ip) {
                                        session.remote_host = get_remote_host(ip, &resolver).await;
                                    } else {
                                        session.remote_host = "unknown".to_string();
                                    }
                                }
                            }
                        }

                        controller.write_response(&Response::ok("Ok")).await?;
                    }
                    "HELP" | "VRFY" | "EXPN" => {
                        controller
                            .write_response(&Response::not_implemented())
                            .await?;
                    }
                    "MAIL" => {
                        if let Err(err) = handle_mail_cmd(args, &mut session, &mut controller).await
                        {
                            let res: Response = err.try_into()?;
                            controller.write_response(&res).await?;
                        }
                    }
                    "RCPT" => {
                        match extract_rcpt_from_arg(args, &mut session).await {
                            Ok(to) => {
                                match handler.handle_rcpt(&session, &to) {
                                    Ok(res) => {
                                        session.to.push(to);

                                        controller
                                            .write_response(&if res.is_default() {
                                                Response::Raw("250 2.1.5 Ok".into())
                                            } else {
                                                res
                                            })
                                            .await?;
                                    }
                                    Err(e) => {
                                        controller.write_response(&match e {
                                            Error::Response(res) if !res.is_default() => res,
                                            _ => Response::Raw("550 5.1.0 Requested action not taken: mailbox unavailable"
                                            .into()),
                                        }).await?;
                                        break;
                                    }
                                };
                            }

                            Err(err) => {
                                let res: Response = err.try_into()?;
                                controller.write_response(&res).await?;
                                break;
                            }
                        };
                    }
                    _ => {
                        // See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
                        controller
                            .write_response(&Response::Raw(
                                "500 5.5.2 Syntax error, command unrecognized".into(),
                            ))
                            .await?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {e}");
                let res: Response = e.try_into()?;
                controller.write_response(&res).await?;
                break;
            }
        }
    }

    Ok(())
}

// Convenience function to create server
pub async fn start_server<T: SmtpHandlerFactory + Send + Sync + 'static>(
    config: SmtpConfig,
    handler: T,
) -> Result<(), std::io::Error> {
    let server = SmtpServer::new(config, handler);
    server.listen_and_serve().await
}

// handle start tls server
fn handle_start_tls_cmd<'a>(
    args: Option<&str>,
    controller: &StreamController,
    session: &Session<'a>,
) -> Result<(), CoreError> {
    // Reject if arguments are provided
    if args.is_some_and(|s| !s.is_empty()) {
        return Err(CoreError::Response(Response::syntax_error(
            "Syntax error (no parameters allowed)",
        )));
    }

    // Reject if already in TLS
    if controller.is_tls {
        return Err(CoreError::Response(Response::bad_sequence(
            "Already in TLS mode",
        )));
    }

    // Check if TLS is configured
    if session.smtp_config.tls_mode.allows_starttls() {
        return Ok(());
    }

    Err(CoreError::Response(Response::not_implemented()))
}

async fn get_auth_data<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> Result<(), CoreError> {
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    if session.authenticated {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (already authenticated for this session)",
        )));
    }

    if session.got_from || !session.to.is_empty() {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (AUTH not permitted during mail transaction)",
        )));
    }

    if args.is_none() || args.is_some_and(|a| a.is_empty()) {
        return Err(CoreError::Response(Response::Raw(
            "501 5.5.4 Malformed AUTH input (argument required)".into(),
        )));
    }

    let res = AuthMach::from_str(&args.unwrap_or_default());
    if res.is_err() {
        return Err(CoreError::Response(Response::new(
            504,
            "Unrecognized authentication type",
            Some("5.5.4".into()),
        )));
    }

    let (mach, line) = res.unwrap();
    if !session.smtp_config.auth_machs.contains(&mach) {
        return Err(CoreError::Response(Response::Raw(
            "504 5.5.4 Unrecognized authentication type".into(),
        )));
    }

    let mut line = line.unwrap_or_default().to_string();
    let data: Option<AuthData>;

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
                return Err(CoreError::Response(Response::syntax_error(
                    "Syntax error (unable to parse)",
                )));
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
                return Err(CoreError::Response(Response::syntax_error(
                    "Authentication cancelled",
                )));
            }

            let buf = utils::parser::parse_b64_line(&line)?;
            let fields: Vec<&[u8]> = buf.split(|&b| b == b' ').collect();

            if fields.len() < 2 {
                return Err(CoreError::Response(Response::syntax_error(
                    "Syntax error (unable to parse)",
                )));
            }

            data = Some(AuthData::CramMD5 {
                username: String::from_utf8_lossy(fields[0]).to_string(),
                password: String::from_utf8_lossy(fields[1]).to_string(),
                shared,
            });
        }
    };

    if data.is_none() {
        return Err(CoreError::Response(Response::new(
            535,
            "Authentication credentials invalid",
            Some("5.7.8".into()),
        )));
    }

    session.auth_data = data;

    Ok(())
}

async fn handle_mail_cmd<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> Result<(), CoreError> {
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    let res = crate::utils::parser::parse_mail_from(args.unwrap_or_default());
    if res.is_none() {
        return Err(CoreError::Response(Response::syntax_error(
            "Syntax error in FROM parameter",
        )));
    }

    let (from, params) = res.unwrap();
    let has_params = params.as_ref().is_some_and(|p| !p.is_empty());

    let size = match params {
        Some(arg_str) => crate::utils::parser::parse_size(arg_str.as_str()),
        None => None,
    };

    if has_params && size.is_none() {
        return Err(CoreError::Response(Response::syntax_error(
            "Invalid SIZE parameter",
        )));
    }

    if let Some(max_size) = session.smtp_config.max_message_size {
        if let Some(s) = size {
            if max_size < s {
                return Err(CoreError::Response(Response::new(
                    552,
                    format!("Max size limit ({max_size}) exceeded"),
                    Some("5.3.4".into()),
                )));
            }
        }
    }

    session.from = from.to_string();
    session.got_from = true;
    session.to.clear();
    controller.write_response(&Response::ok("Ok")).await?;
    Ok(())
}

async fn extract_rcpt_from_arg<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
) -> Result<String, CoreError> {
    if session.smtp_config.tls_mode.tls_mandatory() && !session.tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    if !session.got_from {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL required before RCPT)",
        )));
    }

    if session.smtp_config.max_recipients == session.to.len() {
        return Err(CoreError::Response(Response::new(
            452,
            "Max recipient limit exceeded",
            Some("4.5.3".into()),
        )));
    }

    let to = crate::utils::parser::parse_rcpt_to(&args.unwrap_or_default());
    if to.is_none() {
        return Err(CoreError::Response(Response::syntax_error(
            "Syntax error in parameters or arguments (invalid TO parameter)",
        )));
    }

    Ok(to.unwrap().to_string())
}

async fn extract_mail_data<'a>(
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> Result<Vec<u8>, CoreError> {
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    if !session.got_from || session.to.len() == 0 {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL & RCPT required before DATA)",
        )));
    }

    controller
        .write_line("354 Start mail input; end with <CR><LF>.<CR><LF>")
        .await?;

    let data = controller
        .read_mail_data(session.smtp_config.max_message_size)
        .await?;

    Ok(data)
}

async fn get_remote_host(ip: IpAddr, resolver: &TokioAsyncResolver) -> String {
    match timeout(Duration::from_secs(30), resolver.reverse_lookup(ip)).await {
        Ok(res) => res
            .ok()
            .and_then(|lookup| lookup.iter().next().map(|n| n.to_utf8()))
            .unwrap_or_else(|| "unknown".to_string()),
        Err(_) => "unknown".to_string(),
    }
}
