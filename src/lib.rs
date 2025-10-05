//! # smtpd_rs
//!
//! `smtpd_rs` is an asynchronous, extensible SMTP server library built on top of `tokio`.
//! Inspired by [smtpd](https://github.com/mhale/smtpd).
//! It provides flexible support for authentication, TLS, and custom handling
//! of SMTP commands.
//!
//! ## Features
//! - Asynchronous SMTP server using Tokio.
//! - Supports authentication mechanisms: [`AuthMach::Plain`], [`AuthMach::Login`], [`AuthMach::CramMD5`].
//! - TLS support (STARTTLS and implicit TLS) with optional `native-tls` (feature `native-tls-backend`) or `rustls` (feature `rustls-backend`) backend.
//! - Customizable handlers for AUTH, RCPT, and DATA commands via the Handler struct's [`SmtpHandler::handle_auth`], [`SmtpHandler::handle_email`], and [`SmtpHandler::handle_rcpt`] method
//! - Configurable limits for message size and recipients.
//!
//! ## Example
//! ```no_run
//! use smtpd_rs::{async_trait, start_server, SmtpConfig, AuthMach};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), std::io::Error> {
//!     let config = SmtpConfig {
//!         bind_addr: "127.0.0.1:2525".to_string(),
//!         require_auth: true,
//!         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
//!         ..Default::default()
//!     };
//!
//!     let factory = MyHandlerFactory {};
//!
//!     start_server(config, factory).await?;
//!     Ok(())
//! }
//!
//! struct MyHandler {}
//!
//! #[async_trait]
//! impl smtpd_rs::SmtpHandler for MyHandler {
//!     async fn handle_auth(
//!         &mut self,
//!         _session: &smtpd_rs::Session,
//!         data: smtpd_rs::AuthData,
//!     ) -> Result<smtpd_rs::Response, smtpd_rs::Error> {
//!         let (username, password, _) = data.data();
//!
//!         if username == "abc" && password == "efg" {
//!             return Ok(smtpd_rs::Response::Default);
//!         }
//!
//!         Err(smtpd_rs::Error::Abort)
//!     }
//!
//!     async fn handle_rcpt(
//!         &mut self,
//!         _session: &smtpd_rs::Session,
//!         to: &str,
//!     ) -> Result<smtpd_rs::Response, smtpd_rs::Error> {
//!         // allow recipients only from gmail
//!         if to.ends_with("gmail.com") {
//!             return Ok(smtpd_rs::Response::Default);
//!         }
//!
//!         Err(smtpd_rs::Error::Abort)
//!     }
//! }
//!
//! struct MyHandlerFactory;
//!
//! impl smtpd_rs::SmtpHandlerFactory for MyHandlerFactory {
//!     type Handler = MyHandler;
//!
//!     fn new_handler(&self, _session: &smtpd_rs::Session) -> Self::Handler {
//!         MyHandler {}
//!     }
//! }
//! ```
//!
//! ## Modules
//! - `session`: Represents a client session.
//! - `handler`: Defines traits for handling SMTP commands.
//! - `tls`: TLS configuration and provider utilities.
//! - `stream`: Connection stream abstraction with read/write helpers.
//! - `utils`: Parsing and helper functions for SMTP commands.

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
pub use crate::core::response_error::{Error, Result};
pub use crate::core::session::Session;
use crate::core::stream::StreamController;
pub use crate::core::tls::TlsConfig;
pub use crate::core::tls::TlsMode;
#[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
use crate::core::tls::TlsProvider;
pub use async_trait::async_trait;

#[cfg(feature = "native-tls-backend")]
pub use native_tls::Identity;

#[cfg(feature = "rustls-backend")]
pub use rustls::ServerConfig;

mod constants;
mod core;
mod utils;

/// Starts an SMTP server with the provided configuration and handler factory.
///
/// This is the recommended entry point for running the SMTP server. Internally, it constructs
/// an [`SmtpServer`] instance and begins listening for incoming connections.
///
/// # Example
///
/// ```rust
/// use smtpd_rs::{start_server, SmtpConfig, AuthMach, MyHandlerFactory};
///
/// #[tokio::main]
/// async fn main() -> Result<(), std::io::Error> {
///     let config = SmtpConfig {
///         bind_addr: "127.0.0.1:2525".to_string(),
///         require_auth: true,
///         auth_machs: vec![AuthMach::Plain, AuthMach::Login],
///         ..Default::default()
///     };
///
///     let factory = MyHandlerFactory {};
///
///     println!("Starting SMTP server on {}", config.bind_addr);
///     start_server(config, factory).await?;
///
///     Ok(())
/// }
/// ```
pub async fn start_server<T: SmtpHandlerFactory + Send + Sync + 'static>(
    config: SmtpConfig,
    handler: T,
) -> std::result::Result<(), std::io::Error> {
    let server = SmtpServer::new(config, handler);
    server.listen_and_serve().await
}

/// The core SMTP server struct.
///
/// This struct represents the foundation of the SMTP server. While it is possible to
/// construct an `SmtpServer` instance manually and call its methods directly, the recommended
/// approach is to use the [`start_server`] helper function. This function will internally
/// create the server and invoke [`SmtpServer::listen_and_serve`] for you.
///
/// # Example
///
/// ```rust
/// use smtpd_rs::{SmtpServer, start_server, SmtpConfig, MyHandlerFactory};
///
/// let config = SmtpConfig {
///     bind_addr: "127.0.0.1:2525".to_string(),
///     require_auth: true,
///     ..Default::default()
/// };
///
/// let factory = MyHandlerFactory {};
/// start_server(config, factory).await?;
/// ```
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
    pub async fn listen_and_serve(self) -> std::result::Result<(), std::io::Error> {
        match &self.config.tls_mode {
            #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))]
            TlsMode::Implicit(_) => self.serve_tls().await,
            _ => self.serve_plain().await,
        }
    }

    /// Plain TCP listener (STARTTLS optional handling done per session)
    async fn serve_plain(self) -> std::result::Result<(), std::io::Error> {
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
    async fn serve_tls(self) -> std::result::Result<(), std::io::Error> {
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

/// Handles a single SMTP client connection.
///
/// This internal function manages all aspects of the client session:
/// - Reads commands from the client and parses them
/// - Writes responses to the client
/// - Invokes the appropriate [`SmtpHandler`] methods for AUTH, MAIL, RCPT, DATA, etc.
/// - Applies TLS negotiation if required by the server configuration
///
/// This function is called for each accepted connection and runs within a dedicated
/// Tokio task.
///
/// # Parameters
/// - `controller`: The [`StreamController`] for reading from and writing to the connection.
/// - `addr`: The socket address of the connected client.
/// - `config`: Shared SMTP server configuration (`SmtpConfig`).
/// - `handler_factory`: Factory for creating per-session handler instances.
/// - `resolver`: DNS resolver used for reverse lookups and MX resolution.
/// - `provider` (optional, TLS-only): TLS acceptor used for upgrading TCP streams to TLS.
///
/// # Returns
/// Returns `Ok(())` on successful handling of the session, or a [`CoreError`] if any
/// internal error occurs.
///
/// # Notes
/// - This function is async and designed to be spawned in a Tokio task per connection.
/// - TLS negotiation (STARTTLS or implicit TLS) is applied automatically if `provider` is `Some`.
/// - All authentication and mail commands are delegated to the handler returned by
///   `handler_factory.new_handler(session)`.
async fn handle_client<T: SmtpHandlerFactory + Send + Sync + 'static>(
    mut controller: StreamController,
    addr: SocketAddr,
    config: Arc<SmtpConfig>,
    handler_factory: Arc<T>,
    resolver: Arc<TokioAsyncResolver>,
    #[cfg(any(feature = "native-tls-backend", feature = "rustls-backend"))] provider: Option<
        Arc<TlsProvider>,
    >,
) -> std::result::Result<(), CoreError> {
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
                            Ok(auth_data) => {
                                match handler.handle_auth(&session, auth_data).await {
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
                                match handler.handle_email(&session, data).await {
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
                                match handler.handle_rcpt(&session, &to).await {
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

/// Internal helper to validate a STARTTLS command request.
///
/// This function **does not perform any I/O**. It only checks whether the client
/// is allowed to initiate the STARTTLS command based on the current session and
/// server configuration.
///
/// # Parameters
/// - `args`: Optional arguments provided with the STARTTLS command. Any non-empty
///   argument will result in a syntax error.
/// - `controller`: Reference to the [`StreamController`] of the current connection.
///   Used to check whether the session is already TLS-secured.
/// - `session`: Reference to the current [`Session`], used to inspect server TLS configuration.
///
/// # Returns
/// - `Ok(())` if the client is allowed to initiate STARTTLS.
/// - `Err(CoreError::Response(...))` if:
///   - The command includes unexpected arguments (syntax error)
///   - The connection is already TLS-secured (bad sequence)
///   - TLS is not configured or STARTTLS is not allowed (not implemented)
///
/// # Notes
/// - This function is called internally during command processing before attempting
///   to upgrade the connection to TLS.
fn handle_start_tls_cmd<'a>(
    args: Option<&str>,
    controller: &StreamController,
    session: &Session<'a>,
) -> std::result::Result<(), CoreError> {
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

/// Internal helper to extract authentication data from the client.
///
/// This function validates whether the client is allowed to initiate the AUTH command,
/// checks the requested authentication mechanism, and reads the credentials according
/// to the selected mechanism (PLAIN, LOGIN, or CRAM-MD5).
///
/// # Parameters
/// - `args`: Optional argument passed with the AUTH command, usually the authentication mechanism name.
/// - `session`: Mutable reference to the current [`Session`]. Used to check session state and TLS requirements.
/// - `controller`: Mutable reference to the [`StreamController`] of the current connection. Used to read/write to the client.
///
/// # Returns
/// Returns an [`AuthData`] variant containing the parsed authentication credentials.
///
/// # Errors
/// Returns [`CoreError::Response`] with appropriate [`Response`] in the following cases:
/// - TLS is required but the connection is not secured (`"Must issue a STARTTLS command first"`).
/// - The client is already authenticated (`"Bad sequence of commands (already authenticated for this session)"`).
/// - AUTH command is issued during an ongoing mail transaction (`"AUTH not permitted during mail transaction"`).
/// - Missing or malformed AUTH arguments (`"501 5.5.4 Malformed AUTH input"`).
/// - Unsupported or unrecognized authentication mechanism (`"504 5.5.4 Unrecognized authentication type"`).
/// - Parsing errors or invalid credential format (`"Syntax error (unable to parse)"` or `"Authentication cancelled"`).
/// - Authentication failed after parsing credentials (`"Authentication credentials invalid"`).
///
/// # Example
/// ```no_run
/// # use smtpd_rs::{Session, StreamController, get_auth_data};
/// # async fn example(mut session: Session<'_>, mut controller: StreamController) {
/// let args = Some("PLAIN dGVzdAB0ZXN0ADEyMw=="); // example base64-encoded credentials
/// let auth_data = get_auth_data(args, &mut session, &mut controller).await?;
/// // `auth_data` now contains username and password
/// # }
/// ```
async fn get_auth_data<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<AuthData, CoreError> {
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

    Ok(data.unwrap())
}

/// Internal helper to handle the `MAIL` command.
///
/// This function validates the MAIL command parameters, enforces TLS and authentication
/// requirements, checks the `SIZE` parameter (if provided), and updates the session state.
///
/// # Parameters
/// - `args`: Optional argument passed with the MAIL command, usually `"FROM:<address> [parameters]"`.
/// - `session`: Mutable reference to the current [`Session`]. Used to validate and update session state.
/// - `controller`: Mutable reference to the [`StreamController`] for reading/writing responses.
///
/// # Behavior
/// - Rejects the command if TLS is required but not active.
/// - Rejects if authentication is required but the client is not authenticated.
/// - Parses the `FROM` address and optional parameters; rejects if malformed.
/// - Validates the `SIZE` parameter, if present, against server configuration.
/// - Updates the session's `from`, `got_from`, and clears the recipients list (`to`).
/// - Sends a `250 Ok` response on success.
///
/// # Errors
/// Returns [`CoreError::Response`] with appropriate [`Response`] in the following cases:
/// - TLS is mandatory but not active (`"Must issue a STARTTLS command first"`).
/// - Authentication is required but not completed (`"Authentication required"`).
/// - Malformed FROM argument (`"Syntax error in FROM parameter"`).
/// - Invalid SIZE parameter (`"Invalid SIZE parameter"`).
/// - Message exceeds configured maximum size (`"Max size limit (<max_size>) exceeded"`).
///
/// # Example
/// ```no_run
/// # use smtpd_rs::{Session, StreamController, handle_mail_cmd};
/// # async fn example(mut session: Session<'_>, mut controller: StreamController) {
/// let args = Some("FROM:<alice@example.com> SIZE=1024");
/// handle_mail_cmd(args, &mut session, &mut controller).await?;
/// # }
/// ```
async fn handle_mail_cmd<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<(), CoreError> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Parse MAIL FROM argument
    let (from, params) = crate::utils::parser::parse_mail_from(args.unwrap_or_default())
        .ok_or_else(|| {
            CoreError::Response(Response::syntax_error("Syntax error in FROM parameter"))
        })?;

    // Validate SIZE parameter, if provided
    let size = params
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| crate::utils::parser::parse_size(p.as_str()))
        .flatten();

    if params.is_some() && size.is_none() {
        return Err(CoreError::Response(Response::syntax_error(
            "Invalid SIZE parameter",
        )));
    }

    if let Some(max_size) = session.smtp_config.max_message_size {
        if let Some(s) = size {
            if s > max_size {
                return Err(CoreError::Response(Response::new(
                    552,
                    format!("Max size limit ({max_size}) exceeded"),
                    Some("5.3.4".into()),
                )));
            }
        }
    }

    // Update session state
    session.from = from.to_string();
    session.got_from = true;
    session.to.clear();

    // Send success response
    controller.write_response(&Response::ok("Ok")).await?;
    Ok(())
}

/// Internal helper to extract the recipient address from the RCPT command argument.
///
/// This function validates the session state, enforces TLS and authentication requirements,
/// checks the MAIL command has been issued, and ensures the recipient limit is not exceeded.
///
/// # Parameters
/// - `args`: Optional argument passed with the RCPT command, usually `"TO:<address> [parameters]"`.
/// - `session`: Mutable reference to the current [`Session`].
///
/// # Behavior
/// - Rejects if TLS is mandatory but not active.
/// - Rejects if authentication is required but not yet completed.
/// - Rejects if MAIL command has not been issued yet (`got_from` is false).
/// - Rejects if adding the recipient would exceed `max_recipients` limit.
/// - Parses the recipient address from the command argument.
///
/// # Errors
/// Returns [`CoreError::Response`] with an appropriate [`Response`] in the following cases:
/// - TLS is mandatory but not active (`"Must issue a STARTTLS command first"`).
/// - Authentication is required but not completed (`"Authentication required"`).
/// - MAIL command not yet issued (`"Bad sequence of commands (MAIL required before RCPT)"`).
/// - Max recipient limit exceeded (`"Max recipient limit exceeded"`).
/// - Malformed TO argument (`"Syntax error in parameters or arguments (invalid TO parameter)"`).
async fn extract_rcpt_from_arg<'a>(
    args: Option<&str>,
    session: &mut Session<'a>,
) -> std::result::Result<String, CoreError> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !session.tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Ensure MAIL command has been issued
    if !session.got_from {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL required before RCPT)",
        )));
    }

    // Enforce max recipient limit
    if session.to.len() >= session.smtp_config.max_recipients {
        return Err(CoreError::Response(Response::new(
            452,
            "Max recipient limit exceeded",
            Some("4.5.3".into()),
        )));
    }

    // Parse the recipient address
    let to = crate::utils::parser::parse_rcpt_to(&args.unwrap_or_default()).ok_or_else(|| {
        CoreError::Response(Response::syntax_error(
            "Syntax error in parameters or arguments (invalid TO parameter)",
        ))
    })?;

    Ok(to.to_string())
}

/// Internal helper to read the message body after the DATA command.
///
/// This function validates the session state, enforces TLS and authentication requirements,
/// ensures that MAIL and at least one RCPT command have been successfully processed,
/// prompts the client to start sending mail data, and reads the message until the
/// terminating line (`.<CRLF>`).
///
/// # Parameters
/// - `session`: Mutable reference to the current [`Session`].
/// - `controller`: Mutable reference to the [`StreamController`] handling read/write.
///
/// # Returns
/// Returns the raw message data as a `Vec<u8>`.
///
/// # Errors
/// Returns [`CoreError::Response`] with an appropriate [`Response`] if:
/// - TLS is required but not active.
/// - Authentication is required but not completed.
/// - MAIL or RCPT commands have not yet been issued.
async fn extract_mail_data<'a>(
    session: &mut Session<'a>,
    controller: &mut StreamController,
) -> std::result::Result<Vec<u8>, CoreError> {
    // Enforce TLS if required
    if session.smtp_config.tls_mode.tls_mandatory() && !controller.is_tls {
        return Err(CoreError::Response(Response::reject(
            "Must issue a STARTTLS command first",
        )));
    }

    // Enforce authentication if required
    if session.smtp_config.require_auth && !session.authenticated {
        return Err(CoreError::Response(Response::reject(
            "Authentication required",
        )));
    }

    // Ensure MAIL & RCPT commands have been issued
    if !session.got_from || session.to.is_empty() {
        return Err(CoreError::Response(Response::bad_sequence(
            "Bad sequence of commands (MAIL & RCPT required before DATA)",
        )));
    }

    // Prompt client to start sending the message body
    controller
        .write_line("354 Start mail input; end with <CR><LF>.<CR><LF>")
        .await?;

    // Read the message data with optional maximum size limit
    let data = controller
        .read_mail_data(session.smtp_config.max_message_size)
        .await?;

    Ok(data)
}

/// Performs a reverse DNS lookup for the given IP address using the provided resolver.
/// Returns the first resolved hostname as a `String`, or `"unknown"` if the lookup fails or times out.
///
/// # Parameters
/// - `ip`: The IP address to resolve.
/// - `resolver`: A reference to a `TokioAsyncResolver` instance.
///
/// # Returns
/// A `String` representing the resolved hostname, or `"unknown"` if lookup fails.
async fn get_remote_host(ip: IpAddr, resolver: &TokioAsyncResolver) -> String {
    const TIMEOUT: Duration = Duration::from_secs(30);

    match timeout(TIMEOUT, resolver.reverse_lookup(ip)).await {
        Ok(Ok(lookup)) => lookup
            .iter()
            .next()
            .map(|n| n.to_utf8())
            .unwrap_or_else(|| "unknown".to_string()),
        _ => "unknown".to_string(),
    }
}
