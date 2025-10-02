use smtpd_rs::AuthMach;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = smtpd_rs::SmtpConfig {
        bind_addr: "127.0.0.1:2525".to_string(),
        require_auth: true,
        auth_machs: vec![AuthMach::Plain, AuthMach::Login],
        ..Default::default()
    };

    let factory = MyHandlerFactory {};

    println!("Starting SMTP server on {}", config.bind_addr);
    smtpd_rs::start_server(config, factory).await?;

    Ok(())
}

struct MyHandler {}

impl smtpd_rs::SmtpHandler for MyHandler {
    fn handle_auth(
        &mut self,
        _session: &smtpd_rs::Session,
        data: &smtpd_rs::AuthData,
    ) -> Result<smtpd_rs::Response, smtpd_rs::Error> {
        let (username, password, _) = data.data();

        if username == "abc" && password == "efg" {
            return Ok(smtpd_rs::Response::Default);
        }

        Err(smtpd_rs::Error::InvalidData)
    }
}

struct MyHandlerFactory;

impl smtpd_rs::SmtpHandlerFactory for MyHandlerFactory {
    type Handler = MyHandler;

    fn new_handler(&self, session: &smtpd_rs::Session) -> Self::Handler {
        MyHandler {}
    }
}
