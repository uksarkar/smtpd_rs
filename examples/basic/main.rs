#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = smtpd_rs::SmtpConfig {
        bind_addr: "127.0.0.1:2525".to_string(),
        greeting: "220 my-smtp-server ESMTP Ready".to_string(),
        ..Default::default()
    };

    println!("Starting SMTP server on {}", config.bind_addr);
    smtpd_rs::start_server(config).await?;

    Ok(())
}
