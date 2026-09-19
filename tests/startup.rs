use std::time::Duration;

#[tokio::test]
async fn exits_with_error_when_an_inbound_cannot_bind() -> anyhow::Result<()> {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let config =
        std::env::temp_dir().join(format!("rtunnel-startup-{}.toml", uuid::Uuid::new_v4()));
    std::fs::write(
        &config,
        format!(
            r#"
        [[inbounds]]
        tag = "occupied"
        protocol = "socks5"
        listen = "{}"
        [[outbounds]]
        tag = "direct"
        protocol = "direct"
    "#,
            occupied.local_addr()?
        ),
    )?;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rtunnel"));
    child.arg("--config").arg(&config).kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(5), child.output()).await;
    std::fs::remove_file(config)?;
    let output = result??;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inbound occupied"));
    Ok(())
}
