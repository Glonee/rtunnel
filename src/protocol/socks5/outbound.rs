use anyhow::{Context, bail};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    config::OutboundConfig,
    router::Outbound,
    session::{BoxStream, Command, Session, TargetAddr},
};

pub struct Socks5Outbound {
    cfg: OutboundConfig,
}

impl Socks5Outbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        Ok(Self { cfg })
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "socks5 outbound only supports CONNECT"
        );
        let mut stream = TcpStream::connect(self.cfg.require_server()?).await?;
        let auth = self.cfg.username.is_some() || self.cfg.password.is_some();
        if auth {
            stream.write_all(&[0x05, 0x01, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut resp = [0; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] == 0xff {
            bail!("socks5 outbound rejected auth method");
        }
        if resp[1] == 0x02 {
            let username = self.cfg.username.as_deref().unwrap_or_default().as_bytes();
            let password = self.cfg.password.as_deref().unwrap_or_default().as_bytes();
            anyhow::ensure!(
                username.len() <= 255 && password.len() <= 255,
                "socks5 credentials are too long"
            );
            stream.write_u8(0x01).await?;
            stream.write_u8(username.len() as u8).await?;
            stream.write_all(username).await?;
            stream.write_u8(password.len() as u8).await?;
            stream.write_all(password).await?;
            stream.read_exact(&mut resp).await?;
            if resp != [0x01, 0x00] {
                bail!("socks5 outbound authentication failed");
            }
        }

        write_connect_request(&mut stream, &session.target).await?;
        let status = read_connect_response(&mut stream).await?;
        if status != 0 {
            bail!("socks5 outbound connect failed with status {status}");
        }
        Ok(Box::new(stream))
    }
}

async fn write_connect_request(stream: &mut TcpStream, target: &TargetAddr) -> anyhow::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            stream.write_u8(0x01).await?;
            if let std::net::IpAddr::V4(ip) = addr.ip() {
                stream.write_all(&ip.octets()).await?;
            }
        }
        TargetAddr::Ip(addr) => {
            stream.write_u8(0x04).await?;
            if let std::net::IpAddr::V6(ip) = addr.ip() {
                stream.write_all(&ip.octets()).await?;
            }
        }
        TargetAddr::Domain { host, .. } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long for socks5");
            stream.write_u8(0x03).await?;
            stream.write_u8(host.len() as u8).await?;
            stream.write_all(host.as_bytes()).await?;
        }
    }
    stream.write_u16(target.port()).await?;
    Ok(())
}

async fn read_connect_response(stream: &mut TcpStream) -> anyhow::Result<u8> {
    let ver = stream.read_u8().await?;
    let status = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if ver != 0x05 || rsv != 0 {
        bail!("invalid socks5 outbound response");
    }
    let atyp = stream.read_u8().await?;
    match atyp {
        0x01 => skip(stream, 4).await?,
        0x03 => {
            let len = stream.read_u8().await? as usize;
            skip(stream, len).await?;
        }
        0x04 => skip(stream, 16).await?,
        other => bail!("unsupported socks5 response address type {other}"),
    }
    let _port = stream
        .read_u16()
        .await
        .context("missing socks5 bind port")?;
    Ok(status)
}

async fn skip(stream: &mut TcpStream, len: usize) -> anyhow::Result<()> {
    let mut buf = vec![0; len];
    stream.read_exact(&mut buf).await?;
    Ok(())
}
