use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::session::TargetAddr;

pub async fn read_addr<S>(stream: &mut S) -> anyhow::Result<TargetAddr>
where
    S: AsyncRead + Unpin,
{
    let atyp = stream.read_u8().await?;
    match atyp {
        0x00 => {
            let len = stream.read_u8().await? as usize;
            let mut host = vec![0; len];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            Ok(TargetAddr::Domain {
                host: String::from_utf8(host).context("domain is not utf-8")?,
                port,
            })
        }
        0x01 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(TargetAddr::from((IpAddr::V4(Ipv4Addr::from(octets)), port)))
        }
        0x02 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            Ok(TargetAddr::from((IpAddr::V6(Ipv6Addr::from(octets)), port)))
        }
        0xff => bail!("address type none is not valid for TCP connect"),
        other => bail!("unknown address type {other}"),
    }
}

pub async fn write_addr<S>(stream: &mut S, target: &TargetAddr) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match target {
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long");
            stream.write_u8(0x00).await?;
            stream.write_u8(host.len() as u8).await?;
            stream.write_all(host.as_bytes()).await?;
            stream.write_u16(*port).await?;
        }
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            stream.write_u8(0x01).await?;
            if let IpAddr::V4(ip) = addr.ip() {
                stream.write_all(&ip.octets()).await?;
            }
            stream.write_u16(addr.port()).await?;
        }
        TargetAddr::Ip(addr) => {
            stream.write_u8(0x02).await?;
            if let IpAddr::V6(ip) = addr.ip() {
                stream.write_all(&ip.octets()).await?;
            }
            stream.write_u16(addr.port()).await?;
        }
    }
    Ok(())
}
