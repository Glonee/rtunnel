use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{config::UserConfig, session::TargetAddr};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;
const PASSWORD_HASH_LEN: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddingRule {
    pub stage: u8,
    pub min: u16,
    pub max: u16,
}

pub fn parse_padding_scheme(lines: &[String]) -> anyhow::Result<Vec<PaddingRule>> {
    let mut rules = Vec::new();
    for line in lines {
        let Some((stage, spec)) = line.split_once('=') else {
            continue;
        };
        if stage == "stop" {
            continue;
        }
        let stage: u8 = stage.parse()?;
        for part in spec.split(',') {
            if part == "c" {
                continue;
            }
            let Some((min, max)) = part.split_once('-') else {
                continue;
            };
            rules.push(PaddingRule {
                stage,
                min: min.parse()?,
                max: max.parse()?,
            });
        }
    }
    Ok(rules)
}

#[derive(Debug)]
pub struct Frame {
    pub command: u8,
    pub stream_id: u32,
    pub data: Vec<u8>,
}

pub fn password_hash(password: &str) -> [u8; PASSWORD_HASH_LEN] {
    Sha256::digest(password.as_bytes()).into()
}

pub async fn write_client_hello<S>(stream: &mut S, password: &str) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&password_hash(password)).await?;
    stream.write_u16(0).await?;
    Ok(())
}

pub async fn read_client_hello<S>(stream: &mut S, users: &[UserConfig]) -> anyhow::Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut presented = [0; PASSWORD_HASH_LEN];
    stream.read_exact(&mut presented).await?;
    let padding_len = stream.read_u16().await?;
    if padding_len > 0 {
        let mut padding = vec![0; padding_len as usize];
        stream.read_exact(&mut padding).await?;
    }
    for user in users {
        if password_hash(&user.password) == presented {
            return Ok(user.username.clone());
        }
    }
    anyhow::bail!("anytls authentication failed")
}

pub async fn read_frame<S>(stream: &mut S) -> anyhow::Result<Frame>
where
    S: AsyncRead + Unpin,
{
    let command = stream.read_u8().await?;
    let stream_id = stream.read_u32().await?;
    let len = stream.read_u16().await? as usize;
    let mut data = vec![0; len];
    if len > 0 {
        stream.read_exact(&mut data).await?;
    }
    Ok(Frame {
        command,
        stream_id,
        data,
    })
}

pub async fn write_frame<S>(
    stream: &mut S,
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    anyhow::ensure!(data.len() <= u16::MAX as usize, "anytls frame is too large");
    stream.write_u8(command).await?;
    stream.write_u32(stream_id).await?;
    stream.write_u16(data.len() as u16).await?;
    stream.write_all(data).await?;
    Ok(())
}

pub fn settings() -> &'static [u8] {
    b"v=2"
}

pub fn encode_socksaddr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            output.push(0x01);
            if let IpAddr::V4(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(addr) => {
            output.push(0x04);
            if let IpAddr::V6(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long");
            output.push(0x03);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(output)
}

pub fn decode_socksaddr(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    let mut cursor = Cursor::new(data);
    let atyp = read_u8(&mut cursor)?;
    let target = match atyp {
        0x01 => {
            let mut octets = [0; 4];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x03 => {
            let len = read_u8(&mut cursor)? as usize;
            let mut host = vec![0; len];
            Read::read_exact(&mut cursor, &mut host)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Domain {
                host: String::from_utf8(host)?,
                port,
            }
        }
        0x04 => {
            let mut octets = [0; 16];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => anyhow::bail!("unknown anytls address family {other}"),
    };
    Ok((target, cursor.position() as usize))
}

pub async fn write_connect<S>(stream: &mut S, target: &TargetAddr) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, CMD_SYN, 1, &[]).await?;
    write_frame(stream, CMD_PSH, 1, &encode_socksaddr(target)?).await?;
    Ok(())
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<u8> {
    let mut buf = [0; 1];
    Read::read_exact(cursor, &mut buf)?;
    Ok(buf[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<u16> {
    let mut buf = [0; 2];
    Read::read_exact(cursor, &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_padding_rules() {
        let rules = parse_padding_scheme(&[
            "stop=8".to_owned(),
            "0=30-30".to_owned(),
            "2=400-500,c,500-1000".to_owned(),
        ])
        .unwrap();

        assert_eq!(
            rules,
            vec![
                PaddingRule {
                    stage: 0,
                    min: 30,
                    max: 30
                },
                PaddingRule {
                    stage: 2,
                    min: 400,
                    max: 500
                },
                PaddingRule {
                    stage: 2,
                    min: 500,
                    max: 1000
                }
            ]
        );
    }

    #[test]
    fn decodes_sing_socksaddr() {
        let raw = [0x01, 127, 0, 0, 1, 0x4a, 0x38];
        let (target, consumed) = decode_socksaddr(&raw).unwrap();

        assert_eq!(target.to_string(), "127.0.0.1:19000");
        assert_eq!(consumed, raw.len());
    }
}
