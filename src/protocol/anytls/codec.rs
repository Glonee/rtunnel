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
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;
const PASSWORD_HASH_LEN: usize = 32;
pub const DEFAULT_PADDING_MD5: &str = "e872e281aa5e28149c0f6b8d36e79199";
pub const DEFAULT_PADDING_SCHEME: &str = "\
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

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
    write_client_hello_with_padding(stream, password, 30).await
}

pub async fn write_client_hello_with_padding<S>(
    stream: &mut S,
    password: &str,
    padding_len: u16,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut hello = Vec::with_capacity(PASSWORD_HASH_LEN + 2 + padding_len as usize);
    hello.extend_from_slice(&password_hash(password));
    hello.extend_from_slice(&padding_len.to_be_bytes());
    hello.resize(PASSWORD_HASH_LEN + 2 + padding_len as usize, 0);
    stream.write_all(&hello).await?;
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

pub fn client_settings() -> Vec<u8> {
    client_settings_with_padding_md5(DEFAULT_PADDING_MD5)
}

pub fn client_settings_with_padding_md5(padding_md5: &str) -> Vec<u8> {
    format!("v=2\nclient=rtunel\npadding-md5={padding_md5}").into_bytes()
}

pub fn settings_version(data: &[u8]) -> Option<u8> {
    settings_value(data, "v")?.parse().ok()
}

pub fn settings_value<'a>(data: &'a [u8], key: &str) -> Option<&'a str> {
    let settings = std::str::from_utf8(data).ok()?;
    settings.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name == key).then_some(value)
    })
}

pub fn padding_scheme_text(lines: &[String]) -> String {
    if lines.is_empty() {
        DEFAULT_PADDING_SCHEME.to_owned()
    } else {
        lines.join("\n")
    }
}

pub fn padding_scheme_payload(lines: &[String]) -> Vec<u8> {
    padding_scheme_text(lines).into_bytes()
}

pub fn padding_scheme_md5(lines: &[String]) -> String {
    if lines.is_empty() {
        DEFAULT_PADDING_MD5.to_owned()
    } else {
        format!("{:x}", md5::compute(padding_scheme_text(lines).as_bytes()))
    }
}

pub fn padding0_len(lines: &[String]) -> anyhow::Result<u16> {
    let rules = parse_padding_scheme(lines)?;
    Ok(rules
        .iter()
        .find(|rule| rule.stage == 0)
        .map(|rule| rule.min)
        .unwrap_or(30))
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

    #[test]
    fn parses_settings_values() {
        let settings = client_settings_with_padding_md5("abc123");

        assert_eq!(settings_version(&settings), Some(2));
        assert_eq!(settings_value(&settings, "client"), Some("rtunel"));
        assert_eq!(settings_value(&settings, "padding-md5"), Some("abc123"));
    }

    #[test]
    fn computes_custom_padding_metadata() {
        let scheme = vec!["stop=2".to_owned(), "0=12-12".to_owned()];

        assert_ne!(padding_scheme_md5(&scheme), DEFAULT_PADDING_MD5);
        assert_eq!(padding0_len(&scheme).unwrap(), 12);
    }
}
