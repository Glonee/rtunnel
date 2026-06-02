use boring::ssl::SslRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{config::UserConfig, protocol::addr, session::TargetAddr};

const MAGIC: &[u8; 4] = b"ATLS";
const VERSION: u8 = 1;
const TOKEN_LEN: usize = 32;
const CMD_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PADDING: u8 = 0xfe;
const EXPORTER_LABEL: &str = "rtunel anytls auth";

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

pub fn token(ssl: &SslRef, password: &str) -> anyhow::Result<[u8; TOKEN_LEN]> {
    let mut token = [0; TOKEN_LEN];
    ssl.export_keying_material(&mut token, EXPORTER_LABEL, Some(password.as_bytes()))?;
    Ok(token)
}

pub async fn write_auth<S>(stream: &mut S, token: &[u8; TOKEN_LEN]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(MAGIC).await?;
    stream.write_u8(VERSION).await?;
    stream.write_u8(CMD_AUTH).await?;
    stream.write_all(token).await?;
    Ok(())
}

pub async fn read_auth<S>(stream: &mut S) -> anyhow::Result<[u8; TOKEN_LEN]>
where
    S: AsyncRead + Unpin,
{
    let mut magic = [0; 4];
    stream.read_exact(&mut magic).await?;
    anyhow::ensure!(&magic == MAGIC, "invalid anytls magic");
    let version = stream.read_u8().await?;
    anyhow::ensure!(version == VERSION, "unsupported anytls version {version}");
    let command = stream.read_u8().await?;
    anyhow::ensure!(command == CMD_AUTH, "expected anytls auth command");

    let mut presented = [0; TOKEN_LEN];
    stream.read_exact(&mut presented).await?;
    Ok(presented)
}

pub fn verify_auth(
    ssl: &SslRef,
    users: &[UserConfig],
    presented: &[u8; TOKEN_LEN],
) -> anyhow::Result<String> {
    for user in users {
        if &token(ssl, &user.password)? == presented {
            return Ok(user.username.clone());
        }
    }
    anyhow::bail!("anytls authentication failed")
}

pub async fn write_connect<S>(
    stream: &mut S,
    target: &TargetAddr,
    padding: &[PaddingRule],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    for rule in padding.iter().filter(|rule| rule.stage == 0) {
        write_padding(stream, rule.min).await?;
    }
    stream.write_u8(CMD_CONNECT).await?;
    addr::write_addr(stream, target).await?;
    Ok(())
}

pub async fn read_connect<S>(stream: &mut S) -> anyhow::Result<TargetAddr>
where
    S: AsyncRead + Unpin,
{
    loop {
        match stream.read_u8().await? {
            CMD_CONNECT => return addr::read_addr(stream).await,
            CMD_PADDING => {
                let len = stream.read_u16().await? as usize;
                let mut buf = vec![0; len];
                stream.read_exact(&mut buf).await?;
            }
            other => anyhow::bail!("unexpected anytls command {other}"),
        }
    }
}

async fn write_padding<S>(stream: &mut S, len: u16) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(CMD_PADDING).await?;
    stream.write_u16(len).await?;
    stream.write_all(&vec![0; len as usize]).await?;
    Ok(())
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
}
