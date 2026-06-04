use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use boring::rand::rand_bytes;
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
pub const UOT_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";
pub const FRAME_HEADER_LEN: usize = 1 + 4 + 2;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaddingStep {
    Size { min: u16, max: u16 },
    Check,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneratedPaddingStep {
    Size(usize),
    Check,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddingPlan {
    pub stop: u32,
    entries: Vec<(u32, Vec<PaddingStep>)>,
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

pub fn parse_padding_plan(lines: &[String]) -> anyhow::Result<PaddingPlan> {
    let text = padding_scheme_text(lines);
    let mut stop = None;
    let mut entries = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        let Some((key, spec)) = line.split_once('=') else {
            continue;
        };
        if key == "stop" {
            stop = Some(spec.parse()?);
            continue;
        }

        let Ok(stage) = key.parse::<u32>() else {
            continue;
        };
        let mut steps = Vec::new();
        for part in spec
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            if part == "c" {
                steps.push(PaddingStep::Check);
                continue;
            }
            let Some((min, max)) = part.split_once('-') else {
                continue;
            };
            let Ok(mut min) = min.parse::<u16>() else {
                continue;
            };
            let Ok(mut max) = max.parse::<u16>() else {
                continue;
            };
            if min == 0 || max == 0 {
                continue;
            }
            if min > max {
                std::mem::swap(&mut min, &mut max);
            }
            steps.push(PaddingStep::Size { min, max });
        }
        entries.push((stage, steps));
    }

    Ok(PaddingPlan {
        stop: stop.ok_or_else(|| anyhow::anyhow!("padding scheme missing stop"))?,
        entries,
    })
}

impl PaddingPlan {
    pub fn generate_record_payload_steps(
        &self,
        packet: u32,
    ) -> anyhow::Result<Vec<GeneratedPaddingStep>> {
        let Some((_, steps)) = self.entries.iter().find(|(stage, _)| *stage == packet) else {
            return Ok(Vec::new());
        };
        steps
            .iter()
            .map(|step| match step {
                PaddingStep::Check => Ok(GeneratedPaddingStep::Check),
                PaddingStep::Size { min, max } => {
                    Ok(GeneratedPaddingStep::Size(random_range(*min, *max)?))
                }
            })
            .collect()
    }

    pub fn steps_for_packet(&self, packet: u32) -> Option<&[PaddingStep]> {
        self.entries
            .iter()
            .find(|(stage, _)| *stage == packet)
            .map(|(_, steps)| steps.as_slice())
    }
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
    stream
        .write_all(&encode_frame(command, stream_id, data)?)
        .await?;
    Ok(())
}

pub fn encode_frame(command: u8, stream_id: u32, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(data.len() <= u16::MAX as usize, "anytls frame is too large");
    let mut output = Vec::with_capacity(FRAME_HEADER_LEN + data.len());
    output.push(command);
    output.extend_from_slice(&stream_id.to_be_bytes());
    output.extend_from_slice(&(data.len() as u16).to_be_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

pub fn encode_waste_frame(data_len: usize) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        data_len <= u16::MAX as usize,
        "anytls waste frame is too large"
    );
    let data = vec![0; data_len];
    encode_frame(CMD_WASTE, 0, &data)
}

pub fn shape_packet_payload(
    mut payload: Vec<u8>,
    packet: u32,
    plan: &PaddingPlan,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let steps = plan.generate_record_payload_steps(packet)?;
    if steps.is_empty() {
        return Ok(vec![payload]);
    }

    let mut records = Vec::new();
    for step in steps {
        let remaining = payload.len();
        match step {
            GeneratedPaddingStep::Check => {
                if remaining == 0 {
                    break;
                }
            }
            GeneratedPaddingStep::Size(size) if remaining > size => {
                records.push(payload.drain(..size).collect());
            }
            GeneratedPaddingStep::Size(size) if remaining > 0 => {
                let mut record = std::mem::take(&mut payload);
                let padding_len = size.saturating_sub(remaining + FRAME_HEADER_LEN);
                if padding_len > 0 {
                    record.extend_from_slice(&encode_waste_frame(padding_len)?);
                }
                records.push(record);
            }
            GeneratedPaddingStep::Size(size) => {
                records.push(encode_waste_frame(size)?);
            }
        }
    }

    if !payload.is_empty() {
        records.push(payload);
    }
    Ok(records)
}

pub async fn write_uot_v2_request<S>(
    stream: &mut S,
    connect: bool,
    target: &TargetAddr,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(u8::from(connect)).await?;
    stream.write_all(&encode_uot_addr(target)?).await?;
    Ok(())
}

pub async fn write_uot_payload<S>(stream: &mut S, payload: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&encode_uot_payload(payload)?).await?;
    Ok(())
}

pub fn encode_uot_payload(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        payload.len() <= u16::MAX as usize,
        "uot packet is too large"
    );
    let mut output = Vec::with_capacity(2 + payload.len());
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn encode_uot_packet(target: &TargetAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        payload.len() <= u16::MAX as usize,
        "uot packet is too large"
    );
    let mut output = Vec::with_capacity(259 + 2 + payload.len());
    output.extend_from_slice(&encode_uot_packet_addr(target)?);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn encode_uot_addr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    encode_socksaddr(target)
}

pub fn encode_uot_packet_addr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            output.push(0x00);
            if let IpAddr::V4(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(addr) => {
            output.push(0x01);
            if let IpAddr::V6(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long");
            output.push(0x02);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(output)
}

pub async fn read_uot_payload<S>(stream: &mut S) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u16().await? as usize;
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

pub fn uot_v2_magic_target() -> TargetAddr {
    TargetAddr::Domain {
        host: UOT_V2_MAGIC_HOST.to_owned(),
        port: 0,
    }
}

pub fn is_uot_v2_magic_target(target: &TargetAddr) -> bool {
    matches!(
        target,
        TargetAddr::Domain { host, port } if host.eq_ignore_ascii_case(UOT_V2_MAGIC_HOST) && *port == 0
    )
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
    let plan = parse_padding_plan(lines)?;
    let Some(GeneratedPaddingStep::Size(size)) = plan
        .generate_record_payload_steps(0)?
        .into_iter()
        .find(|step| matches!(step, GeneratedPaddingStep::Size(_)))
    else {
        return Ok(30);
    };
    Ok(size as u16)
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

fn random_range(min: u16, max: u16) -> anyhow::Result<usize> {
    if min == max {
        return Ok(min as usize);
    }
    let span = u128::from(max - min);
    let sample_space = 1u128 << 64;
    let limit = sample_space - (sample_space % span);

    loop {
        let mut bytes = [0; 8];
        rand_bytes(&mut bytes)?;
        let value = u128::from(u64::from_be_bytes(bytes));
        if value < limit {
            return Ok((u128::from(min) + value % span) as usize);
        }
    }
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
    fn parses_padding_plan_with_checkpoints() {
        let plan =
            parse_padding_plan(&["stop=8".to_owned(), "2=400-500,c,500-1000".to_owned()]).unwrap();

        assert_eq!(plan.stop, 8);
        assert_eq!(
            plan.steps_for_packet(2).unwrap(),
            [
                PaddingStep::Size { min: 400, max: 500 },
                PaddingStep::Check,
                PaddingStep::Size {
                    min: 500,
                    max: 1000
                }
            ]
        );
    }

    #[test]
    fn shapes_packet_payload_with_waste_padding() {
        let plan = parse_padding_plan(&["stop=3".to_owned(), "1=20-20".to_owned()]).unwrap();
        let payload = vec![0xaa; 12];

        let records = shape_packet_payload(payload.clone(), 1, &plan).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 20);
        assert_eq!(&records[0][..payload.len()], payload.as_slice());
        assert_eq!(records[0][12], CMD_WASTE);
        assert_eq!(&records[0][13..17], [0, 0, 0, 0]);
        assert_eq!(&records[0][17..19], [0, 1]);
        assert_eq!(records[0][19], 0);
    }

    #[test]
    fn shapes_packet_payload_with_splitting_and_checkpoints() {
        let plan = parse_padding_plan(&["stop=3".to_owned(), "1=5-5,c,5-5".to_owned()]).unwrap();
        let payload = vec![0xbb; 13];

        let records = shape_packet_payload(payload, 1, &plan).unwrap();

        assert_eq!(
            records.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![5, 5, 3]
        );
    }

    #[test]
    fn shape_packet_payload_stops_at_checkpoint_when_payload_drained() {
        let plan =
            parse_padding_plan(&["stop=3".to_owned(), "1=20-20,c,20-20".to_owned()]).unwrap();
        let payload = vec![0xcc; 12];

        let records = shape_packet_payload(payload, 1, &plan).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 20);
    }

    #[test]
    fn decodes_sing_socksaddr() {
        let raw = [0x01, 127, 0, 0, 1, 0x4a, 0x38];
        let (target, consumed) = decode_socksaddr(&raw).unwrap();

        assert_eq!(target.to_string(), "127.0.0.1:19000");
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn encodes_uot_non_connect_packet_addr() {
        let raw = encode_uot_packet(
            &TargetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                19000,
            )),
            b"ping",
        )
        .unwrap();

        assert_eq!(
            raw,
            vec![
                0x00, 127, 0, 0, 1, 0x4a, 0x38, 0x00, 0x04, b'p', b'i', b'n', b'g'
            ]
        );
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
