use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use upstream_anytls::core::{
    Command as CoreCommand, Frame as CoreFrame, HEADER_OVERHEAD_SIZE as CORE_FRAME_HEADER_LEN,
    PaddingFactory,
};

use crate::{config::UserConfig, session::TargetAddr};

pub const CMD_WASTE: u8 = command_code(CoreCommand::Waste);
pub const CMD_SYN: u8 = command_code(CoreCommand::Syn);
pub const CMD_PSH: u8 = command_code(CoreCommand::Psh);
pub const CMD_FIN: u8 = command_code(CoreCommand::Fin);
pub const CMD_SETTINGS: u8 = command_code(CoreCommand::Settings);
pub const CMD_ALERT: u8 = command_code(CoreCommand::Alert);
pub const CMD_UPDATE_PADDING_SCHEME: u8 = command_code(CoreCommand::UpdatePaddingScheme);
pub const CMD_SYNACK: u8 = command_code(CoreCommand::SynAck);
pub const CMD_HEART_REQUEST: u8 = command_code(CoreCommand::HeartRequest);
pub const CMD_HEART_RESPONSE: u8 = command_code(CoreCommand::HeartResponse);
pub const CMD_SERVER_SETTINGS: u8 = command_code(CoreCommand::ServerSettings);
pub const UOT_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";
pub const FRAME_HEADER_LEN: usize = CORE_FRAME_HEADER_LEN;
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

#[derive(Clone)]
pub struct PaddingPlan {
    pub stop: u32,
    entries: Vec<(u32, Vec<PaddingStep>)>,
    factory: PaddingFactory,
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
    let factory = PaddingFactory::new(text.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("invalid anytls padding scheme"))?;
    let mut stop: Option<u32> = None;
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

    let stop = stop.ok_or_else(|| anyhow::anyhow!("padding scheme missing stop"))?;
    anyhow::ensure!(
        stop == factory.stop(),
        "padding scheme stop does not match upstream parser"
    );

    Ok(PaddingPlan {
        stop: factory.stop(),
        entries,
        factory,
    })
}

impl PaddingPlan {
    pub fn md5(&self) -> &str {
        self.factory.md5()
    }

    pub fn padding0_len(&self) -> anyhow::Result<u16> {
        let Some(GeneratedPaddingStep::Size(size)) = self
            .generate_record_payload_steps(0)?
            .into_iter()
            .find(|step| matches!(step, GeneratedPaddingStep::Size(_)))
        else {
            return Ok(30);
        };
        Ok(size as u16)
    }

    pub fn generate_record_payload_steps(
        &self,
        packet: u32,
    ) -> anyhow::Result<Vec<GeneratedPaddingStep>> {
        Ok(self
            .factory
            .generate_record_payload_sizes(packet)
            .into_iter()
            .filter_map(|size| match size {
                upstream_anytls::core::CHECK_MARK => Some(GeneratedPaddingStep::Check),
                size if size > 0 => Some(GeneratedPaddingStep::Size(size as usize)),
                _ => None,
            })
            .collect())
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

#[derive(Debug, Eq, PartialEq)]
pub enum ClientHelloAuth {
    Authenticated(String),
    Rejected(Vec<u8>),
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
    match read_client_hello_or_fallback(stream, users).await? {
        ClientHelloAuth::Authenticated(username) => Ok(username),
        ClientHelloAuth::Rejected(_) => anyhow::bail!("anytls authentication failed"),
    }
}

pub async fn read_client_hello_or_fallback<S>(
    stream: &mut S,
    users: &[UserConfig],
) -> anyhow::Result<ClientHelloAuth>
where
    S: AsyncRead + Unpin,
{
    let mut presented = [0; PASSWORD_HASH_LEN];
    stream.read_exact(&mut presented).await?;
    let Some(username) = users
        .iter()
        .find(|user| password_hash(&user.password) == presented)
        .map(|user| user.username.clone())
    else {
        return Ok(ClientHelloAuth::Rejected(presented.to_vec()));
    };

    let padding_len = stream.read_u16().await?;
    if padding_len > 0 {
        let mut padding = vec![0; padding_len as usize];
        stream.read_exact(&mut padding).await?;
    }
    Ok(ClientHelloAuth::Authenticated(username))
}

pub async fn read_frame<S>(stream: &mut S) -> anyhow::Result<Frame>
where
    S: AsyncRead + Unpin,
{
    let mut raw = vec![0; FRAME_HEADER_LEN];
    stream.read_exact(&mut raw).await?;
    let len = u16::from_be_bytes([raw[5], raw[6]]) as usize;
    if len > 0 {
        raw.resize(FRAME_HEADER_LEN + len, 0);
        stream.read_exact(&mut raw[FRAME_HEADER_LEN..]).await?;
    }
    let frame =
        CoreFrame::from_bytes(&raw).ok_or_else(|| anyhow::anyhow!("invalid anytls frame"))?;
    Ok(Frame::from(frame))
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
    Ok(
        CoreFrame::with_data(command.into(), stream_id, data.to_vec().into())
            .to_bytes()
            .to_vec(),
    )
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
    format!("v=2\nclient=rtunnel\npadding-md5={padding_md5}").into_bytes()
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
        PaddingFactory::new(padding_scheme_text(lines).as_bytes())
            .map(|factory| factory.md5().to_owned())
            .unwrap_or_else(|| format!("{:x}", md5::compute(padding_scheme_text(lines).as_bytes())))
    }
}

pub fn padding0_len(lines: &[String]) -> anyhow::Result<u16> {
    let plan = parse_padding_plan(lines)?;
    plan.padding0_len()
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

const fn command_code(command: CoreCommand) -> u8 {
    match command {
        CoreCommand::Waste => 0,
        CoreCommand::Syn => 1,
        CoreCommand::Psh => 2,
        CoreCommand::Fin => 3,
        CoreCommand::Settings => 4,
        CoreCommand::Alert => 5,
        CoreCommand::UpdatePaddingScheme => 6,
        CoreCommand::SynAck => 7,
        CoreCommand::HeartRequest => 8,
        CoreCommand::HeartResponse => 9,
        CoreCommand::ServerSettings => 10,
        CoreCommand::Unknown(value) => value,
    }
}

impl From<CoreFrame> for Frame {
    fn from(frame: CoreFrame) -> Self {
        Self {
            command: frame.cmd.into(),
            stream_id: frame.sid,
            data: frame.data.to_vec(),
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
    fn frame_encoding_matches_upstream_core() {
        let encoded = encode_frame(CMD_PSH, 42, b"hello").unwrap();
        let upstream = CoreFrame::with_data(CoreCommand::Psh, 42, b"hello".to_vec().into())
            .to_bytes()
            .to_vec();

        assert_eq!(encoded, upstream);
        let parsed = CoreFrame::from_bytes(&encoded).unwrap();
        assert_eq!(parsed.cmd, CoreCommand::Psh);
        assert_eq!(parsed.sid, 42);
        assert_eq!(parsed.data.as_ref(), b"hello");
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
        assert_eq!(settings_value(&settings, "client"), Some("rtunnel"));
        assert_eq!(settings_value(&settings, "padding-md5"), Some("abc123"));
    }

    #[test]
    fn computes_custom_padding_metadata() {
        let scheme = vec!["stop=2".to_owned(), "0=12-12".to_owned()];

        assert_ne!(padding_scheme_md5(&scheme), DEFAULT_PADDING_MD5);
        assert_eq!(padding0_len(&scheme).unwrap(), 12);
    }
}
