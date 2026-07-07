use std::{
    fmt, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Deserializer, de};
use tokio::net::{TcpStream, lookup_host};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub log_level: Option<String>,
    pub acme: Option<AcmeConfig>,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.inbounds.is_empty() {
            bail!("at least one inbound is required");
        }
        if self.outbounds.is_empty() {
            bail!("at least one outbound is required");
        }
        if let Some(default) = &self.routing.default {
            if !self.outbounds.iter().any(|out| out.tag == *default) {
                bail!("routing.default references unknown outbound tag {default}");
            }
        }
        for inbound in &self.inbounds {
            if let Some(tls) = &inbound.tls {
                tls.validate(&inbound.tag)?;
            }
        }
        for outbound in &self.outbounds {
            outbound.validate()?;
        }
        Ok(())
    }

    pub fn acme_config(&self) -> AcmeConfig {
        self.acme.clone().unwrap_or_default()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub listen: SocketAddr,
    pub protocol: Protocol,
    pub users: Option<Vec<UserConfig>>,
    #[serde(default)]
    pub padding_scheme: Vec<String>,
    pub tls: Option<TlsServerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: Protocol,
    pub server: Option<ServerAddr>,
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    pub ca_certificate: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub max_streams: Option<usize>,
    pub max_connections: Option<usize>,
    #[serde(
        default,
        alias = "idle_time",
        deserialize_with = "deserialize_optional_duration"
    )]
    pub connection_idle_timeout: Option<Duration>,
}

impl OutboundConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !matches!(self.protocol, Protocol::Anytls) {
            return Ok(());
        }

        ensure!(
            !(self.max_streams.is_some() && self.max_connections.is_some()),
            "anytls outbound {} cannot configure both max_streams and max_connections",
            self.tag
        );
        ensure!(
            self.max_streams != Some(0),
            "anytls outbound {} max_streams must be greater than zero",
            self.tag
        );
        ensure!(
            self.max_connections != Some(0),
            "anytls outbound {} max_connections must be greater than zero",
            self.tag
        );
        ensure!(
            self.connection_idle_timeout != Some(Duration::ZERO),
            "anytls outbound {} connection_idle_timeout must be greater than zero",
            self.tag
        );
        Ok(())
    }

    pub fn require_server(&self) -> anyhow::Result<&ServerAddr> {
        self.server
            .as_ref()
            .with_context(|| format!("outbound {} requires server", self.tag))
    }

    pub fn tls_server_name(&self) -> anyhow::Result<&str> {
        self.server_name
            .as_deref()
            .or_else(|| self.server.as_ref().and_then(ServerAddr::domain))
            .with_context(|| format!("outbound {} requires server_name", self.tag))
    }

    pub fn anytls_connection_idle_timeout(&self) -> Duration {
        self.connection_idle_timeout
            .unwrap_or_else(default_anytls_connection_idle_timeout)
    }

    pub fn anytls_max_streams(&self) -> Option<usize> {
        if self.max_connections.is_some() {
            None
        } else {
            Some(self.max_streams.unwrap_or_else(default_anytls_max_streams))
        }
    }
}

pub fn default_anytls_max_streams() -> usize {
    1
}

pub fn default_anytls_connection_idle_timeout() -> Duration {
    Duration::from_secs(2 * 60)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DurationValue {
    Seconds(u64),
    Text(String),
}

fn deserialize_optional_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<DurationValue>::deserialize(deserializer)?
        .map(parse_duration_value)
        .transpose()
        .map_err(de::Error::custom)
}

fn parse_duration_value(value: DurationValue) -> anyhow::Result<Duration> {
    match value {
        DurationValue::Seconds(seconds) => Ok(Duration::from_secs(seconds)),
        DurationValue::Text(text) => parse_duration_text(&text),
    }
}

fn parse_duration_text(text: &str) -> anyhow::Result<Duration> {
    let value = text.trim();
    ensure!(!value.is_empty(), "duration must not be empty");

    let digits = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    ensure!(digits > 0, "duration {text:?} must start with a number");

    let amount = value[..digits]
        .parse::<u64>()
        .with_context(|| format!("duration {text:?} has an invalid number"))?;
    let unit = value[digits..].trim();
    let seconds = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => return Ok(Duration::from_secs(amount)),
        "m" | "min" | "mins" | "minute" | "minutes" => amount.checked_mul(60),
        "h" | "hr" | "hrs" | "hour" | "hours" => amount.checked_mul(60 * 60),
        "d" | "day" | "days" => amount.checked_mul(24 * 60 * 60),
        "ms" | "millisecond" | "milliseconds" => return Ok(Duration::from_millis(amount)),
        other => bail!("duration {text:?} has unsupported unit {other:?}"),
    }
    .with_context(|| format!("duration {text:?} is too large"))?;

    Ok(Duration::from_secs(seconds))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAddr {
    host: ServerHost,
    port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ServerHost {
    Ip(IpAddr),
    Domain(String),
}

impl ServerAddr {
    pub fn host(&self) -> String {
        match &self.host {
            ServerHost::Ip(ip) => ip.to_string(),
            ServerHost::Domain(domain) => domain.clone(),
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            ServerHost::Ip(_) => None,
            ServerHost::Domain(domain) => Some(domain.as_str()),
        }
    }

    pub async fn resolve(&self) -> anyhow::Result<SocketAddr> {
        match &self.host {
            ServerHost::Ip(ip) => Ok(SocketAddr::new(*ip, self.port)),
            ServerHost::Domain(domain) => {
                let mut addrs = lookup_host((domain.as_str(), self.port))
                    .await
                    .with_context(|| format!("failed to resolve server {self}"))?;
                addrs
                    .next()
                    .with_context(|| format!("server {self} did not resolve to any address"))
            }
        }
    }

    pub async fn connect_tcp(&self) -> anyhow::Result<TcpStream> {
        match &self.host {
            ServerHost::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, self.port))
                .await
                .with_context(|| format!("failed to connect to server {self}")),
            ServerHost::Domain(domain) => TcpStream::connect((domain.as_str(), self.port))
                .await
                .with_context(|| format!("failed to connect to server {self}")),
        }
    }
}

impl From<SocketAddr> for ServerAddr {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: ServerHost::Ip(value.ip()),
            port: value.port(),
        }
    }
}

impl FromStr for ServerAddr {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ensure!(!value.is_empty(), "server must not be empty");
        ensure!(
            value.trim() == value,
            "server must not contain leading or trailing whitespace"
        );

        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(addr.into());
        }

        let (host, port) = value
            .rsplit_once(':')
            .with_context(|| format!("server {value:?} must include a port"))?;
        ensure!(!host.is_empty(), "server {value:?} is missing a host");
        ensure!(!port.is_empty(), "server {value:?} is missing a port");
        ensure!(
            !host.contains(':'),
            "server {value:?} contains ':' in the host; wrap IPv6 addresses in brackets"
        );
        ensure!(
            !host.contains(char::is_whitespace),
            "server {value:?} contains whitespace in the host"
        );

        let port = port
            .parse::<u16>()
            .with_context(|| format!("server {value:?} has an invalid port"))?;

        Ok(Self {
            host: ServerHost::Domain(host.to_owned()),
            port,
        })
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            ServerHost::Ip(ip) => write!(f, "{}", SocketAddr::new(*ip, self.port)),
            ServerHost::Domain(domain) => write!(f, "{domain}:{}", self.port),
        }
    }
}

impl<'de> Deserialize<'de> for ServerAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Direct,
    Socks5,
    Anytls,
    Tuic,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RoutingConfig {
    pub default: Option<String>,
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RouteRule {
    pub inbound: Option<String>,
    pub outbound: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserConfig {
    #[serde(alias = "name")]
    pub username: String,
    pub uuid: Option<String>,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsServerConfig {
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub acme: Option<TlsAcmeConfig>,
}

impl TlsServerConfig {
    pub fn certificate_path(&self) -> anyhow::Result<&str> {
        self.certificate
            .as_deref()
            .context("tls certificate path is not configured")
    }

    pub fn private_key_path(&self) -> anyhow::Result<&str> {
        self.private_key
            .as_deref()
            .context("tls private key path is not configured")
    }

    fn validate(&self, inbound_tag: &str) -> anyhow::Result<()> {
        let has_certificate = self.certificate.is_some();
        let has_private_key = self.private_key.is_some();
        let has_static = has_certificate || has_private_key;
        let has_acme = self.acme.is_some();

        if has_static {
            ensure!(
                has_certificate && has_private_key,
                "inbound {inbound_tag} tls requires both certificate and private_key"
            );
        }
        ensure!(
            has_static ^ has_acme,
            "inbound {inbound_tag} tls must configure exactly one of certificate/private_key or acme"
        );

        if let Some(acme) = &self.acme {
            ensure!(
                !acme.domains.is_empty(),
                "inbound {inbound_tag} tls.acme.domains must not be empty"
            );
            for domain in &acme.domains {
                ensure!(
                    !domain.starts_with("*."),
                    "inbound {inbound_tag} tls.acme.domains contains wildcard {domain}; HTTP-01 does not support wildcard certificates"
                );
                ensure!(
                    !domain.trim().is_empty() && !domain.contains(char::is_whitespace),
                    "inbound {inbound_tag} tls.acme.domains contains invalid domain {domain:?}"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsAcmeConfig {
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_acme_directory")]
    pub directory: String,
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_acme_http_listen")]
    pub http_listen: SocketAddr,
    #[serde(default = "default_acme_renew_before_days")]
    pub renew_before_days: u32,
    #[serde(default)]
    pub accept_terms: bool,
    #[serde(default)]
    pub contact: Vec<String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory: default_acme_directory(),
            cache_dir: default_acme_cache_dir(),
            http_listen: default_acme_http_listen(),
            renew_before_days: default_acme_renew_before_days(),
            accept_terms: false,
            contact: Vec::new(),
        }
    }
}

fn default_acme_directory() -> String {
    "letsencrypt-staging".to_owned()
}

fn default_acme_cache_dir() -> PathBuf {
    PathBuf::from(".rtunnel/acme")
}

fn default_acme_http_listen() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80)
}

fn default_acme_renew_before_days() -> u32 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_tls_acme_without_top_level_acme_block() {
        let cfg = config_with_tls(TlsServerConfig {
            certificate: None,
            private_key: None,
            acme: Some(TlsAcmeConfig {
                domains: vec!["proxy.example.com".to_owned()],
            }),
        });

        cfg.validate().unwrap();
        assert_eq!(cfg.acme_config().directory, "letsencrypt-staging");
    }

    #[test]
    fn parses_tls_acme_toml_shape() {
        let raw = r#"
[[inbounds]]
tag = "anytls-in"
listen = "127.0.0.1:443"
protocol = "anytls"

[inbounds.tls.acme]
domains = ["proxy.example.com"]

[[outbounds]]
tag = "direct"
protocol = "direct"

[routing]
default = "direct"
"#;

        let cfg: Config = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        let domains = &cfg.inbounds[0]
            .tls
            .as_ref()
            .unwrap()
            .acme
            .as_ref()
            .unwrap()
            .domains;
        assert_eq!(domains.as_slice(), &[String::from("proxy.example.com")]);
    }

    #[test]
    fn parses_domain_outbound_server() {
        let raw = r#"
[[inbounds]]
tag = "socks-in"
listen = "127.0.0.1:1080"
protocol = "socks5"

[[outbounds]]
tag = "proxy"
protocol = "socks5"
server = "proxy.example.com:1080"

[routing]
default = "proxy"
"#;

        let cfg: Config = toml::from_str(raw).unwrap();
        let server = cfg.outbounds[0].server.as_ref().unwrap();

        assert_eq!(server.to_string(), "proxy.example.com:1080");
        assert_eq!(server.domain(), Some("proxy.example.com"));
    }

    #[test]
    fn parses_ip_outbound_server() {
        let server: ServerAddr = "[::1]:443".parse().unwrap();

        assert_eq!(server.to_string(), "[::1]:443");
        assert_eq!(server.domain(), None);
    }

    #[test]
    fn rejects_domain_outbound_server_without_port() {
        let err = "proxy.example.com".parse::<ServerAddr>().unwrap_err();

        assert!(err.to_string().contains("must include a port"));
    }

    #[test]
    fn rejects_tls_with_static_and_acme_sources() {
        let cfg = config_with_tls(TlsServerConfig {
            certificate: Some("cert.pem".to_owned()),
            private_key: Some("key.pem".to_owned()),
            acme: Some(TlsAcmeConfig {
                domains: vec!["proxy.example.com".to_owned()],
            }),
        });

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_http01_wildcard_domains() {
        let cfg = config_with_tls(TlsServerConfig {
            certificate: None,
            private_key: None,
            acme: Some(TlsAcmeConfig {
                domains: vec!["*.example.com".to_owned()],
            }),
        });

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_anytls_connection_tuning() {
        let raw = r#"
[[inbounds]]
tag = "socks-in"
listen = "127.0.0.1:1080"
protocol = "socks5"

[[outbounds]]
tag = "anytls-out"
protocol = "anytls"
server = "proxy.example.com:443"
server_name = "proxy.example.com"
password = "secret"
max_connections = 4
idle_time = "2m"

[routing]
default = "anytls-out"
"#;

        let cfg: Config = toml::from_str(raw).unwrap();
        cfg.validate().unwrap();
        let outbound = &cfg.outbounds[0];

        assert_eq!(outbound.max_connections, Some(4));
        assert_eq!(outbound.max_streams, None);
        assert_eq!(outbound.anytls_max_streams(), None);
        assert_eq!(
            outbound.anytls_connection_idle_timeout(),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn defaults_anytls_connection_tuning() {
        let cfg = anytls_config(None, None, None);

        cfg.validate().unwrap();
        assert_eq!(
            cfg.outbounds[0].anytls_max_streams(),
            Some(default_anytls_max_streams())
        );
        assert_eq!(
            cfg.outbounds[0].anytls_connection_idle_timeout(),
            default_anytls_connection_idle_timeout()
        );
    }

    #[test]
    fn rejects_anytls_max_streams_with_max_connections() {
        let cfg = anytls_config(Some(4), Some(2), None);

        let err = cfg.validate().unwrap_err().to_string();

        assert!(err.contains("cannot configure both max_streams and max_connections"));
    }

    #[test]
    fn rejects_zero_anytls_connection_tuning_values() {
        let max_streams = anytls_config(Some(0), None, None);
        let max_connections = anytls_config(None, Some(0), None);
        let idle_timeout = anytls_config(None, None, Some(Duration::ZERO));

        assert!(max_streams.validate().is_err());
        assert!(max_connections.validate().is_err());
        assert!(idle_timeout.validate().is_err());
    }

    fn anytls_config(
        max_streams: Option<usize>,
        max_connections: Option<usize>,
        connection_idle_timeout: Option<Duration>,
    ) -> Config {
        Config {
            log_level: None,
            acme: None,
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_owned(),
                listen: "127.0.0.1:1080".parse().unwrap(),
                protocol: Protocol::Socks5,
                users: None,
                padding_scheme: Vec::new(),
                tls: None,
            }],
            outbounds: vec![OutboundConfig {
                tag: "anytls-out".to_owned(),
                protocol: Protocol::Anytls,
                server: Some("proxy.example.com:443".parse().unwrap()),
                server_name: Some("proxy.example.com".to_owned()),
                insecure: false,
                ca_certificate: None,
                username: None,
                password: Some("secret".to_owned()),
                uuid: None,
                max_streams,
                max_connections,
                connection_idle_timeout,
            }],
            routing: RoutingConfig {
                default: Some("anytls-out".to_owned()),
                rules: Vec::new(),
            },
        }
    }

    fn config_with_tls(tls: TlsServerConfig) -> Config {
        Config {
            log_level: None,
            acme: None,
            inbounds: vec![InboundConfig {
                tag: "tls-in".to_owned(),
                listen: "127.0.0.1:443".parse().unwrap(),
                protocol: Protocol::Anytls,
                users: None,
                padding_scheme: Vec::new(),
                tls: Some(tls),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_owned(),
                protocol: Protocol::Direct,
                server: None,
                server_name: None,
                insecure: false,
                ca_certificate: None,
                username: None,
                password: None,
                uuid: None,
                max_streams: None,
                max_connections: None,
                connection_idle_timeout: None,
            }],
            routing: RoutingConfig {
                default: Some("direct".to_owned()),
                rules: Vec::new(),
            },
        }
    }
}
