use std::{fs, net::SocketAddr, path::Path};

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub log_level: Option<String>,
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
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub listen: SocketAddr,
    pub protocol: Protocol,
    pub users: Option<Vec<UserConfig>>,
    pub tls: Option<TlsServerConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: Protocol,
    pub server: Option<SocketAddr>,
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uuid: Option<String>,
}

impl OutboundConfig {
    pub fn require_server(&self) -> anyhow::Result<SocketAddr> {
        self.server
            .with_context(|| format!("outbound {} requires server", self.tag))
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
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsServerConfig {
    pub certificate: String,
    pub private_key: String,
}
