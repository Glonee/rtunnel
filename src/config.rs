use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

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
    PathBuf::from(".rtunel/acme")
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
                username: None,
                password: None,
                uuid: None,
            }],
            routing: RoutingConfig {
                default: Some("direct".to_owned()),
                rules: Vec::new(),
            },
        }
    }
}
