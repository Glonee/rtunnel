use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, bail};
use async_trait::async_trait;

use crate::{
    config::{Config, OutboundConfig, Protocol},
    protocol::{
        anytls::outbound::AnytlsOutbound, direct::outbound::DirectOutbound,
        socks5::outbound::Socks5Outbound, tuic::outbound::TuicOutbound,
    },
    session::{BoxDatagram, BoxStream, Session},
};

#[async_trait]
pub trait Outbound: Send + Sync {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream>;

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        let _ = session;
        bail!("udp is not supported by this outbound")
    }
}

pub struct Router {
    cfg: Config,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
}

impl Router {
    pub async fn new(cfg: Config) -> anyhow::Result<Self> {
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        for outbound in &cfg.outbounds {
            outbounds.insert(outbound.tag.clone(), build_outbound(outbound).await?);
        }
        Ok(Self { cfg, outbounds })
    }

    pub async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        let tag = self.pick_outbound(session)?;
        let outbound = self
            .outbounds
            .get(tag)
            .with_context(|| format!("unknown outbound {tag}"))?;
        outbound.dial(session).await
    }

    pub async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        let tag = self.pick_outbound(session)?;
        let outbound = self
            .outbounds
            .get(tag)
            .with_context(|| format!("unknown outbound {tag}"))?;
        outbound.dial_udp(session).await
    }

    fn pick_outbound(&self, session: &Session) -> anyhow::Result<&str> {
        for rule in &self.cfg.routing.rules {
            if rule.inbound.as_deref() == Some(session.inbound.as_str()) {
                return Ok(rule.outbound.as_str());
            }
        }

        if let Some(default) = &self.cfg.routing.default {
            return Ok(default);
        }

        self.cfg
            .outbounds
            .first()
            .map(|out| out.tag.as_str())
            .context("no outbound available")
    }
}

async fn build_outbound(cfg: &OutboundConfig) -> anyhow::Result<Arc<dyn Outbound>> {
    let outbound: Arc<dyn Outbound> = match cfg.protocol {
        Protocol::Direct => Arc::new(DirectOutbound),
        Protocol::Socks5 => Arc::new(Socks5Outbound::new(cfg.clone())?),
        Protocol::Anytls => Arc::new(AnytlsOutbound::new(cfg.clone()).await?),
        Protocol::Tuic => Arc::new(TuicOutbound::new(cfg.clone())?),
    };
    if matches!(
        cfg.protocol,
        Protocol::Socks5 | Protocol::Anytls | Protocol::Tuic
    ) && cfg.server.is_none()
    {
        bail!("outbound {} requires server", cfg.tag);
    }
    Ok(outbound)
}
