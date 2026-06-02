use async_trait::async_trait;

use crate::{
    config::OutboundConfig,
    router::Outbound,
    session::{BoxStream, Session},
};

pub struct TuicOutbound {
    cfg: OutboundConfig,
}

impl TuicOutbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        anyhow::ensure!(
            cfg.uuid.as_deref().is_some_and(|uuid| !uuid.is_empty()),
            "tuic outbound requires uuid"
        );
        anyhow::ensure!(
            cfg.password
                .as_deref()
                .is_some_and(|password| !password.is_empty()),
            "tuic outbound requires password"
        );
        let _ = std::any::type_name::<tokio_quiche::quiche::Config>();
        Ok(Self { cfg })
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    async fn dial(&self, _session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::bail!(
            "tuic outbound {} is scaffolded with tokio-quiche but stream dialing is not implemented in the MVP",
            self.cfg.tag
        )
    }
}
