use std::sync::Arc;

use crate::{
    config::{InboundConfig, Protocol},
    router::Router,
};

pub mod anytls;
pub mod direct;
pub mod socks5;
pub mod tuic;

pub async fn run_inbound(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    match cfg.protocol {
        Protocol::Socks5 => socks5::inbound::run(cfg, router).await,
        Protocol::Anytls => anytls::inbound::run(cfg, router).await,
        Protocol::Tuic => tuic::inbound::run(cfg, router).await,
        Protocol::Direct => anyhow::bail!("direct is only valid as an outbound"),
    }
}
