use std::sync::Arc;

use crate::{
    config::{InboundConfig, Protocol},
    router::Router,
};

pub mod anytls;
pub mod socks5;
pub mod tuic;

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    match cfg.protocol {
        Protocol::Socks5 => socks5::run(cfg, router).await,
        Protocol::Anytls => anytls::run(cfg, router).await,
        Protocol::Tuic => tuic::run(cfg, router).await,
        Protocol::Direct => anyhow::bail!("direct is only valid as an outbound"),
    }
}
