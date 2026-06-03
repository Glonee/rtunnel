use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::{
    router::Outbound,
    session::{BoxStream, Command, Session},
};

pub struct DirectOutbound;

#[async_trait]
impl Outbound for DirectOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "direct outbound only supports CONNECT"
        );
        let stream = TcpStream::connect(session.target.to_string()).await?;
        Ok(Box::new(stream))
    }
}
