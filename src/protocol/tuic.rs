pub mod codec;
pub mod inbound;
pub mod outbound;

use std::time::Duration;

use tokio_quiche::settings::QuicSettings;

pub fn quic_settings() -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];
    settings
}

pub const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(25);
