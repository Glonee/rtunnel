pub mod codec;
pub mod inbound;
pub mod outbound;

use std::time::Duration;

use tokio_quiche::settings::{ExtraTransportParam, QuicSettings, TlsApplicationSettings};

const CHROME_H3_ALPS_SETTINGS: &[u8] = &[];
const CHROME_QUIC_VERSION_INFORMATION: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, // chosen QUIC v1
    0x00, 0x00, 0x00, 0x01, // available QUIC v1
];

pub fn quic_settings() -> QuicSettings {
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];
    settings.tls_ech_grease = true;
    settings.tls_application_settings = vec![TlsApplicationSettings {
        proto: b"h3".to_vec(),
        settings: CHROME_H3_ALPS_SETTINGS.to_vec(),
    }];
    settings.extra_transport_params = vec![
        ExtraTransportParam {
            id: 0x0011,
            value: CHROME_QUIC_VERSION_INFORMATION.to_vec(),
        },
        ExtraTransportParam {
            id: 0x3128,
            value: Vec::new(),
        },
    ];
    settings.ack_delay_exponent = 0;
    settings.max_ack_delay = 0;
    settings.disable_active_migration = false;
    settings
}

pub const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(25);
