use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rtunel::{
    config::{
        Config, InboundConfig, OutboundConfig, Protocol, RoutingConfig, TlsServerConfig, UserConfig,
    },
    protocol::{
        anytls::{inbound as anytls_inbound, outbound::AnytlsOutbound},
        socks5::{inbound as socks5_inbound, outbound::Socks5Outbound},
        tuic::{inbound as tuic_inbound, outbound::TuicOutbound},
    },
    router::{Outbound, Router},
    session::{Command, Session, TargetAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

const TUIC_UUID: &str = "00000000-0000-0000-0000-000000000001";

#[tokio::test]
async fn socks5_outbound_reaches_socks5_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_socks5_inbound(None).await?;
    let client = Socks5Outbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Socks5,
        server: Some(inbound_addr),
        server_name: None,
        insecure: false,
        username: None,
        password: None,
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn socks5_outbound_authenticates_to_socks5_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_socks5_inbound(Some(("user", "pass"))).await?;
    let client = Socks5Outbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Socks5,
        server: Some(inbound_addr),
        server_name: None,
        insecure: false,
        username: Some("user".to_owned()),
        password: Some("pass".to_owned()),
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn anytls_outbound_reaches_anytls_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_anytls_inbound().await?;
    let client = AnytlsOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Anytls,
        server: Some(inbound_addr),
        server_name: Some("localhost".to_owned()),
        insecure: true,
        username: None,
        password: Some("secret".to_owned()),
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn tuic_outbound_reaches_tuic_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_tuic_inbound().await?;
    let client = TuicOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Tuic,
        server: Some(inbound_addr),
        server_name: Some("localhost".to_owned()),
        insecure: true,
        username: None,
        password: Some("secret".to_owned()),
        uuid: Some(TUIC_UUID.to_owned()),
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

async fn assert_echo_roundtrip<C>(client: C, echo_addr: SocketAddr) -> anyhow::Result<()>
where
    C: Outbound,
{
    let session = Session {
        inbound: "test-client".to_owned(),
        command: Command::Connect,
        target: TargetAddr::Ip(echo_addr),
    };
    let mut stream = timeout(Duration::from_secs(5), client.dial(&session)).await??;

    timeout(Duration::from_secs(5), stream.write_all(b"ping")).await??;
    let mut received = [0; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received)).await??;

    assert_eq!(&received, b"ping");
    Ok(())
}

async fn spawn_socks5_inbound(credentials: Option<(&str, &str)>) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let inbound_cfg = InboundConfig {
        tag: "socks-in".to_owned(),
        listen: addr,
        protocol: Protocol::Socks5,
        users: credentials.map(|(username, password)| {
            vec![UserConfig {
                username: username.to_owned(),
                uuid: None,
                password: password.to_owned(),
            }]
        }),
        padding_scheme: Vec::new(),
        tls: None,
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        inbounds: vec![inbound_cfg.clone()],
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
    })?);
    tokio::spawn(socks5_inbound::serve(listener, inbound_cfg, router));
    Ok(addr)
}

async fn spawn_anytls_inbound() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let tls = write_test_tls_files()?;
    let inbound_cfg = InboundConfig {
        tag: "anytls-in".to_owned(),
        listen: addr,
        protocol: Protocol::Anytls,
        users: Some(vec![UserConfig {
            username: "user".to_owned(),
            uuid: None,
            password: "secret".to_owned(),
        }]),
        padding_scheme: Vec::new(),
        tls: Some(tls),
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        inbounds: vec![inbound_cfg.clone()],
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
    })?);
    tokio::spawn(anytls_inbound::serve(listener, inbound_cfg, router));
    Ok(addr)
}

async fn spawn_tuic_inbound() -> anyhow::Result<SocketAddr> {
    let socket = UdpSocket::bind(localhost(0)).await?;
    let addr = socket.local_addr()?;
    let tls = write_test_tls_files()?;
    let inbound_cfg = InboundConfig {
        tag: "tuic-in".to_owned(),
        listen: addr,
        protocol: Protocol::Tuic,
        users: Some(vec![UserConfig {
            username: "user".to_owned(),
            uuid: Some(TUIC_UUID.to_owned()),
            password: "secret".to_owned(),
        }]),
        padding_scheme: Vec::new(),
        tls: Some(tls),
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        inbounds: vec![inbound_cfg.clone()],
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
    })?);
    tokio::spawn(tuic_inbound::serve(socket, inbound_cfg, router));
    Ok(addr)
}

async fn spawn_echo_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buf[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn write_test_tls_files() -> anyhow::Result<TlsServerConfig> {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let cert = std::env::temp_dir().join(format!("rtunel-{suffix}.crt"));
    let key = std::env::temp_dir().join(format!("rtunel-{suffix}.key"));
    std::fs::write(&cert, CERT_PEM)?;
    std::fs::write(&key, KEY_PEM)?;
    Ok(TlsServerConfig {
        certificate: cert.to_string_lossy().into_owned(),
        private_key: key.to_string_lossy().into_owned(),
    })
}

const CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUQqS9PiLlcPZXU7kaZJXk6SuB5hMwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwMzE0MjMzN1oXDTI2MDYw
NDE0MjMzN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwOUHpVfBQYwA5nODiQ7kp2W5uredY3K5XHITc8OuPKnT
iM9fUhaPL+tvOk8CAVpazTcTcpyMgJEx+qf3FLS71WfCtCZjxBqyLVjugxm4+dBt
mF8oY2by4e9FJZ2CXz/uKSxcsYB85iuCCV2Gc4QnxXy7TwuugnmVnjFPpG4b4hs2
XbAPwoiteVYyyEOgOYd//U72BMe82+1y1th7qR1nJ4oez/UaavxhyP/qnpo5FI3j
6McVualQEfU3+wO6f1ctK403jI6dz4Q33u1CTLlSgVg9WHqKKKM+9ckfdMPL+zcw
iGG7mdM2+vuMKFhij3pkAakhdAqIuQTyovsJ8/m0wwIDAQABo1MwUTAdBgNVHQ4E
FgQUabZLaoALnqsGUwNH/TLR3lh4LH4wHwYDVR0jBBgwFoAUabZLaoALnqsGUwNH
/TLR3lh4LH4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAKc0d
pbwkQ8CSEJ/7sjCSgpOD9BcTlZqKIMwooftO9EPSQvl4RcTkykj5DwQF5237+xWO
IVkKciXixJZyANayQmN8N6WUNAJjRmlIbXylTs71SIU2ZrDjEx2Bpb7EbswZt1FN
4cz+1c+lHdEQ4VYaog0qLwKGfx6+RZ/B5c5ftajnb6+3fZXJrQ8KPARq0Gy0Vn1E
q/bGaIY7LpQNel+jG88NQONhZm0R/zL+0GaKs1uum6rJmFvAx2DziZxbJO60yTFN
+XpBdINCT0jZsphnAXOHdy1UZ380Xy6wEvIiYbhzhfm8eRCArIsuNzkrEDkzWE4+
hvHo2CFXLDYxy/AV2w==
-----END CERTIFICATE-----
"#;

const KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDA5QelV8FBjADm
c4OJDuSnZbm6t51jcrlcchNzw648qdOIz19SFo8v6286TwIBWlrNNxNynIyAkTH6
p/cUtLvVZ8K0JmPEGrItWO6DGbj50G2YXyhjZvLh70UlnYJfP+4pLFyxgHzmK4IJ
XYZzhCfFfLtPC66CeZWeMU+kbhviGzZdsA/CiK15VjLIQ6A5h3/9TvYEx7zb7XLW
2HupHWcnih7P9Rpq/GHI/+qemjkUjePoxxW5qVAR9Tf7A7p/Vy0rjTeMjp3PhDfe
7UJMuVKBWD1Yeooooz71yR90w8v7NzCIYbuZ0zb6+4woWGKPemQBqSF0Coi5BPKi
+wnz+bTDAgMBAAECggEASWTbi+Xf+niyvvykx7mK9saV7J2AnR5BuRMOo7WIzjwv
6JY+xpUe1jTWlXEKakle00Zpd+po62JTifPu50n9Ti20v6b7vtoJgYec+PUIlMTh
bmCGlYvOTnkj7jQILwW8MJ5YhpFE9K8JQ1b6mWlnWJUlD+Z599sbOp24l+/tXBIk
21vqnQcmOY1c3nT5ZJNEljeRotrlUTDQMxHtpqurYwfMUke+TLQRuQrfhI375Vef
hw6vo7blyrn6G0oibDgppIOz/bNXR4jCyPEPIVG6GUND/fvFzvuyygaJ9jmGjrCd
qZtDi1d38JoK31OALHi6L4R74NmgUjM34FAU08ejwQKBgQDyG5atGTp0ThNy8KB4
Yhc3UTVyhO+DbHJHveNPOT1eDibBbbTadpwV+3FG7hwSs0e5AHdnS+XE6J4LEZaL
lQwYlrdNM+RAwLZa+IOuk7NwqroL0qqDjxlyvlZUzFjf28jg9o64x8vX1BjSfoTw
8I/4ymdqy9y+bGdxRmoGxd1t5QKBgQDL9ogJITKYGrc57klOgk3G+S1kBMRY2XLG
29S5h9f3NUechUdjorbgpxKy+LX+bjbsa33aGPA0/Xw/qmOY9lcC4BgbciH55agP
JXLwbGL7mLgCshVOBlhrU4X4G/Bqw/I/3CSDc2JBlZOuJq4+dDLfGV/8FZobpq0B
seZ1Dh2thwKBgQCvMNV8VlgdFu4t6v9DfT9tcN8rChTC1fNwBHD6v+GvMLBMoZUP
zGov4e3bNKutwHsy3KqKXbpbHTRXsBdu06CYHl9vhxAw5wJNm6y14/0hlvjfW0a1
whPZGvAflmrtOf4HA4LNJQ5VFA4OKy0JqBmWHuhsuC34wTqtFhXc5srPHQKBgDhZ
YffzvgCb0OcmWAZipY5FJS8uyfgqCzW5Yinnx9i6VZB+mdyDBbdHMTlU0SL73Byx
DdIFdceOCJemQWHvHNbkhoR+obhipG2a0QhvSWFtLdlAzfYCdscgCjEjtuYoQHM4
JLZUWF76LhS9BwKmI6/TWNtSNINTJxUCy0KnpbddAoGABpz3EntHgUDjGpmTBKhM
SvXKDN3Yktjym/lB9KXa8lPEZ8v+rs/7o0mASQQe3XCRGxdwuy79Azmysb3pLvq0
sVqd3Ijla7kui3ep7NWl9XySI2774hEYvf0HUOXIfLhe/dP/nWQFHC96OZ1ygRCe
IXcqeU9YRAPLNOHOZVD1yV0=
-----END PRIVATE KEY-----
"#;
