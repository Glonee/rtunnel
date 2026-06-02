use boring::ssl::{SslConnector, SslFiletype, SslMethod, SslOptions, SslVerifyMode, SslVersion};

use crate::config::TlsServerConfig;

pub fn chrome_like_connector(insecure: bool) -> anyhow::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    builder.set_cipher_list(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\
         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    )?;
    builder.set_curves_list("X25519:P-256:P-384")?;
    builder.set_options(SslOptions::NO_COMPRESSION);
    if insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

pub fn server_acceptor(tls: &TlsServerConfig) -> anyhow::Result<boring::ssl::SslAcceptor> {
    let mut builder = boring::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls_server())?;
    builder.set_private_key_file(&tls.private_key, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(&tls.certificate)?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder.build())
}
