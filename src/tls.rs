use std::{
    fs,
    io::{Cursor, Write},
    sync::Arc,
};

use anyhow::{Context, ensure};
use boring::{
    pkey::{PKey, Private},
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SelectCertError, SslAcceptor,
        SslConnector, SslContextBuilder, SslMethod, SslOptions, SslRef, SslVerifyMode, SslVersion,
    },
    x509::X509,
};
use tokio_quiche::{
    quic::ConnectionHook,
    settings::{Hooks, TlsCertificatePaths},
};
use tracing::debug;

use crate::config::TlsServerConfig;

const CHROME_TLS12_CIPHERS: &str = "\
    ECDHE-ECDSA-AES128-GCM-SHA256:\
    ECDHE-RSA-AES128-GCM-SHA256:\
    ECDHE-ECDSA-AES256-GCM-SHA384:\
    ECDHE-RSA-AES256-GCM-SHA384:\
    ECDHE-ECDSA-CHACHA20-POLY1305:\
    ECDHE-RSA-CHACHA20-POLY1305:\
    ECDHE-RSA-AES128-SHA:\
    ECDHE-RSA-AES256-SHA:\
    AES128-GCM-SHA256:\
    AES256-GCM-SHA384:\
    AES128-SHA:\
    AES256-SHA";

const CHROME_SIGNATURE_ALGORITHMS: &str = "\
    ecdsa_secp256r1_sha256:\
    rsa_pss_rsae_sha256:\
    rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:\
    rsa_pss_rsae_sha384:\
    rsa_pkcs1_sha384:\
    rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha512";

pub fn chrome_like_connector(insecure: bool) -> anyhow::Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    builder.set_cipher_list(CHROME_TLS12_CIPHERS)?;
    builder.set_curves_list("X25519:P-256:P-384")?;
    builder.set_sigalgs_list(CHROME_SIGNATURE_ALGORITHMS)?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.enable_ocsp_stapling();
    builder.enable_signed_cert_timestamps();
    builder.add_certificate_compression_algorithm(BrotliCertificateDecompressor)?;
    builder.set_options(SslOptions::NO_COMPRESSION);
    if insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

#[derive(Default)]
struct BrotliCertificateDecompressor;

impl CertificateCompressor for BrotliCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        brotli::BrotliDecompress(&mut Cursor::new(input), output)
    }
}

pub fn server_acceptor(tls: &TlsServerConfig) -> anyhow::Result<SslAcceptor> {
    let cert_path = tls.certificate_path()?.to_owned();
    let key_path = tls.private_key_path()?.to_owned();
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())?;
    load_certificate_into_context(&mut builder, &cert_path, &key_path)?;
    if tls.acme.is_some() {
        install_certificate_reload_callback(&mut builder, cert_path, key_path);
    }
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder.build())
}

pub fn quic_hooks(tls: &TlsServerConfig) -> anyhow::Result<Hooks> {
    if tls.acme.is_none() {
        return Ok(Hooks::default());
    }

    Ok(Hooks {
        connection_hook: Some(Arc::new(ReloadingCertificateHook {
            cert_path: tls.certificate_path()?.to_owned(),
            key_path: tls.private_key_path()?.to_owned(),
        })),
        ..Hooks::default()
    })
}

#[derive(Debug)]
struct ReloadingCertificateHook {
    cert_path: String,
    key_path: String,
}

impl ConnectionHook for ReloadingCertificateHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = match SslContextBuilder::new(SslMethod::tls_server()) {
            Ok(builder) => builder,
            Err(err) => {
                debug!(%err, "failed to create QUIC TLS context for ACME certificate reload");
                return None;
            }
        };
        if let Err(err) =
            load_certificate_into_context(&mut builder, &self.cert_path, &self.key_path)
        {
            debug!(%err, "failed to load QUIC TLS certificate for ACME reload");
            return None;
        }
        install_certificate_reload_callback(
            &mut builder,
            self.cert_path.clone(),
            self.key_path.clone(),
        );
        Some(builder)
    }
}

fn install_certificate_reload_callback(
    builder: &mut SslContextBuilder,
    cert_path: String,
    key_path: String,
) {
    builder.set_select_certificate_callback(move |mut hello| {
        load_certificate_into_ssl(hello.ssl_mut(), &cert_path, &key_path).map_err(|err| {
            debug!(%err, "failed to reload ACME certificate for TLS handshake");
            SelectCertError::ERROR
        })
    });
}

fn load_certificate_into_context(
    builder: &mut SslContextBuilder,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    let (certs, key) = load_certificate_pair(cert_path, key_path)?;
    let (leaf, chain) = certs
        .split_first()
        .context("TLS certificate chain is empty")?;
    builder.set_certificate(leaf)?;
    builder.set_private_key(&key)?;
    for cert in chain {
        builder.add_extra_chain_cert(cert.to_owned())?;
    }
    builder.check_private_key()?;
    Ok(())
}

fn load_certificate_into_ssl(
    ssl: &mut SslRef,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    let (certs, key) = load_certificate_pair(cert_path, key_path)?;
    let (leaf, chain) = certs
        .split_first()
        .context("TLS certificate chain is empty")?;
    ssl.set_certificate(leaf)?;
    ssl.set_private_key(&key)?;
    for cert in chain {
        ssl.add_chain_cert(cert)?;
    }
    Ok(())
}

fn load_certificate_pair(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Vec<X509>, PKey<Private>)> {
    let cert_pem = fs::read(cert_path)
        .with_context(|| format!("failed to read TLS certificate chain {cert_path}"))?;
    let key_pem =
        fs::read(key_path).with_context(|| format!("failed to read TLS private key {key_path}"))?;
    let certs = X509::stack_from_pem(&cert_pem)
        .with_context(|| format!("failed to parse TLS certificate chain {cert_path}"))?;
    ensure!(
        !certs.is_empty(),
        "TLS certificate chain {cert_path} is empty"
    );
    let key = PKey::private_key_from_pem(&key_pem)
        .with_context(|| format!("failed to parse TLS private key {key_path}"))?;
    Ok((certs, key))
}
