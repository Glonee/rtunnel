use std::io::{Cursor, Write};

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslFiletype, SslMethod,
    SslOptions, SslVerifyMode, SslVersion,
};

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

pub fn server_acceptor(tls: &TlsServerConfig) -> anyhow::Result<boring::ssl::SslAcceptor> {
    let mut builder = boring::ssl::SslAcceptor::mozilla_intermediate(SslMethod::tls_server())?;
    builder.set_private_key_file(&tls.private_key, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(&tls.certificate)?;
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    Ok(builder.build())
}
