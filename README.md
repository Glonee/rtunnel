# rtunnel

`rtunnel` is a Rust sing-box-like proxy with protocol-specific inbound and
outbound implementations.

Supported:

- SOCKS5 inbound and outbound with TCP CONNECT and UDP ASSOCIATE
- AnyTLS inbound and outbound over BoringSSL with TLS-exporter auth and binary
  CONNECT framing, UDP relay over streams, and negotiated client-side packet
  padding and splitting
- TUIC v5 inbound and outbound over `tokio-quiche`, including TCP relay,
  authentication, heartbeat, and UDP packet relay modes
- Direct TCP and UDP outbound
- ACME HTTP-01 certificates for AnyTLS and TUIC inbounds, with cached PEM files
  and hot reload for new TLS handshakes
- A TOML config format with route rules and default outbound selection

For the expected workflow when adding or completing a protocol, see
[`docs/protocol-implementation-guide.md`](docs/protocol-implementation-guide.md).

## Run

```sh
cargo run -- -c examples/socks.toml
```

Then point a SOCKS5 client at `127.0.0.1:1080`.

## ACME certificates

AnyTLS and TUIC inbounds can use ACME instead of static certificate files:

```toml
[acme]
directory = "letsencrypt-staging"
http_listen = "0.0.0.0:80"
accept_terms = true
contact = ["mailto:admin@example.com"]

[inbounds.tls.acme]
domains = ["proxy.example.com"]
```

`directory` defaults to `letsencrypt-staging`; use `letsencrypt-production` for
public trusted certificates after testing. HTTP-01 requires the configured
`http_listen` address, normally port 80, to be reachable for every domain in
`tls.acme.domains`. Certificates and account credentials are cached under
`.rtunnel/acme` by default. If no valid cached certificate exists and issuance
fails, startup fails; if a cached certificate is still valid, renewal failures
are logged and retried later.

## TLS fingerprinting

TLS is backed by BoringSSL through the `boring` and `tokio-boring` crates. TCP
TLS outbounds apply Chrome-like defaults:

- TLS 1.3 minimum preference with TLS 1.2 enabled for compatibility
- Chrome-style ALPN list: `h2`, `http/1.1`
- Broad modern cipher preference for TLS 1.2 fallback
- Chrome-style supported group order: `X25519MLKEM768`, `X25519`, `P-256`, `P-384`
- GREASE, shuffled extensions, ECH GREASE, h2 ALPS, OCSP stapling, SCTs, and
  Brotli certificate decompression
- SNI enabled

TUIC/H3 uses a pinned quiche fork with BoringSSL 5.x support and opt-in
fingerprint controls for ECH GREASE, h3 ALPS, and extra QUIC transport
parameters. The outbound TUIC path advertises Chrome-like QUIC transport
parameters, TLS application settings, signature algorithms, certificate
compression, and supported groups.

Thumbprint probes currently classify the TCP h2 fingerprint as a slightly older
Chrome/Chromium profile, and the TUIC/H3 TLS and QUIC transport-parameter
fingerprints as Chrome 149-family profiles.

These settings are fingerprint-sensitive rather than a guarantee of byte-for-byte
Chrome behavior. Chrome fingerprints can change between releases, and fields
such as extension ordering, GREASE behavior, PSK/resumption, HTTP headers, and
future post-quantum advertisements may need periodic re-verification.
