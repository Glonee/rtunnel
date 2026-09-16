# rtunnel

[![unit tests](https://github.com/Glonee/rtunnel/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/Glonee/rtunnel/actions/workflows/unit-tests.yml)
[![sing-box interop](https://github.com/Glonee/rtunnel/actions/workflows/sing-box-interop.yml/badge.svg)](https://github.com/Glonee/rtunnel/actions/workflows/sing-box-interop.yml)

**WIP! Use at your own risk!**

`rtunnel` is a Rust sing-box-like proxy with protocol-specific inbound and
outbound implementations.

Supported:

- SOCKS5 inbound and outbound with TCP CONNECT and UDP ASSOCIATE
- AnyTLS inbound and outbound over BoringSSL with TLS-exporter auth and binary
  CONNECT framing, UDP relay over streams, and negotiated client-side packet
  padding and splitting
- AnyTLS HTTP fallback, either through a plaintext reverse-proxy target or a
  built-in static 404 response
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

SOCKS5 UDP associations accept packets only from the TCP client's IP. A nonzero
client port in the UDP ASSOCIATE request is enforced; otherwise the first valid
packet selects the UDP port for the association.

TUIC UDP uses the configured routing rules in both native and QUIC stream modes.
TUIC clients must authenticate within 10 seconds of completing the QUIC handshake.
Before authentication, each connection may retain at most 256 KiB of incoming
data and 256 pending streams/datagrams in total; exceeding either limit closes
the connection.

Outbound `server` values accept either an IP socket address such as
`127.0.0.1:8443` or a domain endpoint such as `proxy.example.com:8443`.

## AnyTLS fallback

AnyTLS inbounds negotiate TLS 1.3 when the client supports it, retain TLS 1.2
compatibility, and prefer `h2` over `http/1.1` through ALPN. When
authentication fails, the inbound serves a protocol-correct HTTP/2 or HTTP/1.1
static 404 response by default. For a real cover service, configure a plaintext
HTTP reverse-proxy target:

```toml
[[inbounds]]
tag = "anytls-in"
listen = "0.0.0.0:443"
protocol = "anytls"
fallback = "127.0.0.1:8080"
```

The outer TLS connection terminates in `rtunnel`, so the fallback target should
accept plaintext HTTP rather than HTTPS. Because modern clients will negotiate
`h2`, a raw fallback target should support prior-knowledge h2c as well as
HTTP/1.1. The bytes inspected during AnyTLS authentication are preserved and
forwarded to the fallback target.

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

TUIC/H3 uses upstream BoringSSL 5.x support and a pinned quiche fork with opt-in
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
