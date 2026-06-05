# rtunnel

`rtunnel` is a Rust MVP for a sing-box-like proxy with protocol-specific inbound
and outbound implementations.

Supported:

- SOCKS5 inbound and outbound over TCP
- AnyTLS inbound and outbound over BoringSSL with TLS-exporter auth and binary
  CONNECT framing
- TUIC v5 inbound and outbound over `tokio-quiche`, including TCP relay,
  authentication, heartbeat, and UDP packet relay modes
- A TOML config format with route rules and default outbound selection

For the expected workflow when adding or completing a protocol, see
[`docs/protocol-implementation-guide.md`](docs/protocol-implementation-guide.md).

The SOCKS5, AnyTLS, and TUIC TCP CONNECT paths are runnable today. UDP associate
is available through the shared datagram outbound path. AnyTLS applies the
negotiated client-side packet padding and splitting scheme during early session
writes.

## Run

```sh
cargo run -- -c examples/socks.toml
```

Then point a SOCKS5 client at `127.0.0.1:1080`.

## TLS fingerprinting

TLS is backed by BoringSSL through the `boring` and `tokio-boring` crates. The
client config applies Chrome-like defaults where the public BoringSSL API allows:

- TLS 1.3 minimum preference with TLS 1.2 enabled for compatibility
- Chrome-style ALPN list: `h2`, `http/1.1`
- Broad modern cipher preference for TLS 1.2 fallback
- X25519/P-256/P-384 curve order
- SNI enabled

This does not produce a byte-for-byte Chrome ClientHello. BoringSSL gives the
same TLS implementation family Chrome uses, but exact Chrome fingerprints also
depend on fields such as extension ordering, GREASE behavior, QUIC transport
parameters, and version-specific Chrome details.
