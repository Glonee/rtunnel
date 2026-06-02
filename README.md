# rtunel

`rtunel` is a Rust MVP for a sing-box-like proxy with protocol-specific inbound
and outbound implementations.

Supported in this first cut:

- SOCKS5 inbound and outbound over TCP
- AnyTLS inbound and outbound scaffolding over BoringSSL
- TUIC inbound and outbound scaffolding with `tokio-quiche` as the selected QUIC
  stack
- A TOML config format with route rules and default outbound selection

The SOCKS5 path is runnable today. AnyTLS and TUIC are intentionally small MVP
transport modules: they establish the right listener/dialer boundaries and TLS /
QUIC library choices, but leave the production protocol framing, auth, UDP relay,
congestion tuning, and replay protection for the next implementation pass.

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
