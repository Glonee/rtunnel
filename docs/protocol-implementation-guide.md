# Protocol Implementation Guide

This guide is the expected path for adding or finishing a protocol in `rtunel`.
The short version is: read the upstream spec, encode the wire format first,
build inbound and outbound as separate protocol-owned modules, test them against
each other, then prove both directions against sing-box.

## Scope And Exit Criteria

A protocol is considered implemented only when all of these are true:

- The upstream spec has been read and converted into a feature matrix.
- The protocol has `codec.rs`, `inbound.rs`, and `outbound.rs` under
  `src/protocol/<protocol>/`.
- The config model can build both inbound and outbound instances.
- Unit tests cover every encoder, decoder, and state-machine edge that can be
  tested without sockets.
- Integration tests cover `rtunel` inbound against `rtunel` outbound.
- Interop tests cover `rtunel` outbound against sing-box inbound.
- Interop tests cover sing-box outbound against `rtunel` inbound.
- Known unsupported spec features are documented before merge.

## Step 1: Read The Spec

Start with the upstream protocol spec, then compare it with sing-box's current
configuration docs and behavior.

Recommended sources:

- TUIC spec: <https://github.com/tuic-protocol/tuic/blob/master/SPEC.md>
- AnyTLS spec: <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>
- sing-box inbound docs: <https://sing-box.sagernet.org/configuration/inbound/>
- sing-box outbound docs: <https://sing-box.sagernet.org/configuration/outbound/>
- sing-box TLS docs: <https://sing-box.sagernet.org/configuration/shared/tls/>

Write a small feature matrix before coding:

```text
Feature                  Spec required  rtunel inbound  rtunel outbound  sing-box field/test
Authentication           yes            planned         planned          users/password
TCP connect              yes            planned         planned          curl through SOCKS
UDP native/datagram      optional       planned         planned          udp_relay_mode=native
UDP stream mode          optional       planned         planned          udp_relay_mode=quic
Heartbeat                yes            planned         planned          idle connection test
Padding/session reuse    protocol dep.  planned         planned          protocol-specific
```

For TUIC, pay special attention to:

- version byte and command IDs
- TLS exporter token inputs
- address type mapping
- authentication before, after, or parallel with other commands
- TCP stream relay
- UDP associate IDs, packet IDs, fragmentation, and dissociation
- native datagram mode vs QUIC stream mode
- heartbeat behavior

For AnyTLS, pay special attention to:

- client hello and password authentication
- frame header layout
- `cmdSettings`, `cmdServerSettings`, `cmdUpdatePaddingScheme`, and `cmdAlert`
- session reuse and stream IDs
- padding scheme parsing and packet shaping
- heartbeat request/response
- TLS behavior and fingerprint-sensitive settings

## Step 2: Put Code In The Protocol Path

Keep each protocol self-contained:

```text
src/protocol/<protocol>.rs
src/protocol/<protocol>/codec.rs
src/protocol/<protocol>/inbound.rs
src/protocol/<protocol>/outbound.rs
```

Do not use `mod.rs`. The top-level `src/protocol/<protocol>.rs` file should
declare the protocol-owned modules:

```rust
pub mod codec;
pub mod inbound;
pub mod outbound;
```

Wire the protocol into:

- `src/protocol.rs` for inbound dispatch
- `src/router.rs` for outbound construction
- `src/config.rs` for config enum and protocol-specific fields

Keep shared behavior out of protocol modules only when it is truly shared. TLS
fingerprint setup belongs in `src/tls.rs`; wire-format parsing belongs in the
protocol codec.

## Step 3: Implement Codec First

The codec should not know about sockets, routing, or tasks. It should only know
how to turn bytes into protocol values and protocol values into bytes.

Codec checklist:

- Define constants for version, command IDs, address types, and fixed lengths.
- Encode and decode each command independently.
- Validate lengths before slicing.
- Reject invalid enum values and impossible fragment states.
- Preserve protocol byte order.
- Keep raw bytes raw. Do not force UTF-8 unless the spec says a field is text.
- Add unit tests for every command and every address family.
- Add negative tests for short buffers, invalid commands, invalid fragments, and
  overflow boundaries.

Example unit-test shape:

```rust
#[test]
fn roundtrips_packet() {
    let encoded = encode_packet(&packet).unwrap();
    let decoded = parse_packet(&encoded).unwrap();
    assert_eq!(decoded, packet);
}
```

## Step 4: Implement Inbound

Inbound code accepts peer connections, authenticates the client, converts a
protocol request into a `Session`, and calls `Router::dial`.

Inbound checklist:

- Parse and validate config at startup.
- Fail early when required users, TLS, UUIDs, or passwords are missing.
- Keep one connection state object per peer.
- Authenticate before forwarding application payload, unless the spec explicitly
  allows pre-auth command queuing.
- For TCP connect, bridge peer stream data to the selected outbound.
- For UDP, keep per-connection associate/session state.
- Handle graceful shutdown and peer FIN.
- Log target, inbound tag, and auth identity at useful points.
- Avoid panics on malformed peer input.

Use the existing patterns in:

- `src/protocol/socks5/inbound.rs`
- `src/protocol/anytls/inbound.rs`
- `src/protocol/tuic/inbound.rs`

## Step 5: Implement Outbound

Outbound code implements the `Outbound` trait and returns a `BoxStream` for
`Command::Connect`.

Outbound checklist:

- Validate required config in `new`.
- Establish transport and TLS/QUIC handshakes in `dial`.
- Send authentication and protocol setup before exposing the stream.
- Keep protocol state in a small session object when the protocol is multiplexed.
- Reconnect when the underlying session is closed.
- Do not hard-code test credentials or ports.
- Return clear errors for unsupported commands.

The current `Outbound` trait is stream-oriented. If the protocol has first-class
UDP behavior, add tests through protocol-level helpers first, then extend the
public abstraction deliberately.

## Step 6: Test Inside rtunel

Run the fast checks first:

```sh
cargo fmt
cargo test
```

Unit tests should live next to the codec or state machine they test.
Integration tests should live in `tests/protocol_loopback.rs`.

Minimum loopback tests for a protocol:

- outbound reaches inbound over TCP connect
- auth success
- auth failure or malformed auth
- inbound rejects or alerts on invalid command ordering
- large payload round trip
- EOF/FIN closes the matching peer side
- UDP echo for every relay mode the protocol claims to support

Use local echo helpers instead of external network services. That keeps tests
deterministic and makes CI possible.

## Step 7: Test Against sing-box

Interop must be tested in both directions.

Use the same target service for both directions. For TCP, a local HTTP server is
simple:

```sh
python3 -m http.server 18080 --bind 127.0.0.1
```

Then test through a local SOCKS inbound:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:18080/
```

When client and server are on different machines, run the HTTP server on the
server side or use a target address reachable from the server side.

### Direction A: rtunel Outbound To sing-box Inbound

1. Start sing-box as the protocol server.
2. Start `rtunel` with a SOCKS inbound and the protocol outbound.
3. Send traffic through `rtunel`'s local SOCKS inbound.
4. Confirm the target service receives traffic.
5. Check both logs for auth, target address, and close behavior.

Generic `rtunel` client config shape:

```toml
log_level = "debug"

[[inbounds]]
tag = "socks-in"
listen = "127.0.0.1:1080"
protocol = "socks5"

[[outbounds]]
tag = "candidate-out"
protocol = "<protocol>"
server = "127.0.0.1:<sing-box-port>"
server_name = "localhost"
password = "change-me"
insecure = true

[routing]
default = "candidate-out"
```

For TUIC, include `uuid`. For SOCKS, include `username` and `password` only when
the sing-box inbound requires auth.

### Direction B: sing-box Outbound To rtunel Inbound

1. Start `rtunel` as the protocol server with direct outbound.
2. Start sing-box with a SOCKS inbound and the protocol outbound.
3. Send traffic through sing-box's local SOCKS inbound.
4. Confirm the target service receives traffic.
5. Check both logs for auth, target address, and close behavior.

Generic sing-box client config shape:

```json
{
  "log": {
    "level": "debug"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "<protocol>",
      "tag": "candidate-out",
      "server": "127.0.0.1",
      "server_port": 8443,
      "password": "change-me",
      "tls": {
        "enabled": true,
        "server_name": "localhost",
        "insecure": true
      }
    }
  ],
  "route": {
    "final": "candidate-out"
  }
}
```

For TUIC, include `uuid`, `congestion_control`, `udp_relay_mode`, and
`heartbeat` as needed. For SOCKS outbound, use `version`, `username`,
`password`, and `network` as needed.

### sing-box Server Templates

AnyTLS inbound:

```json
{
  "log": {
    "level": "debug"
  },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        {
          "name": "demo",
          "password": "change-me"
        }
      ],
      "padding_scheme": [],
      "tls": {
        "enabled": true,
        "certificate_path": "cert.pem",
        "key_path": "key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

TUIC inbound:

```json
{
  "log": {
    "level": "debug"
  },
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "127.0.0.1",
      "listen_port": 4433,
      "users": [
        {
          "name": "demo",
          "uuid": "00000000-0000-0000-0000-000000000001",
          "password": "change-me"
        }
      ],
      "congestion_control": "cubic",
      "heartbeat": "10s",
      "tls": {
        "enabled": true,
        "certificate_path": "cert.pem",
        "key_path": "key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

SOCKS inbound:

```json
{
  "log": {
    "level": "debug"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": 1081,
      "users": [
        {
          "username": "demo",
          "password": "change-me"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

### sing-box Client Templates

AnyTLS outbound:

```json
{
  "type": "anytls",
  "tag": "anytls-out",
  "server": "127.0.0.1",
  "server_port": 8443,
  "password": "change-me",
  "tls": {
    "enabled": true,
    "server_name": "localhost",
    "insecure": true
  }
}
```

TUIC outbound:

```json
{
  "type": "tuic",
  "tag": "tuic-out",
  "server": "127.0.0.1",
  "server_port": 4433,
  "uuid": "00000000-0000-0000-0000-000000000001",
  "password": "change-me",
  "congestion_control": "cubic",
  "udp_relay_mode": "native",
  "heartbeat": "10s",
  "tls": {
    "enabled": true,
    "server_name": "localhost",
    "insecure": true
  }
}
```

SOCKS outbound:

```json
{
  "type": "socks",
  "tag": "socks-out",
  "server": "127.0.0.1",
  "server_port": 1081,
  "version": "5",
  "username": "demo",
  "password": "change-me",
  "network": "tcp"
}
```

## Interop Test Checklist

For each protocol and direction, record:

- `rtunel` commit hash
- sing-box version
- OS and CPU architecture
- protocol config files
- TCP connect result
- UDP result, if supported
- auth failure result
- large payload result
- idle timeout or heartbeat result
- packet capture notes, if TLS/QUIC behavior changed
- unsupported fields or behavior differences

Keep configs in `/tmp` while iterating. Move stable examples into `examples/`
only after they are known to work.

## Debugging Interop Failures

Work from the outside in:

- Confirm the target service works without a proxy.
- Confirm the local SOCKS inbound accepts TCP.
- Confirm the protocol server is listening on the expected TCP or UDP port.
- Confirm TLS certificate path, SNI, and `insecure` behavior.
- Confirm credentials match exactly.
- Confirm address encoding for IPv4, IPv6, and domains.
- Confirm command ordering against the spec.
- Confirm EOF/FIN behavior with short requests.
- For TUIC, confirm QUIC ALPN, datagram support, stream IDs, and UDP relay mode.
- For AnyTLS, confirm settings are sent before streams and padding updates are
  applied before the next session.

Do not hide failures by relaxing validation. If sing-box accepts something that
the spec rejects, document the behavior and add a test before matching it.

## Merge Checklist

Before committing a protocol change:

```sh
cargo fmt
cargo test
git diff --check
```

The commit message should name the protocol and behavior, for example:

```text
Implement TUIC stream UDP interop
```

The final note for the change should include:

- what spec features were added
- which `cargo test` suites passed
- which sing-box directions passed
- what remains unsupported
