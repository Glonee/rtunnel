#!/usr/bin/env node

import dgram from "node:dgram";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RTUNEL_BIN = process.env.RTUNEL_BIN ?? path.join(ROOT, "target", "debug", "rtunel");
const SING_BOX_BIN =
  process.env.SING_BOX_BIN ??
  [
    "/private/tmp/sing-box-1.13.13-darwin-arm64/sing-box",
    "/tmp/sing-box-1.13.13-darwin-arm64/sing-box",
    "sing-box",
  ].find((candidate) => candidate === "sing-box" || fs.existsSync(candidate));

const PASSWORD = "secret";
const TUIC_UUID = "00000000-0000-0000-0000-000000000001";
const TIMEOUT_MS = Number(process.env.INTEROP_TIMEOUT_MS ?? 8000);

const cases = [
  { protocol: "socks5", direction: "rtunel-out-to-sing-box-in" },
  { protocol: "socks5", direction: "sing-box-out-to-rtunel-in" },
  { protocol: "anytls", direction: "rtunel-out-to-sing-box-in" },
  { protocol: "anytls", direction: "sing-box-out-to-rtunel-in" },
  { protocol: "tuic", direction: "rtunel-out-to-sing-box-in" },
  {
    protocol: "tuic",
    direction: "sing-box-out-to-rtunel-in",
    singBoxUdpRelayMode: "native",
  },
  {
    protocol: "tuic",
    direction: "sing-box-out-to-rtunel-in",
    singBoxUdpRelayMode: "quic",
  },
];

main().catch((error) => {
  console.error(error.stack ?? String(error));
  process.exit(1);
});

async function main() {
  if (!SING_BOX_BIN) {
    throw new Error("sing-box binary not found; set SING_BOX_BIN=/path/to/sing-box");
  }
  if (!fs.existsSync(RTUNEL_BIN)) {
    throw new Error(`rtunel binary not found at ${RTUNEL_BIN}; run cargo build first`);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rtunel-sing-box-interop-"));
  const cert = createCertificate(tmpDir);
  const tcpEcho = await createTcpEchoServer();
  const udpEcho = await createUdpEchoServer();
  const results = [];

  console.log(`rtunel: ${RTUNEL_BIN}`);
  console.log(`sing-box: ${SING_BOX_BIN}`);
  console.log(`workdir: ${tmpDir}`);

  try {
    console.log((await commandOutput(SING_BOX_BIN, ["version"])).split("\n")[0]);

    for (const testCase of cases) {
      const label = caseLabel(testCase);
      try {
        await runCase(testCase, tmpDir, cert, tcpEcho, udpEcho);
        results.push({ label, ok: true });
        console.log(`ok ${label}`);
      } catch (error) {
        results.push({ label, ok: false, error });
        console.error(`not ok ${label}: ${error.message}`);
      }
    }
  } finally {
    await tcpEcho.close();
    await udpEcho.close();
  }

  const failed = results.filter((result) => !result.ok);
  console.log("");
  console.log("Interop summary:");
  for (const result of results) {
    console.log(`${result.ok ? "PASS" : "FAIL"} ${result.label}`);
  }
  if (failed.length > 0) {
    throw new Error(`${failed.length} interop case(s) failed`);
  }
}

async function runCase(testCase, tmpDir, cert, tcpEcho, udpEcho) {
  const serverPort = testCase.protocol === "tuic" ? await freeUdpPort() : await freeTcpPort();
  const socksPort = await freeTcpPort();
  const label = caseLabel(testCase);
  const caseDir = path.join(tmpDir, safeName(label));
  fs.mkdirSync(caseDir, { recursive: true });

  const processes = [];
  try {
    if (testCase.direction === "rtunel-out-to-sing-box-in") {
      const singConfig = singBoxServerConfig(testCase.protocol, serverPort, cert);
      const rtunelConfig = rtunelClientConfig(testCase.protocol, socksPort, serverPort);
      const singPath = writeJson(caseDir, "sing-box-server.json", singConfig);
      const rtunelPath = writeText(caseDir, "rtunel-client.toml", rtunelConfig);
      const sing = spawnLogged("sing-box-server", SING_BOX_BIN, ["run", "-c", singPath], caseDir);
      processes.push(sing);
      await waitForProtocolServer(sing, testCase.protocol, serverPort);
      const rtunel = spawnLogged("rtunel-client", RTUNEL_BIN, ["-c", rtunelPath], caseDir);
      processes.push(rtunel);
      await waitForTcpPort(socksPort, rtunel);
    } else {
      const rtunelConfig = rtunelServerConfig(testCase.protocol, serverPort, cert);
      const singConfig = singBoxClientConfig(
        testCase.protocol,
        socksPort,
        serverPort,
        testCase.singBoxUdpRelayMode,
      );
      const rtunelPath = writeText(caseDir, "rtunel-server.toml", rtunelConfig);
      const singPath = writeJson(caseDir, "sing-box-client.json", singConfig);
      const rtunel = spawnLogged("rtunel-server", RTUNEL_BIN, ["-c", rtunelPath], caseDir);
      processes.push(rtunel);
      await waitForProtocolServer(rtunel, testCase.protocol, serverPort);
      const sing = spawnLogged("sing-box-client", SING_BOX_BIN, ["run", "-c", singPath], caseDir);
      processes.push(sing);
      await waitForTcpPort(socksPort, sing);
    }

    await tcpRoundTrip(socksPort, tcpEcho.port, Buffer.from(`${label}:tcp`));
    await udpRoundTrip(socksPort, udpEcho, Buffer.from(`${label}:udp:one`));
    await udpRoundTrip(socksPort, udpEcho, Buffer.from(`${label}:udp:two`));
  } catch (error) {
    error.message = `${error.message}\nlogs: ${processes.map((p) => p.logPath).join(", ")}`;
    throw error;
  } finally {
    await Promise.all(processes.reverse().map(stopProcess));
  }
}

function singBoxServerConfig(protocol, port, cert) {
  const inbound = {
    socks5: {
      type: "socks",
      tag: "socks-in",
      listen: "127.0.0.1",
      listen_port: port,
    },
    anytls: {
      type: "anytls",
      tag: "anytls-in",
      listen: "127.0.0.1",
      listen_port: port,
      users: [{ name: "demo", password: PASSWORD }],
      padding_scheme: [],
      tls: {
        enabled: true,
        certificate_path: cert.certPath,
        key_path: cert.keyPath,
      },
    },
    tuic: {
      type: "tuic",
      tag: "tuic-in",
      listen: "127.0.0.1",
      listen_port: port,
      users: [{ name: "demo", uuid: TUIC_UUID, password: PASSWORD }],
      congestion_control: "cubic",
      heartbeat: "10s",
      tls: {
        enabled: true,
        certificate_path: cert.certPath,
        key_path: cert.keyPath,
        alpn: ["h3"],
      },
    },
  }[protocol];

  return {
    log: { level: "debug", timestamp: false },
    inbounds: [inbound],
    outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct" },
  };
}

function singBoxClientConfig(protocol, socksPort, serverPort, udpRelayMode = "native") {
  const outbound = {
    socks5: {
      type: "socks",
      tag: "socks-out",
      server: "127.0.0.1",
      server_port: serverPort,
      version: "5",
    },
    anytls: {
      type: "anytls",
      tag: "anytls-out",
      server: "127.0.0.1",
      server_port: serverPort,
      password: PASSWORD,
      tls: {
        enabled: true,
        server_name: "localhost",
        insecure: true,
      },
    },
    tuic: {
      type: "tuic",
      tag: "tuic-out",
      server: "127.0.0.1",
      server_port: serverPort,
      uuid: TUIC_UUID,
      password: PASSWORD,
      congestion_control: "cubic",
      udp_relay_mode: udpRelayMode,
      heartbeat: "10s",
      tls: {
        enabled: true,
        server_name: "localhost",
        insecure: true,
        alpn: ["h3"],
      },
    },
  }[protocol];

  return {
    log: { level: "debug", timestamp: false },
    inbounds: [
      {
        type: "socks",
        tag: "socks-in",
        listen: "127.0.0.1",
        listen_port: socksPort,
      },
    ],
    outbounds: [outbound],
    route: { final: outbound.tag },
  };
}

function rtunelClientConfig(protocol, socksPort, serverPort) {
  const protocolName = protocol === "socks5" ? "socks5" : protocol;
  const extra =
    protocol === "anytls"
      ? `password = "${PASSWORD}"\nserver_name = "localhost"\ninsecure = true\n`
      : protocol === "tuic"
        ? `uuid = "${TUIC_UUID}"\npassword = "${PASSWORD}"\nserver_name = "localhost"\ninsecure = true\n`
        : "";
  return `log_level = "debug"

[[inbounds]]
tag = "socks-in"
listen = "127.0.0.1:${socksPort}"
protocol = "socks5"

[[outbounds]]
tag = "${protocol}-out"
protocol = "${protocolName}"
server = "127.0.0.1:${serverPort}"
${extra}
[routing]
default = "${protocol}-out"
`;
}

function rtunelServerConfig(protocol, port, cert) {
  if (protocol === "socks5") {
    return `log_level = "debug"

[[inbounds]]
tag = "socks-in"
listen = "127.0.0.1:${port}"
protocol = "socks5"

[[outbounds]]
tag = "direct"
protocol = "direct"

[routing]
default = "direct"
`;
  }

  const tls = `
[inbounds.tls]
certificate = "${cert.certPath}"
private_key = "${cert.keyPath}"
`;
  const users =
    protocol === "anytls"
      ? `[[inbounds.users]]
name = "demo"
password = "${PASSWORD}"
`
      : `[[inbounds.users]]
name = "demo"
uuid = "${TUIC_UUID}"
password = "${PASSWORD}"
`;

  return `log_level = "debug"

[[inbounds]]
tag = "${protocol}-in"
listen = "127.0.0.1:${port}"
protocol = "${protocol}"
${users}${tls}
[[outbounds]]
tag = "direct"
protocol = "direct"

[routing]
default = "direct"
`;
}

async function tcpRoundTrip(socksPort, targetPort, payload) {
  const socket = await socksConnect("127.0.0.1", socksPort);
  const reader = new SocketReader(socket);
  try {
    await socksGreeting(socket, reader);
    await socksConnectRequest(socket, reader, "127.0.0.1", targetPort);
    socket.write(payload);
    const echoed = await reader.readExactly(payload.length);
    if (!echoed.equals(payload)) {
      throw new Error(`tcp echo mismatch: got ${echoed.toString("hex")}`);
    }
  } finally {
    socket.destroy();
  }
}

async function udpRoundTrip(socksPort, udpEcho, payload) {
  const control = await socksConnect("127.0.0.1", socksPort);
  const reader = new SocketReader(control);
  const udpSocket = dgram.createSocket("udp4");
  const before = udpEcho.received.length;
  try {
    await socksGreeting(control, reader);
    const relay = await socksUdpAssociate(control, reader);
    await bindUdp(udpSocket);
    const response = waitForUdpResponse(udpSocket, payload);
    udpSocket.send(
      encodeSocksUdpPacket("127.0.0.1", udpEcho.port, payload),
      relay.port,
      relay.host,
    );
    const decoded = await response;
    if (!decoded.payload.equals(payload)) {
      throw new Error(`udp echo mismatch: got ${decoded.payload.toString("hex")}`);
    }
    const seen = udpEcho.received
      .slice(before)
      .some((packet) => packet.message.equals(payload));
    if (!seen) {
      throw new Error("udp echo server did not receive the sent packet");
    }
  } finally {
    control.destroy();
    udpSocket.close();
  }
}

async function socksConnect(host, port) {
  const socket = net.createConnection({ host, port });
  await onceWithTimeout(socket, "connect", TIMEOUT_MS, `connect socks ${host}:${port}`);
  return socket;
}

async function socksGreeting(socket, reader) {
  socket.write(Buffer.from([0x05, 0x01, 0x00]));
  const response = await reader.readExactly(2);
  if (response[0] !== 0x05 || response[1] !== 0x00) {
    throw new Error(`socks auth rejected: ${response.toString("hex")}`);
  }
}

async function socksConnectRequest(socket, reader, targetHost, targetPort) {
  socket.write(
    Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00]),
      encodeSocksAddr(targetHost, targetPort),
    ]),
  );
  await readSocksReply(reader, "connect");
}

async function socksUdpAssociate(socket, reader) {
  socket.write(
    Buffer.concat([
      Buffer.from([0x05, 0x03, 0x00]),
      encodeSocksAddr("0.0.0.0", 0),
    ]),
  );
  return readSocksReply(reader, "udp associate");
}

async function readSocksReply(reader, label) {
  const head = await reader.readExactly(4);
  if (head[0] !== 0x05 || head[1] !== 0x00 || head[2] !== 0x00) {
    throw new Error(`socks ${label} failed: ${head.toString("hex")}`);
  }
  const addr = await readSocksAddr(reader, head[3]);
  return addr;
}

function encodeSocksUdpPacket(host, port, payload) {
  return Buffer.concat([Buffer.from([0x00, 0x00, 0x00]), encodeSocksAddr(host, port), payload]);
}

function decodeSocksUdpPacket(packet) {
  if (packet.length < 4 || packet[0] !== 0 || packet[1] !== 0 || packet[2] !== 0) {
    throw new Error(`invalid socks udp response: ${packet.toString("hex")}`);
  }
  const { host, port, consumed } = decodeSocksAddr(packet, 3);
  return { host, port, payload: packet.subarray(consumed) };
}

function encodeSocksAddr(host, port) {
  if (net.isIPv4(host)) {
    return Buffer.from([0x01, ...host.split(".").map(Number), port >> 8, port & 0xff]);
  }
  if (net.isIPv6(host)) {
    throw new Error("IPv6 is not used by this interop harness");
  }
  const name = Buffer.from(host);
  return Buffer.concat([Buffer.from([0x03, name.length]), name, portBytes(port)]);
}

async function readSocksAddr(reader, atyp) {
  if (atyp === 0x01) {
    const data = await reader.readExactly(6);
    return { host: [...data.subarray(0, 4)].join("."), port: data.readUInt16BE(4) };
  }
  if (atyp === 0x03) {
    const len = (await reader.readExactly(1))[0];
    const data = await reader.readExactly(len + 2);
    return {
      host: data.subarray(0, len).toString(),
      port: data.readUInt16BE(len),
    };
  }
  if (atyp === 0x04) {
    const data = await reader.readExactly(18);
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(data.readUInt16BE(i).toString(16));
    return { host: parts.join(":"), port: data.readUInt16BE(16) };
  }
  throw new Error(`unsupported socks address type ${atyp}`);
}

function decodeSocksAddr(buffer, offset) {
  const atyp = buffer[offset];
  if (atyp === 0x01) {
    const host = [...buffer.subarray(offset + 1, offset + 5)].join(".");
    const port = buffer.readUInt16BE(offset + 5);
    return { host, port, consumed: offset + 7 };
  }
  if (atyp === 0x03) {
    const len = buffer[offset + 1];
    const host = buffer.subarray(offset + 2, offset + 2 + len).toString();
    const port = buffer.readUInt16BE(offset + 2 + len);
    return { host, port, consumed: offset + 2 + len + 2 };
  }
  if (atyp === 0x04) {
    const parts = [];
    for (let i = offset + 1; i < offset + 17; i += 2) {
      parts.push(buffer.readUInt16BE(i).toString(16));
    }
    const port = buffer.readUInt16BE(offset + 17);
    return { host: parts.join(":"), port, consumed: offset + 19 };
  }
  throw new Error(`unsupported socks address type ${atyp}`);
}

function waitForUdpResponse(socket, payload) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timeout waiting for udp response ${payload}`));
    }, TIMEOUT_MS);
    const onMessage = (message) => {
      try {
        const decoded = decodeSocksUdpPacket(message);
        if (decoded.payload.equals(payload)) {
          cleanup();
          resolve(decoded);
        }
      } catch (error) {
        cleanup();
        reject(error);
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("message", onMessage);
    };
    socket.on("message", onMessage);
  });
}

class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.buffers = [];
    this.length = 0;
    this.waiters = [];
    this.closed = false;
    socket.on("data", (data) => {
      this.buffers.push(data);
      this.length += data.length;
      this.flush();
    });
    socket.on("close", () => {
      this.closed = true;
      this.flush();
    });
    socket.on("error", () => {
      this.closed = true;
      this.flush();
    });
  }

  readExactly(size) {
    if (this.length >= size) {
      return Promise.resolve(this.take(size));
    }
    if (this.closed) {
      return Promise.reject(new Error(`socket closed while reading ${size} bytes`));
    }
    return withTimeout(
      new Promise((resolve, reject) => {
        this.waiters.push({ size, resolve, reject });
      }),
      TIMEOUT_MS,
      `read ${size} bytes`,
    );
  }

  flush() {
    while (this.waiters.length > 0) {
      const waiter = this.waiters[0];
      if (this.length >= waiter.size) {
        this.waiters.shift();
        waiter.resolve(this.take(waiter.size));
      } else if (this.closed) {
        this.waiters.shift();
        waiter.reject(new Error(`socket closed while reading ${waiter.size} bytes`));
      } else {
        break;
      }
    }
  }

  take(size) {
    const output = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const chunk = this.buffers[0];
      const copy = Math.min(chunk.length, size - offset);
      chunk.copy(output, offset, 0, copy);
      offset += copy;
      if (copy === chunk.length) {
        this.buffers.shift();
      } else {
        this.buffers[0] = chunk.subarray(copy);
      }
    }
    this.length -= size;
    return output;
  }
}

async function createTcpEchoServer() {
  const server = net.createServer((socket) => socket.pipe(socket));
  await listenTcp(server, 0);
  return {
    port: server.address().port,
    close: () => closeServer(server),
  };
}

async function createUdpEchoServer() {
  const socket = dgram.createSocket("udp4");
  const received = [];
  socket.on("message", (message, rinfo) => {
    received.push({ message: Buffer.from(message), rinfo });
    socket.send(message, rinfo.port, rinfo.address);
  });
  await bindUdp(socket);
  return {
    port: socket.address().port,
    received,
    close: () => closeUdp(socket),
  };
}

async function freeTcpPort() {
  const server = net.createServer();
  await listenTcp(server, 0);
  const port = server.address().port;
  await closeServer(server);
  return port;
}

async function freeUdpPort() {
  const socket = dgram.createSocket("udp4");
  await bindUdp(socket);
  const port = socket.address().port;
  await closeUdp(socket);
  return port;
}

function listenTcp(server, port) {
  server.listen(port, "127.0.0.1");
  return onceWithTimeout(server, "listening", TIMEOUT_MS, `listen tcp ${port}`);
}

function bindUdp(socket) {
  socket.bind(0, "127.0.0.1");
  return onceWithTimeout(socket, "listening", TIMEOUT_MS, "bind udp");
}

async function waitForProtocolServer(proc, protocol, port) {
  if (protocol === "tuic") {
    await sleep(500);
    ensureAlive(proc);
    return;
  }
  await waitForTcpPort(port, proc);
}

async function waitForTcpPort(port, proc) {
  const deadline = Date.now() + TIMEOUT_MS;
  let lastError;
  while (Date.now() < deadline) {
    ensureAlive(proc);
    try {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      await onceWithTimeout(socket, "connect", 250, `connect tcp ${port}`);
      socket.destroy();
      return;
    } catch (error) {
      lastError = error;
      await sleep(50);
    }
  }
  throw new Error(`timeout waiting for tcp port ${port}: ${lastError?.message ?? "unknown"}`);
}

function spawnLogged(name, command, args, cwd) {
  const logPath = path.join(cwd, `${name}.log`);
  const stream = fs.createWriteStream(logPath);
  const child = spawn(command, args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, RUST_LOG: "debug" },
  });
  let tail = "";
  const append = (data) => {
    const text = data.toString();
    stream.write(text);
    tail = (tail + text).slice(-4000);
  };
  child.stdout.on("data", append);
  child.stderr.on("data", append);
  child.on("exit", () => stream.end());
  child.logPath = logPath;
  child.tail = () => tail;
  return child;
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGINT");
  try {
    await withTimeout(once(child, "exit"), 1500, `stop ${child.spawnfile}`);
  } catch {
    child.kill("SIGKILL");
    await once(child, "exit").catch(() => {});
  }
}

function ensureAlive(proc) {
  if (proc.exitCode !== null || proc.signalCode !== null) {
    throw new Error(
      `${path.basename(proc.spawnfile)} exited early with code ${proc.exitCode}; tail:\n${proc.tail()}`,
    );
  }
}

function createCertificate(tmpDir) {
  const certPath = path.join(tmpDir, "cert.pem");
  const keyPath = path.join(tmpDir, "key.pem");
  const result = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-subj",
      "/CN=localhost",
      "-keyout",
      keyPath,
      "-out",
      certPath,
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`openssl failed: ${result.stderr || result.stdout}`);
  }
  return { certPath, keyPath };
}

function writeJson(dir, name, value) {
  return writeText(dir, name, `${JSON.stringify(value, null, 2)}\n`);
}

function writeText(dir, name, value) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, value);
  return file;
}

function portBytes(port) {
  return Buffer.from([port >> 8, port & 0xff]);
}

function safeName(name) {
  return name.replace(/[^a-z0-9._-]+/gi, "_");
}

function caseLabel(testCase) {
  return [
    testCase.protocol,
    testCase.direction,
    testCase.singBoxUdpRelayMode ? `udp-${testCase.singBoxUdpRelayMode}` : null,
  ]
    .filter(Boolean)
    .join(" ");
}

async function commandOutput(command, args) {
  const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (data) => (stdout += data));
  child.stderr.on("data", (data) => (stderr += data));
  const [code] = await once(child, "exit");
  if (code !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${stderr}`);
  }
  return stdout;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function onceWithTimeout(emitter, event, ms, label) {
  return withTimeout(once(emitter, event), ms, label);
}

function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`timeout: ${label}`)), ms);
    }),
  ]);
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function closeUdp(socket) {
  return new Promise((resolve) => socket.close(resolve));
}
