// Actual isolated frontend measurements, CODE ONLY until the main operator runs.
// stdin SECRET envelope: {request:<frontend_stage export-baseline/public/subscription>,
// binaries:{xray:<absolute exe>,mihomo:<absolute exe>,curl:<absolute exe>},concurrency:2}.
// stdout contains only coordinator proof + measured versions, curl codes, hashes
// and cleanup evidence. No subscription URL, UUID, key, raw config or core logs.
// No config files, app/controller API, HWID enrollment, app reload or panel writes.
// This reuses local_matrix's isolation wrapper, NEVER its reconstructing Xray
// conversion/test helper: the exact selected outbound/proxy must reach the core.
// subscription_readback helpers are projection checks, not a wire reconstruction.
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const crypto = require('crypto');
const cp = require('child_process');
const matrix = require('../pc-outage-20260918/local_matrix.cjs');
const subscription = require('../pc-outage-20260918/subscription_readback.cjs');

const MAX_INPUT = 2 * 1024 * 1024;
const PREFIX = 'ham-front-measure-';
const CHECK_URL = 'https://www.gstatic.com/generate_204';
const EGRESS_URL = 'https://api.ipify.org';
const requireTrue = (ok, message = 'invalid_measurement_input') => { if (!ok) throw Error(message); };
const copy = value => JSON.parse(JSON.stringify(value));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, allowed) => requireTrue(object(value) && Object.keys(value).every(k => allowed.includes(k)), 'unsupported_wire_fields');

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    // Avoid silently hashing a JS-rounded JSON number differently from Python.
    requireTrue(Number.isSafeInteger(value) && !Object.is(value, -0), 'noncanonical_number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  requireTrue(object(value), 'noncanonical_json');
  // The current schema uses ASCII keys, as does Python's sort_keys output.
  requireTrue(Object.keys(value).every(k => /^[\x20-\x7e]+$/.test(k)), 'noncanonical_key');
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
const digest = value => crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex');
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function wireHash(client, wire) {
  requireTrue(['xray', 'mihomo'].includes(client));
  const label = client === 'xray' ? 'tag' : 'name';
  return digest(Object.fromEntries(Object.entries(wire).filter(([k]) => k !== label)));
}
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
const portNumber = value => Number.isInteger(value) && value > 0 && value < 65536;
const hostname = value => typeof value === 'string' && value.length <= 253 && /^(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.:-]*[A-Za-z0-9]$/.test(value);
function strings(value) { return Array.isArray(value) && value.length > 0 && value.every(v => typeof v === 'string' && v.length > 0); }

function validateWire(client, wire) {
  // Explicitly fail unknown fields rather than truncate them or let a core
  // silently ignore an unreviewed setting. Supported optional fields are kept.
  let endpoint;
  if (client === 'xray') {
    keys(wire, ['tag', 'protocol', 'settings', 'streamSettings', 'mux']);
    requireTrue(wire.protocol === 'vless', 'unsupported_wire_protocol');
    keys(wire.settings, ['vnext']);
    requireTrue(Array.isArray(wire.settings.vnext) && wire.settings.vnext.length === 1);
    const hop = wire.settings.vnext[0]; keys(hop, ['address', 'port', 'users']);
    requireTrue(Array.isArray(hop.users) && hop.users.length === 1);
    const user = hop.users[0]; keys(user, ['id', 'encryption', 'flow', 'level']);
    requireTrue(uuid(user.id) && user.encryption === 'none' && user.flow === 'xtls-rprx-vision');
    const stream = wire.streamSettings;
    keys(stream, ['network', 'security', 'realitySettings', 'tlsSettings', 'tcpSettings', 'rawSettings', 'sockopt']);
    requireTrue(['raw', 'tcp', undefined].includes(stream.network) && ['reality', 'tls'].includes(stream.security));
    requireTrue(!(stream.tcpSettings && stream.rawSettings));
    for (const name of ['tcpSettings', 'rawSettings']) if (stream[name] !== undefined) {
      keys(stream[name], ['header', 'acceptProxyProtocol']);
      requireTrue(!stream[name].acceptProxyProtocol);
      if (stream[name].header !== undefined) {
        keys(stream[name].header, ['type']); requireTrue(stream[name].header.type === 'none');
      }
    }
    if (stream.sockopt !== undefined) keys(stream.sockopt, ['tcpFastOpen', 'tcpNoDelay', 'tcpKeepAliveIdle', 'tcpKeepAliveInterval']);
    if (wire.mux !== undefined) { keys(wire.mux, ['enabled', 'concurrency', 'xudpConcurrency', 'xudpProxyUDP443']); requireTrue(wire.mux.enabled === false); }
    if (stream.security === 'reality') {
      requireTrue(stream.tlsSettings === undefined);
      const rs = stream.realitySettings;
      keys(rs, ['serverName', 'fingerprint', 'publicKey', 'password', 'shortId', 'spiderX', 'show']);
      requireTrue(hostname(rs.serverName) && typeof rs.fingerprint === 'string' && !!rs.fingerprint &&
        (!!rs.publicKey !== !!rs.password) && /^[A-Za-z0-9_-]{43}$/.test(rs.publicKey || rs.password) &&
        typeof rs.shortId === 'string' && /^(?:[a-f0-9]{2}){0,8}$/i.test(rs.shortId));
      if (rs.show !== undefined) requireTrue(typeof rs.show === 'boolean');
      // The old helper does not know Xray's newer password alias. Validate its
      // read-only projection without changing the wire sent to the binary.
      const projection = subscription.xrayWire(wire);
      requireTrue(projection && projection.address === hop.address && projection.uuid === user.id);
    } else {
      requireTrue(stream.realitySettings === undefined);
      const tls = stream.tlsSettings;
      keys(tls, ['serverName', 'fingerprint', 'alpn', 'allowInsecure', 'minVersion', 'maxVersion']);
      requireTrue(hostname(tls.serverName) && (!Object.hasOwn(tls, 'allowInsecure') || tls.allowInsecure === false));
      if (tls.alpn !== undefined) requireTrue(strings(tls.alpn));
      for (const k of ['minVersion', 'maxVersion']) if (tls[k] !== undefined) requireTrue(['1.2', '1.3'].includes(tls[k]));
    }
    endpoint = {address: hop.address, port: hop.port};
  } else {
    requireTrue(client === 'mihomo');
    keys(wire, ['name', 'type', 'server', 'port', 'uuid', 'network', 'tls', 'udp', 'flow', 'servername',
      'client-fingerprint', 'reality-opts', 'skip-cert-verify', 'alpn', 'packet-encoding', 'tfo', 'mptcp', 'ip-version']);
    requireTrue(wire.type === 'vless' && uuid(wire.uuid) && wire.tls === true && wire.flow === 'xtls-rprx-vision' &&
      ['tcp', undefined].includes(wire.network) && (!Object.hasOwn(wire, 'skip-cert-verify') || wire['skip-cert-verify'] === false) &&
      hostname(wire.servername) && typeof wire['client-fingerprint'] === 'string' && !!wire['client-fingerprint']);
    if (wire['reality-opts'] !== undefined) {
      keys(wire['reality-opts'], ['public-key', 'short-id']);
      requireTrue(/^[A-Za-z0-9_-]{43}$/.test(wire['reality-opts']['public-key']) &&
        typeof wire['reality-opts']['short-id'] === 'string' && /^(?:[a-f0-9]{2}){0,8}$/i.test(wire['reality-opts']['short-id']));
    }
    if (wire.alpn !== undefined) requireTrue(strings(wire.alpn));
    const projection = subscription.wire(wire);
    requireTrue(projection.address === wire.server && projection.uuid === wire.uuid);
    endpoint = {address: wire.server, port: wire.port};
  }
  requireTrue(hostname(endpoint.address) && portNumber(endpoint.port), 'invalid_wire_endpoint');
  canonical(wire); // Unknown numeric representations cannot silently change hash.
  return endpoint;
}

function validate(envelope) {
  keys(envelope, ['request', 'binaries', 'concurrency']);
  const {request, binaries} = envelope;
  keys(request, ['sha256', 'request_sha256', 'items']);
  requireTrue(hash(request.sha256) && hash(request.request_sha256) && Array.isArray(request.items) &&
    request.items.length > 0 && request.items.length <= 32);
  requireTrue(digest({sha256: request.sha256, items: request.items}) === request.request_sha256, 'request_hash_mismatch');
  const ids = new Set();
  for (const item of request.items) {
    keys(item, ['id', 'client', 'wire', 'expected_egress', 'wire_sha256', 'legacy']);
    requireTrue(typeof item.id === 'string' && /^[A-Za-z0-9._:-]{1,120}$/.test(item.id) && !ids.has(item.id)); ids.add(item.id);
    requireTrue(typeof item.legacy === 'boolean' && net.isIP(item.expected_egress) !== 0 && hash(item.wire_sha256));
    validateWire(item.client, item.wire);
    requireTrue(item.wire_sha256 === wireHash(item.client, item.wire), 'wire_hash_mismatch');
  }
  keys(binaries, ['xray', 'mihomo', 'curl']);
  const clients = new Set(request.items.map(i => i.client));
  for (const name of [...clients, 'curl']) requireTrue(typeof binaries[name] === 'string' && path.isAbsolute(binaries[name]), 'explicit_absolute_binary_required');
  const concurrency = envelope.concurrency ?? 2;
  requireTrue(Number.isInteger(concurrency) && concurrency >= 1 && concurrency <= 3);
  return {request: copy(request), binaries: {...binaries}, concurrency};
}

function configuration(item, number) {
  validateWire(item.client, item.wire);
  requireTrue(portNumber(number));
  if (item.client === 'mihomo') {
    const cfg = matrix.configuration(item.wire, 'mihomo', item.wire['client-fingerprint'], number);
    cfg['log-level'] = 'silent';
    cfg.proxies = [{...copy(item.wire), name: 'MATRIX'}];
    requireTrue(subscription.equal(subscription.wire(item.wire), subscription.wire(cfg.proxies[0])));
    requireTrue(wireHash('mihomo', cfg.proxies[0]) === item.wire_sha256, 'executed_wire_changed');
    return cfg;
  }
  const outbound = copy(item.wire); // Not reconstructed from a Mihomo proxy.
  requireTrue(wireHash('xray', outbound) === item.wire_sha256, 'executed_wire_changed');
  return {log: {loglevel: 'none'}, inbounds: [{listen: '127.0.0.1', port: number,
    protocol: 'socks', settings: {auth: 'noauth', udp: false}}], outbounds: [outbound]};
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function bounded(done, ms) {
  let timeout;
  try { await Promise.race([done, new Promise(resolve => { timeout = setTimeout(resolve, ms); })]); }
  finally { clearTimeout(timeout); }
}
function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer(); server.on('error', reject);
    server.listen(0, '127.0.0.1', () => { const p = server.address().port; server.close(error => error ? reject(error) : resolve(p)); });
  });
}
function listening(number) {
  return new Promise(resolve => {
    const socket = net.connect({port: number, host: '127.0.0.1', timeout: 500});
    const done = value => { socket.destroy(); resolve(value); };
    socket.on('connect', () => done(true)); socket.on('error', () => done(false)); socket.on('timeout', () => done(false));
  });
}

function start(binary, args, input) {
  const child = cp.spawn(binary, args, {windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe']});
  const state = {child, closed: false, spawnError: false, code: null, signal: null};
  state.done = new Promise(resolve => {
    child.once('error', () => { state.spawnError = true; });
    child.once('close', (code, signal) => { Object.assign(state, {closed: true, code, signal}); resolve(); });
  });
  // Continuous drain avoids Windows pipe deadlock. Raw core log bytes are never
  // kept or echoed: they may contain UUIDs, server names or private config paths.
  child.stdout.resume(); child.stderr.resume(); child.stdin.on('error', () => {});
  child.stdin.end(JSON.stringify(input));
  return state;
}
async function stop(state) {
  if (!state || state.closed) return;
  state.child.kill();
  await bounded(state.done, 2000);
  if (!state.closed) { state.child.kill('SIGKILL'); await bounded(state.done, 2000); }
  requireTrue(state.closed, 'isolated_process_cleanup_failed');
}
function runFile(binary, args, timeout) {
  return new Promise(resolve => cp.execFile(binary, args, {windowsHide: true, shell: false, timeout, maxBuffer: 65536},
    (error, stdout) => resolve({code: error ? (Number.isInteger(error.code) ? error.code : null) : 0,
      output: String(stdout || ''), killed: !!error?.killed, signal: error?.signal || null})));
}
async function versions(binaries, clients) {
  const result = {};
  for (const client of [...clients, 'curl']) {
    const file = binaries[client]; requireTrue(fs.statSync(file).isFile(), 'binary_not_regular_file');
    const sha256 = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    const raw = await runFile(file, client === 'xray' ? ['version'] : client === 'mihomo' ? ['-v'] : ['--version'], 5000);
    requireTrue(raw.code === 0 && !raw.killed, 'client_version_unavailable');
    const expression = client === 'xray' ? /^Xray\s+(v?\d[^\s]*)/im : client === 'mihomo' ? /^Mihomo(?:\s+Meta)?\s+(v?\d[^\s]*)/im : /^curl\s+(\d[^\s]*)/im;
    const version = raw.output.match(expression)?.[1];
    requireTrue(version && /^v?\d[A-Za-z0-9.+_-]{0,63}$/.test(version), 'client_version_unrecognized');
    result[client] = {version, binary_sha256: sha256};
  }
  return result;
}

async function curl(binary, number, egress) {
  const args = ['--disable', '-4', '--noproxy', '', '--socks5-hostname', `127.0.0.1:${number}`,
    '-fsS', '--connect-timeout', '5', '--max-time', '14', '--max-filesize', '4096', '--proto', '=https'];
  if (egress) args.push('-w', '\n%{http_code}', EGRESS_URL);
  else args.push('-o', os.devNull, '-w', '%{http_code}', CHECK_URL);
  const raw = await runFile(binary, args, 18000);
  requireTrue(Number.isInteger(raw.code) && !raw.killed && !raw.signal, 'curl_process_did_not_complete');
  if (!egress) return {code: raw.code, status: /^\d{3}$/.test(raw.output.trim()) ? Number(raw.output.trim()) : 0};
  const parts = raw.output.trim().split(/\r?\n/);
  const status = /^\d{3}$/.test(parts.at(-1) || '') ? Number(parts.pop()) : 0;
  const ip = parts.join('\n').trim();
  return {code: raw.code, status, ip: raw.code === 0 && status === 200 && net.isIP(ip) ? ip : null};
}

function cleanupDirectory(directory) {
  const full = fs.realpathSync(directory), parent = fs.realpathSync(os.tmpdir());
  requireTrue(!fs.lstatSync(directory).isSymbolicLink() && path.resolve(directory) === full &&
    path.dirname(full) === parent && path.basename(full).startsWith(PREFIX), 'unsafe_temporary_directory');
  fs.rmSync(full, {recursive: true}); // Only this verified disposable child.
}

async function measure(item, binaries, measuredVersions) {
  const number = await availablePort();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), PREFIX));
  if (process.platform !== 'win32') fs.chmodSync(directory, 0o700);
  const started = Date.now() / 1000;
  let processState, configurationCheck, result, failure;
  try {
    requireTrue(!await listening(number), 'isolated_port_already_used');
    const cfg = configuration(item, number), binary = binaries[item.client];
    const args = item.client === 'mihomo' ? ['-d', directory, '-f', '-'] : ['run', '-c', 'stdin:'];
    const testArgs = item.client === 'mihomo' ? ['-t', ...args] : ['run', '-test', '-c', 'stdin:'];
    configurationCheck = start(binary, testArgs, cfg);
    await bounded(configurationCheck.done, 8000);
    requireTrue(configurationCheck.closed && configurationCheck.code === 0 && !configurationCheck.spawnError, 'actual_core_config_test_failed');
    processState = start(binary, args, cfg);
    let ready = false;
    for (let i = 0; i < 80; i++) {
      if (processState.closed || processState.spawnError) break;
      if (await listening(number)) { ready = true; break; }
      await sleep(100);
    }
    requireTrue(ready && !processState.closed && !processState.spawnError, 'isolated_listener_unavailable');
    const response = await curl(binaries.curl, number, false);
    const egress = await curl(binaries.curl, number, true);
    requireTrue(!processState.closed && !processState.spawnError, 'isolated_core_exited');
    const authenticated = (response.code === 0 && response.status === 204) || (egress.code === 0 && egress.ip !== null);
    result = {id: item.id, client: item.client, client_version: measuredVersions[item.client].version,
      binary_sha256: measuredVersions[item.client].binary_sha256, namespace: 'external-client',
      wire_sha256: item.wire_sha256, passed: authenticated && response.code === 0 && response.status === 204 &&
        egress.code === 0 && egress.ip === item.expected_egress,
      authenticated, http_code: response.status, exit_ip: egress.ip, returncodes: [response.code, egress.code],
      egress_http_code: egress.status, configuration_test_returncode: configurationCheck.code,
      started_at: started, timestamp: Date.now() / 1000};
  } catch (error) { failure = error; }
  finally {
    // Attempt ALL cleanup even if a child/port cleanup fails. No partial proof
    // is returned and no error includes child output or the secret envelope.
    for (const state of [processState, configurationCheck]) {
      try { await stop(state); } catch (error) { failure ||= error; }
    }
    let removed = false;
    try { removed = !await listening(number); } catch (error) { failure ||= error; }
    if (!removed) failure ||= Error('isolated_listener_cleanup_failed');
    try { cleanupDirectory(directory); } catch (error) { failure ||= error; }
    if (result) Object.assign(result, {listener_removed: removed, process_removed: !!processState?.closed, temporary_directory_removed: !fs.existsSync(directory)});
  }
  if (failure) throw Error('isolated_measurement_or_cleanup_failed');
  return result;
}

async function run(envelope, deps = {}) {
  const {request, binaries, concurrency} = validate(envelope);
  const clients = new Set(request.items.map(i => i.client));
  const measuredVersions = await (deps.versions || versions)(binaries, clients);
  const results = Array(request.items.length), errors = [];
  let next = 0;
  async function worker() {
    while (!errors.length && next < request.items.length) {
      const index = next++;
      try { results[index] = await (deps.measure || measure)(request.items[index], binaries, measuredVersions); }
      catch { errors.push(true); }
    }
  }
  // Wait for all started children to clean up even if another case fails.
  await Promise.all(Array.from({length: Math.min(concurrency, request.items.length)}, worker));
  requireTrue(!errors.length && results.every(Boolean), 'measurement_incomplete_no_proof');
  for (let i = 0; i < results.length; i++) {
    const result = results[i], item = request.items[i];
    requireTrue(result.id === item.id && result.client === item.client && result.wire_sha256 === item.wire_sha256 &&
      result.listener_removed === true && result.process_removed === true && result.temporary_directory_removed === true, 'measurement_identity_or_cleanup_failed');
  }
  return {sha256: request.sha256, request_sha256: request.request_sha256, timestamp: Date.now() / 1000,
    versions: measuredVersions, tests: results};
}

async function main() {
  requireTrue(!process.stdin.isTTY && process.argv.length === 2, 'secret_stdin_envelope_only');
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) { length += chunk.length; requireTrue(length <= MAX_INPUT, 'bounded_input_exceeded'); chunks.push(chunk); }
  // Decode once: Unicode names can straddle arbitrary stdin byte boundaries.
  const result = await run(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify(result) + '\n');
}
if (require.main === module) main().catch(() => {
  console.error('Frontend measurement failed; no proof accepted, no app configuration changed'); process.exitCode = 1;
});
module.exports = {canonical, digest, wireHash, validateWire, validate, configuration, run, measure, versions, curl, cleanupDirectory};
