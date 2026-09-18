// All-label diagnostic only: exact fresh Mihomo proxy, no app reload or panel
// writes. Pending migration routes are excluded by endpoint AND exact label.
// Unknown/insecure schemas are reported, never truncated or converted.
// Secret input stays stdin/RAM; only public label/code/egress/hash is emitted.
const fs = require('fs'), path = require('path'), os = require('os'), net = require('net');
const cp = require('child_process');
const m = require('./frontend_measure.cjs');
const matrix = require('../pc-outage-20260918/local_matrix.cjs');
const pendingIPs = new Set(['147.45.71.38', '31.77.59.141', '45.151.180.85', '51.194.240.225']);
const pendingDomains = new Set(['in-at38.torcalc.ru', 'in-pl141.torcalc.ru', 'in-cz85.torcalc.ru', 'in-gb225.torcalc.ru']);
const pendingPorts = new Set([18445, 18446, 18447, 18448]);
const check = (value, reason) => { if (!value) throw Error(reason || 'invalid_input'); };
const copy = value => JSON.parse(JSON.stringify(value));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const plainKeys = (value, allowed) => check(object(value) && Object.keys(value).every(k => allowed.includes(k)), 'unsupported_schema');

function pending(proxy, labels) {
  return labels.includes(proxy.name) || pendingIPs.has(proxy.server) || pendingDomains.has(proxy.server) ||
    pendingDomains.has(proxy.servername || proxy.sni) ||
    proxy.server === '176.108.245.140' && pendingPorts.has(proxy.port);
}
function inspect(proxy) {
  check(object(proxy) && typeof proxy.name === 'string' && proxy.name.length > 0 && proxy.name.length < 256, 'invalid_label');
  check(typeof proxy.server === 'string' && Number.isInteger(proxy.port) && proxy.port > 0 && proxy.port < 65536, 'invalid_endpoint');
  const shared = ['name', 'type', 'server', 'port', 'client-fingerprint', 'udp', 'alpn', 'skip-cert-verify', 'tfo', 'mptcp', 'ip-version'];
  check(!proxy['skip-cert-verify'], 'insecure_certificate_flag');
  if (proxy.type === 'hysteria2') {
    plainKeys(proxy, [...shared, 'password', 'sni', 'up', 'down', 'obfs', 'obfs-password']);
    check(typeof proxy.password === 'string' && !!proxy.password && typeof proxy.sni === 'string' && !!proxy.sni, 'invalid_hysteria_identity');
    if (proxy.obfs !== undefined) check(proxy.obfs === 'salamander' && typeof proxy['obfs-password'] === 'string', 'unsupported_obfuscation');
  } else {
    check(proxy.type === 'vless', 'unsupported_protocol');
    plainKeys(proxy, [...shared, 'uuid', 'network', 'tls', 'flow', 'servername', 'reality-opts', 'packet-encoding', 'ws-opts', 'xhttp-opts']);
    check(typeof proxy.uuid === 'string' && proxy.tls === true && typeof proxy.servername === 'string', 'invalid_vless_identity');
    check(['tcp', 'ws', 'xhttp', undefined].includes(proxy.network), 'unsupported_transport');
    if (proxy['reality-opts']) plainKeys(proxy['reality-opts'], ['public-key', 'short-id']);
    if (proxy['ws-opts']) {
      plainKeys(proxy['ws-opts'], ['path', 'headers', 'max-early-data', 'early-data-header-name']);
      if (proxy['ws-opts'].headers) plainKeys(proxy['ws-opts'].headers, ['Host']);
    }
    if (proxy['xhttp-opts']) {
      plainKeys(proxy['xhttp-opts'], ['path', 'host', 'mode', 'headers', 'no-grpc-header', 'x-padding-bytes',
        'sc-max-each-post-bytes', 'sc-min-posts-interval-ms', 'sc-stream-up-server-secs', 'reuse-settings']);
      // Headers/reuse-settings are retained exactly as exported. They cannot
      // configure an external proxy/provider/controller; the installed core
      // must validate their actual shape, no field rebuilding is performed.
      if (proxy['xhttp-opts'].headers) check(object(proxy['xhttp-opts'].headers), 'unsupported_schema');
      if (proxy['xhttp-opts']['reuse-settings']) check(object(proxy['xhttp-opts']['reuse-settings']), 'unsupported_schema');
    }
  }
  return {type: proxy.type, network: proxy.type === 'hysteria2' ? 'udp' : proxy.network || 'tcp'};
}
function configuration(proxy, port) {
  inspect(proxy);
  const cfg = matrix.configuration(proxy, 'mihomo', proxy['client-fingerprint'], port);
  cfg['log-level'] = 'silent'; cfg.proxies = [{...copy(proxy), name: 'MATRIX'}];
  check(m.wireHash('mihomo', cfg.proxies[0]) === m.wireHash('mihomo', proxy), 'executed_wire_changed');
  return cfg;
}
function port() {
  return new Promise((resolve, reject) => {
    const server = net.createServer(); server.on('error', reject);
    server.listen(0, '127.0.0.1', () => { const n = server.address().port; server.close(() => resolve(n)); });
  });
}
function listening(number) {
  return new Promise(resolve => {
    const s = net.connect({host: '127.0.0.1', port: number, timeout: 500});
    const done = value => { s.destroy(); resolve(value); };
    s.on('connect', () => done(true)); s.on('error', () => done(false)); s.on('timeout', () => done(false));
  });
}
async function bounded(promise, delay) {
  let timer; try { await Promise.race([promise, new Promise(resolve => { timer = setTimeout(resolve, delay); })]); }
  finally { clearTimeout(timer); }
}
function child(binary, args, cfg) {
  const proc = cp.spawn(binary, args, {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false});
  const state = {proc, closed: false, code: null, error: false};
  state.done = new Promise(resolve => {
    proc.on('error', () => { state.error = true; });
    proc.on('close', code => { state.code = code; state.closed = true; resolve(); });
  });
  proc.stdout.resume(); proc.stderr.resume(); proc.stdin.on('error', () => {});
  proc.stdin.end(JSON.stringify(cfg)); return state;
}
async function stop(state) {
  if (!state || state.closed) return;
  state.proc.kill(); await bounded(state.done, 2000);
  if (!state.closed) { state.proc.kill('SIGKILL'); await bounded(state.done, 2000); }
  check(state.closed, 'cleanup_failed');
}
async function probe(proxy, binaries, versions) {
  const output = {label: proxy.name, ...inspect(proxy), wire_sha256: m.wireHash('mihomo', proxy),
    client_version: versions.mihomo.version, started_at: Date.now() / 1000,
    config_code: null, http_code: null, egress_http_code: null, returncodes: null, egress_ip: null,
    expected_egress_checked: false, outcome: 'not_tested'};
  const number = await port(), directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ham-front-measure-'));
  let configProc, liveProc, error;
  try {
    const cfg = configuration(proxy, number);
    check(!await listening(number), 'port_collision');
    configProc = child(binaries.mihomo, ['-t', '-d', directory, '-f', '-'], cfg);
    await bounded(configProc.done, 10000);
    output.config_code = configProc.code;
    if (!configProc.closed || configProc.error || configProc.code !== 0) output.outcome = 'configuration_rejected';
    else {
      liveProc = child(binaries.mihomo, ['-d', directory, '-f', '-'], cfg);
      let ready = false;
      for (let i = 0; i < 80; i++) {
        if (liveProc.closed || liveProc.error) break;
        if (await listening(number)) { ready = true; break; }
        await sleep(100);
      }
      check(ready && !liveProc.closed, 'listener_unavailable');
      const https = await m.curl(binaries.curl, number, false), egress = await m.curl(binaries.curl, number, true);
      check(!liveProc.closed, 'client_exited');
      Object.assign(output, {http_code: https.status, egress_http_code: egress.status,
        returncodes: [https.code, egress.code], egress_ip: egress.ip});
      output.outcome = https.code === 0 && https.status === 204 && egress.code === 0 && egress.ip !== null ? 'https_and_egress_observed' : 'network_probe_failed';
      // This one egress has an independent prior measurement. Do not assume
      // other management/ingress addresses are the exit's NAT egress address.
      if (proxy.server === '176.108.245.140' && proxy.port === 18444) {
        output.expected_egress_checked = true;
        output.egress_matches_reference = egress.ip === '196.251.107.245';
        if (output.outcome === 'https_and_egress_observed' && !output.egress_matches_reference) output.outcome = 'egress_mismatch';
      }
    }
  } catch { error = true; output.outcome = 'probe_runtime_error'; }
  finally {
    for (const state of [liveProc, configProc]) try { await stop(state); } catch { error = true; }
    output.listener_removed = !await listening(number);
    output.process_removed = (!liveProc || liveProc.closed) && (!configProc || configProc.closed);
    try { m.cleanupDirectory(directory); } catch { error = true; }
    output.temporary_directory_removed = !fs.existsSync(directory);
    if (!output.listener_removed || !output.process_removed || !output.temporary_directory_removed) {
      output.outcome = 'cleanup_failed'; throw Error('cleanup_failed');
    }
  }
  output.timestamp = Date.now() / 1000;
  return output;
}

async function run(input, emit, deps = {}) {
  check(['run', 'schema'].includes(input.action) && Array.isArray(input.proxies) && input.proxies.length > 0 &&
    input.proxies.length <= 80 && Array.isArray(input.pending_labels), 'invalid_request');
  check(new Set(input.proxies.map(p => p.name)).size === input.proxies.length, 'duplicate_labels');
  const safe = [];
  for (const proxy of input.proxies) {
    if (pending(proxy, input.pending_labels)) { safe.push({label: proxy.name, outcome: 'excluded_pending_migration'}); continue; }
    try { inspect(proxy); }
    catch { safe.push({label: proxy.name, type: proxy.type, outcome: 'unsupported_or_insecure_schema'}); }
  }
  emit({event: 'inventory', fresh_subscription: true, available_labels: input.proxies.length, fetched_at: input.fetched_at,
    device_preexisting: input.device_preexisting, excludes: safe, timestamp: Date.now() / 1000});
  if (input.action === 'schema') {
    emit({event: 'schemas', schemas: input.proxies.map(p => ({label: p.name, type: p.type, fields: Object.keys(p).sort()}))}); return;
  }
  const versions = await (deps.versions || m.versions)(input.binaries, new Set(['mihomo']));
  emit({event: 'versions', versions, no_app_reload: true});
  const ignored = new Set(safe.map(v => v.label));
  const tasks = input.proxies.filter(p => !ignored.has(p.name));
  let index = 0; const results = [], failures = [];
  async function worker() {
    while (index < tasks.length && !failures.length) {
      const proxy = tasks[index++];
      try { const result = await (deps.probe || probe)(proxy, input.binaries, versions); results.push(result); emit({event: 'result', ...result}); }
      catch { failures.push(true); emit({event: 'fatal', label: proxy.name, outcome: 'cleanup_unconfirmed_stop'}); }
    }
  }
  await Promise.all(Array.from({length: Math.min(2, tasks.length)}, worker));
  check(!failures.length, 'audit_incomplete');
  emit({event: 'summary', tested: results.length, excluded_or_unsupported: safe.length,
    observed_https_and_egress: results.filter(v => v.outcome === 'https_and_egress_observed').length,
    failures: results.filter(v => v.outcome !== 'https_and_egress_observed').length,
    scope: 'current local Windows network only; not all Russian operators', timestamp: Date.now() / 1000});
}

async function main() {
  check(process.argv.length === 2 && !process.stdin.isTTY, 'secret_stdin_only');
  let size = 0; const chunks = [];
  for await (const chunk of process.stdin) { size += chunk.length; check(size <= 4 * 1024 * 1024, 'request_too_large'); chunks.push(chunk); }
  await run(JSON.parse(Buffer.concat(chunks).toString('utf8')), value => process.stdout.write(JSON.stringify(value) + '\n'));
}
if (require.main === module) main().catch(() => { console.error('PC audit failed safely; private configuration not printed'); process.exitCode = 1; });
module.exports = {inspect, pending, configuration, probe, run};
