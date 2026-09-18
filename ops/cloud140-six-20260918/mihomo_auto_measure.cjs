// stdin-only isolated group measurement. No application controller/config writes.
// Only our ephemeral localhost controller is read. Exact proxy/group/rule fields
// are preserved; local listeners, DNS and persistence are an explicit sandbox.
const fs = require('fs'), os = require('os'), path = require('path');
const net = require('net'), crypto = require('crypto'), cp = require('child_process');
const helper = require('./frontend_measure.cjs');
const AUTO = '⚡ Автовыбор Серверов · ПК';
function check(ok) { if (!ok) throw Error('isolated_auto_measurement_failed'); }
const pause = ms => new Promise(r => setTimeout(r, ms));
function port() { return new Promise((resolve, reject) => {
  const s = net.createServer(); s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const n = s.address().port; s.close(() => resolve(n)); });
}); }
function listening(n) { return new Promise(resolve => {
  const s = net.connect(n, '127.0.0.1', () => { s.destroy(); resolve(true); });
  s.on('error', () => resolve(false));
}); }
function configuration(source, socks, controller, secret) {
  check(source && Array.isArray(source.proxies) && Array.isArray(source['proxy-groups']));
  const cfg = structuredClone(source);
  Object.assign(cfg, {'mixed-port': socks, 'socks-port': 0, port: 0, 'redir-port': 0, 'tproxy-port': 0,
    'bind-address': '127.0.0.1', 'allow-lan': false, 'external-controller': `127.0.0.1:${controller}`,
    secret, mode: 'rule', 'log-level': 'silent', tun: {enable: false}, dns: {enable: false},
    profile: {'store-selected': false, 'store-fake-ip': false}});
  for (const key of ['listeners', 'external-controller-pipe', 'external-controller-unix', 'external-controller-tls']) {
    check(!source[key]); delete cfg[key];
  }
  check(helper.digest(cfg.proxies) === helper.digest(source.proxies));
  check(helper.digest(cfg['proxy-groups']) === helper.digest(source['proxy-groups']));
  check(helper.digest(cfg.rules) === helper.digest(source.rules));
  return cfg;
}
function start(binary, args, cfg) {
  const child = cp.spawn(binary, args, {windowsHide: true, stdio: ['pipe', 'pipe', 'pipe']});
  const state = {child, closed: false, code: null};
  state.done = new Promise(resolve => {
    child.on('error', () => { state.error = true; });
    child.on('close', code => { state.closed = true; state.code = code; resolve(); });
  });
  child.stdout.on('data', () => {}); child.stderr.on('data', () => {});
  child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify(cfg));
  return state;
}
async function bounded(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('bounded')), ms); })]); }
  finally { clearTimeout(timer); }
}
async function stop(state) {
  if (!state) return;
  if (!state.closed) state.child.kill();
  await bounded(state.done, 5000); check(state.closed);
}
async function run(input) {
  check(input && ['candidate', 'public'].includes(input.phase));
  check(input.preview?.passed === true && input.preview.generated_sha256 === helper.digest(input.candidate));
  check(input.plan_sha256 === input.preview.plan_sha256);
  const versions = await helper.versions(input.binaries, new Set(['mihomo']));
  const socks = await port(); let controller = await port();
  while (controller === socks) controller = await port();
  const secret = crypto.randomBytes(32).toString('hex');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ham-front-measure-'));
  const cfg = configuration(input.candidate, socks, controller, secret);
  let test, running, output, failure;
  const groups = async () => {
    // NEVER uses the active HamVPN-PC named pipe/controller.
    const r = await fetch(`http://127.0.0.1:${controller}/proxies`, {
      headers: {Authorization: `Bearer ${secret}`}, signal: AbortSignal.timeout(5000), redirect: 'error'});
    check(r.status === 200); const data = (await r.json()).proxies;
    const mainName = input.candidate['proxy-groups'][0].name;
    check(data[AUTO]?.type === 'URLTest' && data[mainName]?.now === AUTO);
    check(JSON.stringify([...data[AUTO].all].sort()) === JSON.stringify([...input.preview.pool_names].sort()));
    check(JSON.stringify([...data[mainName].all].sort()) === JSON.stringify([...input.preview.main_names].sort()));
    return {[AUTO]: {type: data[AUTO].type, all: data[AUTO].all, now: data[AUTO].now},
      [mainName]: {type: data[mainName].type, all: data[mainName].all, now: data[mainName].now}};
  };
  try {
    test = start(input.binaries.mihomo, ['-t', '-d', directory, '-f', '-'], cfg);
    await bounded(test.done, 12000); check(test.code === 0 && !test.error);
    running = start(input.binaries.mihomo, ['-d', directory, '-f', '-'], cfg);
    let ready = false;
    for (let i = 0; i < 80; i++) {
      check(!running.closed && !running.error);
      if (await listening(socks) && await listening(controller)) { ready = true; break; }
      await pause(100);
    }
    check(ready);
    // Allow the group's bounded initial background health checks to settle.
    await groups(); await pause(16000);
    const attempts = [];
    for (let i = 0; i < 2; i++) {
      const before = await groups();
      const http = await helper.curl(input.binaries.curl, socks, false);
      const egress = await helper.curl(input.binaries.curl, socks, true);
      const after = await groups();
      const member = after[AUTO].now;
      attempts.push({test_id: crypto.randomUUID(), http: http.status, egress_http: egress.status,
        curl_exit_codes: [http.code, egress.code], egress_ip: egress.ip,
        selected_member: member, selected_wire_sha256: input.preview.pool_wire_sha256[member],
        selection_stable: before[AUTO].now === member});
    }
    check(!running.closed && !running.error);
    output = {phase: input.phase, plan_sha256: input.plan_sha256, generated_sha256: input.preview.generated_sha256,
      timestamp: Date.now()/1000, test_id: crypto.randomUUID(), client_version: versions.mihomo.version,
      binary_sha256: versions.mihomo.binary_sha256, config_test_exit_code: test.code,
      namespace: 'isolated-loopback', sandbox_sha256: helper.digest(cfg), groups: await groups(), attempts};
  } catch (error) { failure = error; }
  finally {
    for (const state of [running, test]) {
      try { await stop(state); } catch (error) { failure ||= error; }
    }
    const removed = !await listening(socks) && !await listening(controller);
    try { helper.cleanupDirectory(directory); } catch (error) { failure ||= error; }
    if (output) output.cleanup = {process: !!running?.closed && !!test?.closed,
      listener: removed, directory: !fs.existsSync(directory)};
    if (!removed) failure ||= Error('listener_cleanup');
  }
  if (failure) throw Error('isolated_auto_measurement_failed_no_proof');
  return output;
}
async function main() {
  check(!process.stdin.isTTY && process.argv.length === 2);
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; check(size <= 8*1024*1024); chunks.push(chunk); }
  const result = await run(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  process.stdout.write(JSON.stringify(result)+'\n');
}
if (require.main === module) main().catch(() => {
  process.stderr.write('Auto group measurement stopped; private input/output suppressed\n'); process.exitCode = 1;
});
module.exports = {configuration, run};
