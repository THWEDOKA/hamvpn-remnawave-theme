// Read-only control-machine protocol matrix. No active app reload/switch.
// Input envelope over stdin: profilePath, yamlModuleRoot, mihomoBinary,
// xrayBinary, sha256, targets:[{id,address,port,exit_ip}], optional concurrency.
// Existing subscription credentials are held in memory and sent to child stdin.
// Never print the source configuration, UUIDs, links, or child log bodies.
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const http = require('http');
const cp = require('child_process');

function port() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const value = server.address().port;
      server.close(() => resolve(value));
    });
  });
}
function listening(number) {
  return new Promise(resolve => {
    const s = net.connect(number, '127.0.0.1', () => { s.destroy(); resolve(true); });
    s.on('error', () => resolve(false));
  });
}
function delay(name) {
  return new Promise(resolve => {
    const r = http.get({socketPath: '\\\\.\\pipe\\HamVPN-PC\\mihomo',
      path: '/proxies/' + encodeURIComponent(name) + '/delay?timeout=9000&url=' +
        encodeURIComponent('https://www.gstatic.com/generate_204'), timeout: 12000}, response => {
      let body = '';
      response.on('data', b => { body += b; });
      response.on('end', () => {
        try { resolve(JSON.parse(body).delay || 0); } catch { resolve(0); }
      });
    });
    r.on('timeout', () => r.destroy());
    r.on('error', () => resolve(0));
  });
}
function configuration(proxy, core, fingerprint, number) {
  if (core === 'mihomo') return {
    'mixed-port': number, 'bind-address': '127.0.0.1', 'allow-lan': false,
    mode: 'rule', 'log-level': 'debug', ipv6: false, tun: {enable: false},
    dns: {enable: false}, profile: {'store-selected': false, 'store-fake-ip': false},
    proxies: [{...proxy, name: 'MATRIX', 'client-fingerprint': fingerprint}], rules: ['MATCH,MATRIX'],
  };
  return {log: {loglevel: 'none'}, inbounds: [{listen: '127.0.0.1', port: number,
    protocol: 'socks', settings: {auth: 'noauth', udp: false}}], outbounds: [{protocol: 'vless',
    settings: {vnext: [{address: proxy.server, port: proxy.port,
      users: [{id: proxy.uuid, encryption: 'none', flow: proxy.flow}]}]},
    streamSettings: {network: 'raw', security: 'reality', realitySettings: {
      serverName: proxy.servername, fingerprint,
      publicKey: proxy['reality-opts']['public-key'], shortId: proxy['reality-opts']['short-id'],
    }}}]};
}

async function test(request, item) {
  const {target, proxy, core, fp} = item;
  const number = await port();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ham-pc-matrix-'));
  const result = {id: `${target.id}-${core}-${fp}`};
  let proc, closed, logs = '';
  try {
    const binary = core === 'mihomo' ? request.mihomoBinary : request.xrayBinary;
    const args = core === 'mihomo' ? ['-d', directory, '-f', '-'] : ['run', '-c', 'stdin:'];
    proc = cp.spawn(binary, args, {windowsHide: true, stdio: ['pipe', 'pipe', 'pipe']});
    closed = new Promise(resolve => { proc.on('close', resolve); proc.on('error', resolve); });
    // Always drain both pipes during network requests: Windows pipe buffers are
    // small; collecting logs only after curl finishes can deadlock the core.
    const drain = chunk => { logs = (logs + chunk.toString()).slice(-65536); };
    proc.stdout.on('data', drain); proc.stderr.on('data', drain);
    proc.stdin.on('error', () => {});
    proc.stdin.end(JSON.stringify(configuration(proxy, core, fp, number)));
    let ready = false;
    for (let i = 0; i < 70; i++) {
      if (proc.exitCode !== null) break;
      if (await listening(number)) { ready = true; break; }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!ready) throw new Error('isolated_listener_unavailable');
    const curl = extra => new Promise(resolve => cp.execFile('curl.exe', [
      '-4', '--noproxy', '', '--socks5-hostname', `127.0.0.1:${number}`, '-fsS',
      '--connect-timeout', '5', '--max-time', '14', ...extra,
    ], {windowsHide: true, timeout: 18000}, (error, stdout) => resolve({
      code: error ? error.code || 1 : 0, output: stdout.trim(),
    })));
    const response = await curl(['-o', 'NUL', '-w', '%{http_code}', 'https://www.gstatic.com/generate_204']);
    const egress = await curl(['https://api.ipify.org']);
    result.http = response.output;
    result.curl_codes = [response.code, egress.code];
    result.exit_ip = egress.code === 0 ? egress.output : null;
    result.egress_check_url = 'https://api.ipify.org';
    result.passed = response.output === '204' && response.code === 0 && egress.code === 0 && egress.output === target.exit_ip;
  } catch {
    result.error = 'isolated_probe_failed';
  } finally {
    if (proc) { proc.kill(); await closed; }
    result.listener_removed = !await listening(number);
    result.reality_auth = [...logs.matchAll(/Authentication: (true|false)/g)].map(match => match[1]);
    // This generated directory contains only the isolated core's disposable
    // cache. Resolve both paths before removing it, never delete a broad path.
    const full = fs.realpathSync(directory), temp = fs.realpathSync(os.tmpdir());
    if (path.dirname(full) !== temp || !path.basename(full).startsWith('ham-pc-matrix-')) {
      throw new Error('unsafe_temporary_directory');
    }
    fs.rmSync(full, {recursive: true});
  }
  return result;
}

async function main() {
  let input = ''; for await (const chunk of process.stdin) input += chunk;
  const request = JSON.parse(input);
  if (!/^[a-f0-9]{64}$/.test(request.sha256) || !Array.isArray(request.targets) || request.targets.length > 6) {
    throw new Error('invalid_request');
  }
  const yaml = require(require.resolve('yaml', {paths: [request.yamlModuleRoot]}));
  const config = yaml.parse(fs.readFileSync(request.profilePath, 'utf8'));
  const selected = request.targets.map(target => {
    const matches = config.proxies.filter(p => p.server === target.address && p.port === target.port);
    if (matches.length !== 1 || matches[0].type !== 'vless' || !matches[0]['reality-opts']) throw new Error('proxy_selection_failed');
    return {target, proxy: matches[0]};
  });
  const tasks = selected.flatMap(item => ['mihomo', 'xray'].flatMap(core => ['firefox', 'chrome'].map(fp => ({...item, core, fp}))));
  let index = 0; const results = [];
  async function worker() { while (index < tasks.length) { const item = tasks[index++]; results.push(await test(request, item)); } }
  await Promise.all(Array.from({length: Math.min(3, request.concurrency || 3)}, worker));
  const delays = {};
  for (const item of selected) delays[item.target.id] = await delay(item.proxy.name);
  process.stdout.write(JSON.stringify({sha256: request.sha256, timestamp: Date.now() / 1000,
    tests: results, live_mihomo_delays: delays}) + '\n');
}
if (require.main === module) main().catch(() => { console.error('Matrix stopped; no app settings were changed'); process.exitCode = 1; });
module.exports = {configuration, test};
