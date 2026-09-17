// Offline tests. Fake measurements are test fixtures, never production proofs.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const cp = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const {EventEmitter} = require('events');
const {PassThrough, Writable} = require('stream');
const m = require('./frontend_measure.cjs');
const matrix = require('../pc-outage-20260918/local_matrix.cjs');
const sub = require('../pc-outage-20260918/subscription_readback.cjs');
const clone = value => JSON.parse(JSON.stringify(value));
const SECRET = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const key = 'A'.repeat(43);

function wire(client) {
  if (client === 'xray') return {tag: 'old-local-label', protocol: 'vless', settings: {vnext: [
    {address: 'example.invalid', port: 18447, users: [{id: SECRET, encryption: 'none', flow: 'xtls-rprx-vision', level: 0}]}]},
    streamSettings: {network: 'raw', security: 'reality', realitySettings: {
      publicKey: key, serverName: 'example.invalid', shortId: 'abcdef', fingerprint: 'firefox', spiderX: '/hello', show: false},
      sockopt: {tcpFastOpen: true}}, mux: {enabled: false, concurrency: 8}};
  return {name: 'Фактический основной хост', type: 'vless', server: 'example.invalid', port: 18447,
    uuid: SECRET, tls: true, network: 'tcp', udp: true, servername: 'example.invalid', flow: 'xtls-rprx-vision',
    'client-fingerprint': 'firefox', 'skip-cert-verify': false, 'packet-encoding': 'xudp', tfo: true,
    'reality-opts': {'public-key': key, 'short-id': 'abcdef'}};
}
function envelope(clients = ['xray', 'mihomo']) {
  const items = clients.map((client, i) => ({id: `case-${i}-${client}`, client, wire: wire(client),
    expected_egress: '45.151.180.85', wire_sha256: m.wireHash(client, wire(client)), legacy: false}));
  const request = {sha256: 'f'.repeat(64), items}; request.request_sha256 = m.digest(request);
  return {request, binaries: {xray: path.resolve('fake-xray.exe'), mihomo: path.resolve('fake-mihomo.exe'),
    curl: path.resolve('fake-curl.exe')}, concurrency: 2};
}
function rehash(value) {
  for (const item of value.request.items) item.wire_sha256 = m.wireHash(item.client, item.wire);
  value.request.request_sha256 = m.digest({sha256: value.request.sha256, items: value.request.items});
  return value;
}
function measured(item) {
  return {id: item.id, client: item.client, wire_sha256: item.wire_sha256, passed: true, authenticated: true,
    http_code: 204, exit_ip: item.expected_egress, returncodes: [0, 0], client_version: '1.2.3', binary_sha256: '0'.repeat(64),
    listener_removed: true, process_removed: true, temporary_directory_removed: true};
}
const fakeVersions = async () => ({xray: {version: '1.2.3', binary_sha256: '0'.repeat(64)},
  mihomo: {version: '1.2.3', binary_sha256: '0'.repeat(64)}, curl: {version: '8.0.0', binary_sha256: '0'.repeat(64)}});

test('canonical hash matches Python preflight including Unicode values', () => {
  const input = envelope().request;
  const python = process.platform === 'win32' ? 'py' : 'python3';
  const args = [...(process.platform === 'win32' ? ['-3.13'] : []), '-B', '-c',
    'import sys,json;sys.path.insert(0,sys.argv[1]);import preflight;print(preflight.digest(json.loads(sys.stdin.buffer.read().decode("utf-8"))))', __dirname];
  const result = cp.execFileSync(python, args, {input: JSON.stringify(input), encoding: 'utf8', windowsHide: true});
  assert.equal(m.digest(input), result.trim());
  assert.throws(() => m.canonical({x: 1.5}));
  assert.throws(() => m.canonical({x: Number.MAX_SAFE_INTEGER + 1}));
});

test('wire hash omits only local tag/name, not UUID/fingerprint/unknown field', () => {
  for (const client of ['xray', 'mihomo']) {
    const original = wire(client), next = clone(original);
    next[client === 'xray' ? 'tag' : 'name'] = 'unrelated-local-label';
    assert.equal(m.wireHash(client, original), m.wireHash(client, next));
    next['unknown-field'] = false;
    assert.notEqual(m.wireHash(client, original), m.wireHash(client, next));
  }
});

test('exact Xray outbound and Mihomo proxy preserved, no app/TUN/controller config', () => {
  const {request} = envelope();
  for (const item of request.items) {
    const original = clone(item.wire), cfg = m.configuration(item, 21234);
    if (item.client === 'xray') {
      assert.deepEqual(cfg.outbounds, [original]);
      assert.equal(cfg.inbounds[0].listen, '127.0.0.1');
      assert.equal(cfg.inbounds[0].port, 21234);
      assert.equal(cfg.routing, undefined); // Only outbound; never direct fallback.
      assert(sub.equal(sub.xrayWire(original), sub.xrayWire(cfg.outbounds[0])));
    } else {
      assert.deepEqual(cfg.proxies, [{...original, name: 'MATRIX'}]);
      assert.equal(cfg['bind-address'], '127.0.0.1');
      assert.equal(cfg['allow-lan'], false); assert.equal(cfg.tun.enable, false);
      assert.equal(cfg.dns.enable, false); assert.equal(cfg['external-controller'], undefined);
      assert.deepEqual(cfg.rules, ['MATCH,MATRIX']);
      assert.deepEqual(cfg.profile, matrix.configuration(original, 'mihomo', 'firefox', 21234).profile);
    }
    assert.deepEqual(item.wire, original);
  }
});

test('Xray password key alias preserved byte-for-byte, never recoded to publicKey', () => {
  const value = envelope(['xray']), item = value.request.items[0];
  const rs = item.wire.streamSettings.realitySettings; rs.password = rs.publicKey; delete rs.publicKey;
  rehash(value); m.validate(value);
  assert.deepEqual(m.configuration(item, 21543).outbounds[0], item.wire);
});

test('real TLS wires accepted only with certificate checking and retained ALPN', () => {
  const value = envelope();
  const [xray, mihomo] = value.request.items;
  xray.wire.streamSettings.security = 'tls'; delete xray.wire.streamSettings.realitySettings;
  xray.wire.streamSettings.tlsSettings = {serverName: 'example.invalid', alpn: ['h2', 'http/1.1'], allowInsecure: false, minVersion: '1.2'};
  delete mihomo.wire['reality-opts']; mihomo.wire.alpn = ['h2', 'http/1.1'];
  rehash(value); m.validate(value);
  assert.deepEqual(m.configuration(xray, 21543).outbounds[0], xray.wire);
  xray.wire.streamSettings.tlsSettings.allowInsecure = true; rehash(value);
  assert.throws(() => m.validate(value));
});

test('unknown fields, proxy detours, unsupported transport and insecure flags fail before any child', async () => {
  const changes = [
    v => { v.request.items[0].wire.unrecognized = 'do-not-drop'; },
    v => { v.request.items[0].wire.settings.vnext[0].users[0].extra = true; },
    v => { v.request.items[0].wire.streamSettings.sockopt.dialerProxy = 'DIRECT'; },
    v => { v.request.items[0].wire.streamSettings.realitySettings.unrecognized = 1; },
    v => { v.request.items[0].wire.streamSettings.network = 'xhttp'; },
    v => { v.request.items[0].wire.mux.enabled = true; },
    v => { v.request.items[1].wire['dialer-proxy'] = 'DIRECT'; },
    v => { v.request.items[1].wire['skip-cert-verify'] = true; },
    v => { v.request.items[1].wire['unknown-option'] = null; },
    v => { v.request.items[1].wire.network = 'ws'; },
  ];
  for (const change of changes) {
    const value = envelope(); change(value); rehash(value);
    let called = false;
    await assert.rejects(m.run(value, {versions: async () => { called = true; }, measure: async () => { called = true; }}));
    assert.equal(called, false);
  }
});

test('request and actual wire hashes, bounded cases and absolute binaries mandatory', () => {
  for (const mutate of [
    v => { v.request.request_sha256 = '0'.repeat(64); },
    v => { v.request.items[0].wire_sha256 = '0'.repeat(64); v.request.request_sha256 = m.digest({sha256: v.request.sha256, items: v.request.items}); },
    v => { v.concurrency = 4; }, v => { v.binaries.xray = 'xray'; },
    v => { v.request.items[1].id = v.request.items[0].id; rehash(v); },
    v => { v.request.items = []; rehash(v); },
  ]) { const value = envelope(); mutate(value); assert.throws(() => m.validate(value)); }
});

test('proof compatible shape, bounded concurrency and no secret output', async () => {
  let active = 0, peak = 0;
  const value = envelope(['xray', 'mihomo', 'xray', 'mihomo']);
  const output = await m.run(value, {versions: fakeVersions, measure: async item => {
    peak = Math.max(peak, ++active); await new Promise(resolve => setTimeout(resolve, 10)); active--;
    return measured(item);
  }});
  assert.equal(peak, 2); assert.equal(active, 0);
  assert.equal(output.request_sha256, value.request.request_sha256);
  assert.deepEqual(output.tests.map(v => v.id), value.request.items.map(v => v.id));
  assert(!JSON.stringify(output).includes(SECRET)); assert(!JSON.stringify(output).includes(key));
});

test('await started cases cleanup after one failure, no partial proof', async () => {
  let cleaned = false;
  await assert.rejects(m.run(envelope(), {versions: fakeVersions, measure: async item => {
    if (item.client === 'xray') throw Error(SECRET);
    await new Promise(resolve => setTimeout(resolve, 20)); cleaned = true; return measured(item);
  }}), /measurement_incomplete_no_proof/);
  assert.equal(cleaned, true);
});

test('false network outcomes retained truthfully, no fabricated PASS or skipped cases', async () => {
  const output = await m.run(envelope(), {versions: fakeVersions, measure: async item => ({...measured(item),
    passed: false, authenticated: false, http_code: 0, exit_ip: null, returncodes: [28, 28]})});
  assert(output.tests.every(t => t.passed === false && t.exit_ip === null));
  await assert.rejects(m.run(envelope(), {versions: fakeVersions, measure: async item => ({...measured(item), listener_removed: false})}));
});

test('mock child integration executes two curl responses, exact stdin wire, drains, cleans localhost listeners', async t => {
  const value = envelope(['xray']), item = value.request.items[0];
  const inputs = [], processes = [], curlCalls = [];
  t.mock.method(cp, 'spawn', (binary, args, options) => {
    assert.equal(options.windowsHide, true); assert.equal(options.shell, false);
    assert(!args.some(v => v.includes(SECRET)));
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    let input = '', server;
    child.stdin = new Writable({write(chunk, encoding, done) { input += chunk; done(); }, final(done) {
      const cfg = JSON.parse(input); inputs.push(cfg); done();
      if (args.includes('-test')) setImmediate(() => child.emit('close', 0, null));
      else {
        server = net.createServer(socket => socket.end());
        server.listen(cfg.inbounds[0].port, cfg.inbounds[0].listen);
        child.stdout.write(SECRET.repeat(10000)); child.stderr.write(SECRET.repeat(10000));
      }
    }});
    child.kill = () => { if (server) server.close(() => child.emit('close', 0, null)); else child.emit('close', 0, null); return true; };
    processes.push(child); return child;
  });
  t.mock.method(cp, 'execFile', (binary, args, options, done) => {
    curlCalls.push(args); assert.equal(args[0], '--disable'); assert.equal(options.shell, false);
    assert(args.includes('--socks5-hostname')); assert(!args.includes('-k')); assert(!args.includes('-L'));
    setImmediate(() => done(null, args.at(-1).includes('ipify') ? '45.151.180.85\n200' : '204'));
  });
  const result = await m.measure(item, value.binaries, await fakeVersions());
  assert.equal(result.passed, true); assert.equal(result.authenticated, true);
  assert.equal(result.client_version, '1.2.3'); assert.deepEqual(result.returncodes, [0, 0]);
  assert.equal(curlCalls.length, 2); assert.equal(processes.length, 2);
  for (const cfg of inputs) assert.deepEqual(cfg.outbounds, [item.wire]);
  assert(result.listener_removed && result.process_removed && result.temporary_directory_removed);
  assert(!JSON.stringify(result).includes(SECRET));
});

test('cleanup rejects broad temp/root paths without deleting anything', () => {
  assert.throws(() => m.cleanupDirectory(os.tmpdir()));
  assert(fs.existsSync(os.tmpdir()));
});

test('CLI refuses malformed secret input with fixed error and empty stdout', () => {
  const result = cp.spawnSync(process.execPath, [path.join(__dirname, 'frontend_measure.cjs')], {
    input: JSON.stringify({password: SECRET}), windowsHide: true, encoding: 'utf8'});
  assert.equal(result.status, 1); assert.equal(result.stdout, '');
  assert(!result.stderr.includes(SECRET)); assert(result.stderr.includes('no app configuration changed'));
});

test('actual installed cores accept exact wrapper over stdin (opt-in, configuration-only)', {
  skip: process.env.HAM_FRONT_CORECHECK !== '1',
}, () => {
  const value = envelope();
  const binaries = {xray: process.env.HAM_FRONT_XRAY, mihomo: process.env.HAM_FRONT_MIHOMO};
  for (const item of value.request.items) {
    assert(path.isAbsolute(binaries[item.client]));
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ham-front-measure-'));
    try {
      const args = item.client === 'xray' ? ['run', '-test', '-c', 'stdin:'] : ['-t', '-d', directory, '-f', '-'];
      const result = cp.spawnSync(binaries[item.client], args, {
        input: JSON.stringify(m.configuration(item, 21347)), encoding: 'utf8', windowsHide: true, timeout: 10000,
      });
      // Raw binary output is deliberately never interpolated in assertions.
      assert.equal(result.status, 0, item.client + ' actual configuration test failed');
    } finally { m.cleanupDirectory(directory); }
  }
});

test('Python coordinator consumes runner proof for public+subscription, Unicode hash and extra measured fields', () => {
  const python = process.platform === 'win32' ? 'py' : 'python3';
  // This is an OFFLINE integration test. Simulated curl outcomes are confined
  // to the fixture API, never sent to a panel or used as actual runtime proof.
  const source = `
import json,sys,subprocess
sys.path.insert(0,sys.argv[1])
import test_frontend_stage as t
case=t.FrontendTests();case.init('pl')
original=case.legacy_request
def legacy():
    value=original()
    for item in value['items']: item['wire']['streamSettings']['realitySettings']['publicKey']='A'*43
    return value
case.legacy_request=legacy
case.stage()
def proof(request):
    js="""const m=require(process.argv[1]);(async()=>{let text='';for await(const c of process.stdin)text+=c;
const result=await m.run(JSON.parse(text),{versions:async()=>({}),measure:async item=>({id:item.id,client:item.client,
wire_sha256:item.wire_sha256,passed:true,authenticated:true,http_code:204,exit_ip:item.expected_egress,
returncodes:[0,0],client_version:'1.2.3',namespace:'external-client',binary_sha256:'0'.repeat(64),
listener_removed:true,process_removed:true,temporary_directory_removed:true})});process.stdout.write(JSON.stringify(result))})()
"""
    binaries={name:sys.executable for name in ('xray','mihomo','curl')}
    run=subprocess.run([sys.argv[2],'-e',js,sys.argv[3]],input=json.dumps(dict(request=request,binaries=binaries)).encode(),capture_output=True,check=True)
    value=json.loads(run.stdout);value['timestamp']=case.exit.now
    return value
request=case.worker.export_public('pl');case.worker.accept('pl','public',proof(request));case.worker.publish('pl')
request=case.worker.export_subscription('pl',dict(headers={'x-hwid':'existing-fixture-device'}))
case.worker.accept('pl','subscription',proof(request))
assert case.worker.finish('pl')['actual_subscription_verified']
print('compatible')
`;
  const output = cp.execFileSync(python, [...(process.platform === 'win32' ? ['-3.13'] : []), '-B', '-c', source,
    __dirname, process.execPath, path.join(__dirname, 'frontend_measure.cjs')], {encoding: 'utf8', windowsHide: true, timeout: 15000});
  assert.equal(output.trim(), 'compatible');
});
