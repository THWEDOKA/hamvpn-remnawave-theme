const {test} = require('node:test');
const assert = require('node:assert/strict');
const a = require('./pc_audit.cjs');
const m = require('./frontend_measure.cjs');
const clone = v => JSON.parse(JSON.stringify(v));
function fixture(type = 'vless') {
  const base = {name: 'Сервер', type, server: 'example.invalid', port: 443, udp: true, 'client-fingerprint': 'chrome'};
  return type === 'hysteria2' ? {...base, password: 'SECRET-FIXTURE-ONLY', sni: 'example.invalid', alpn: ['h3']} : {
    ...base, uuid: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', tls: true, servername: 'example.invalid',
    flow: 'xtls-rprx-vision', network: 'tcp', 'packet-encoding': 'xudp',
    'reality-opts': {'public-key': 'A'.repeat(43), 'short-id': 'af'} };
}
test('exact VLESS/HY2 wire retained; isolated loopback rules, TUN and DNS disabled', () => {
  for (const type of ['vless', 'hysteria2']) {
    const p = fixture(type), cfg = a.configuration(p, 26443);
    assert.deepEqual(cfg.proxies, [{...p, name: 'MATRIX'}]);
    assert.equal(m.wireHash('mihomo', p), m.wireHash('mihomo', cfg.proxies[0]));
    assert.equal(cfg['bind-address'], '127.0.0.1'); assert.equal(cfg['allow-lan'], false);
    assert.equal(cfg.tun.enable, false); assert.equal(cfg.dns.enable, false); assert.deepEqual(cfg.rules, ['MATCH,MATRIX']);
    assert.equal(cfg['external-controller'], undefined);
  }
});
test('WS and XHTTP options and headers remain unchanged for installed-core test', () => {
  for (const network of ['ws', 'xhttp']) {
    const p = fixture(); p.network = network; delete p.flow; delete p['reality-opts'];
    p[network + '-opts'] = network === 'ws' ? {path: '/test', headers: {Host: 'example.invalid'}} :
      {path: '/test', host: 'example.invalid', mode: 'auto', 'reuse-settings': {'h-max-request-times': '100-200'}};
    assert.deepEqual(a.configuration(p, 26443).proxies, [{...p, name: 'MATRIX'}]);
  }
});
test('unknown fields, insecure flags and proxy detours fail instead of dropping', () => {
  for (const mutation of [p => p.unknown = true, p => p['skip-cert-verify'] = true, p => p['dialer-proxy'] = 'DIRECT',
    p => p.network = 'grpc', p => p['reality-opts'].unknown = true]) {
    const p = fixture(); mutation(p); assert.throws(() => a.inspect(p));
  }
});
test('pending routes exclude exact labels/endpoints, not all same-country nodes', () => {
  const p = fixture(); p.name = '🇵🇱 Польша — 2'; assert.equal(a.pending(p, ['🇵🇱 Польша']), false);
  p.name = '🇵🇱 Польша'; assert.equal(a.pending(p, ['🇵🇱 Польша']), true);
  p.name = 'Auto'; p.server = '31.77.59.141'; assert.equal(a.pending(p, []), true);
  p.server = '176.108.245.140'; p.port = 18447; assert.equal(a.pending(p, []), true);
  p.port = 18444; assert.equal(a.pending(p, []), false);
});
test('fresh audit output includes every label/exclusion and no private wire', async () => {
  const proxies = [fixture(), {...fixture('hysteria2'), name: 'HY2'}, {...fixture(), name: 'Pending', server: '45.151.180.85'}];
  const emitted = [], calls = [];
  await a.run({action: 'run', proxies, pending_labels: [], fetched_at: 123, binaries: {}}, v => emitted.push(v), {
    versions: async () => ({}), probe: async p => { calls.push(p); return {label: p.name, outcome: 'https_and_egress_observed'}; },
  });
  assert.equal(calls.length, 2); assert.equal(emitted[0].available_labels, 3);
  assert.equal(emitted[0].excludes[0].label, 'Pending'); assert.equal(emitted.at(-1).tested, 2);
  assert(!JSON.stringify(emitted).includes('SECRET-FIXTURE-ONLY'));
  assert(!JSON.stringify(emitted).includes('aaaaaaaa-bbbb'));
});
test('duplicate labels cannot disappear by collision and schema mode never probes', async () => {
  await assert.rejects(a.run({action: 'run', proxies: [fixture(), fixture()], pending_labels: []}, () => {}));
  let called = false;
  await a.run({action: 'schema', proxies: [fixture()], pending_labels: []}, () => {}, {
    versions: async () => { called = true; }, probe: async () => { called = true; },
  }); assert.equal(called, false);
});
