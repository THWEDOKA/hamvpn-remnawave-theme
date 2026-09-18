const test = require('node:test'), assert = require('node:assert/strict');
const {configuration, run} = require('./mihomo_auto_measure.cjs');
const source = () => ({'mixed-port': 7890, 'socks-port': 7891, 'external-controller': '0.0.0.0:9090',
  proxies: [{name: 'wire', type: 'vless', 'ws-opts': {headers: {Host: 'example.test'}}, future: {untouched: true}}],
  'proxy-groups': [{name: 'Manual', type: 'select', proxies: ['Auto']},
    {name: 'Auto', type: 'url-test', 'include-all-proxies': true, filter: '^wire$'}], rules: ['MATCH,Manual']});
test('sandbox changes listeners only, preserves unknown nested wire/group/rule fields', () => {
  const original = source(), before = structuredClone(original), cfg = configuration(original, 21001, 21002, 'ephemeral');
  assert.deepEqual(original, before);
  for (const k of ['proxies', 'proxy-groups', 'rules']) assert.deepEqual(cfg[k], original[k]);
  assert.equal(cfg['bind-address'], '127.0.0.1'); assert.equal(cfg['allow-lan'], false);
  assert.equal(cfg['external-controller'], '127.0.0.1:21002'); assert.equal(cfg['socks-port'], 0);
  assert.equal(cfg.tun.enable, false); assert.equal(cfg.profile['store-selected'], false);
});
test('non-isolated custom listeners/controllers fail instead of silently binding', () => {
  for (const key of ['listeners','external-controller-pipe','external-controller-unix','external-controller-tls']) {
    const cfg = source(); cfg[key] = key === 'listeners' ? [{port: 9999}] : 'existing';
    assert.throws(() => configuration(cfg, 21001, 21002, 'ephemeral'));
  }
});
test('unbound/tampered envelope rejected before processes', async () => {
  await assert.rejects(run({phase: 'candidate', preview: {passed: false}}));
  await assert.rejects(run({phase: 'other'}));
});
