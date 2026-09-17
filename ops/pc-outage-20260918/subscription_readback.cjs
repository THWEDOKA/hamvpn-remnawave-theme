// Read-only fresh subscription check; credentials/link/configurations stay RAM.
// Input stdin: metadataPath, profilePath, yamlModuleRoot, sha256,
// targets:[{id,address,port}]. No HWID is invented or device enrollment requested.
const fs = require('fs');
function wire(p) {
  return {address: p.server, port: p.port, uuid: p.uuid, sni: p.servername,
    key: p['reality-opts']?.['public-key'], sid: p['reality-opts']?.['short-id'],
    flow: p.flow, reality: !!p['reality-opts'], tls: p.tls,
    network: p.network || 'tcp'};
}
function xrayWire(outbound) {
  const destination = outbound.settings?.vnext?.[0], stream = outbound.streamSettings || {};
  if (outbound.protocol !== 'vless' || !destination || destination.users?.length !== 1) return null;
  return {address: destination.address, port: destination.port, uuid: destination.users[0].id,
    sni: stream.realitySettings?.serverName, key: stream.realitySettings?.publicKey,
    sid: stream.realitySettings?.shortId, flow: destination.users[0].flow,
    reality: stream.security === 'reality', tls: ['tls','reality'].includes(stream.security),
    network: ['raw','tcp',undefined].includes(stream.network) ? 'tcp' : stream.network};
}
function equal(a, b) {
  const keys = Object.keys(a).sort();
  return JSON.stringify(keys) === JSON.stringify(Object.keys(b).sort()) && keys.every(k => a[k] === b[k]);
}
async function read(url, agent) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw Error('invalid URL');
  const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(25000),
    headers: {'User-Agent': agent}});
  if (response.status !== 200) throw Error('subscription HTTP failure');
  return response.text();
}
async function main() {
  let input = ''; for await (const chunk of process.stdin) input += chunk;
  const request = JSON.parse(input);
  if (!/^[a-f0-9]{64}$/.test(request.sha256)) throw Error('candidate hash required');
  const yaml = require(require.resolve('yaml', {paths: [request.yamlModuleRoot]}));
  const metadata = yaml.parse(fs.readFileSync(request.metadataPath, 'utf8'));
  const item = metadata.items.find(item => item.id === metadata.current);
  if (!item || item.type !== 'remote' || typeof item.url !== 'string') throw Error('remote active subscription required');
  const cached = yaml.parse(fs.readFileSync(request.profilePath, 'utf8'));
  const [mihomoText, happText] = await Promise.all([read(item.url, 'mihomo/1.19.29'), read(item.url, 'Happ/5.7.0')]);
  const fresh = yaml.parse(mihomoText), happ = JSON.parse(happText);
  if (!Array.isArray(fresh.proxies) || !Array.isArray(happ)) throw Error('unexpected subscription formats');
  const auto = happ.filter(config => config.remarks === '⚡ Автовыбор Серверов');
  if (auto.length !== 1) throw Error('expected exactly one automatic-server config');
  const result = [];
  for (const target of request.targets) {
    const matches = proxies => proxies.filter(p => p.server === target.address && p.port === target.port && p.type === 'vless');
    const before = matches(cached.proxies), after = matches(fresh.proxies);
    if (before.length !== 1 || after.length !== 1) throw Error('ambiguous main subscription target');
    const expected = wire(before[0]);
    const main = happ.filter(config => config.remarks === after[0].name);
    const actualMain = main.flatMap(config => (config.outbounds || []).map(xrayWire)).filter(Boolean)
      .filter(p => p.address === target.address && p.port === target.port);
    const actualAuto = (auto[0].outbounds || []).map(xrayWire).filter(Boolean)
      .filter(p => p.address === target.address && p.port === target.port);
    result.push({id: target.id, mihomo_main_unchanged: equal(expected, wire(after[0])),
      happ_main_unchanged: actualMain.length === 1 && equal(expected, actualMain[0]),
      happ_auto_unchanged: actualAuto.length === 1 && equal(expected, actualAuto[0]),
      automatic_mihomo_group_member: fresh['proxy-groups']?.some(group => group.type === 'url-test' && group.proxies?.includes(after[0].name)) || false});
  }
  console.log(JSON.stringify({sha256: request.sha256, timestamp: Date.now()/1000, subscription_readback: result,
    passed: result.length === request.targets.length && result.every(r => r.mihomo_main_unchanged && r.happ_main_unchanged && r.happ_auto_unchanged)}));
}
if (require.main === module) main().catch(() => { console.error('Fresh subscription readback failed; private link was not printed'); process.exitCode = 1; });
module.exports = {wire, xrayWire, equal};
