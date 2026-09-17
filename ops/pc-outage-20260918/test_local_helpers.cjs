const test = require('node:test');
const assert = require('node:assert/strict');
const {configuration} = require('./local_matrix.cjs');
const {wire,xrayWire,equal} = require('./subscription_readback.cjs');
const proxy = {name:'fixture',type:'vless',server:'192.0.2.1',port:443,uuid:'fixture-identity',
  servername:'example.invalid',flow:'xtls-rprx-vision',network:'tcp',tls:true,
  'reality-opts':{'public-key':'fixture-public','short-id':'ab'}};
test('isolated Mihomo has no TUN, no public listener, same credentials',()=>{
  const c=configuration(proxy,'mihomo','chrome',35001);
  assert.equal(c.tun.enable,false); assert.equal(c['bind-address'],'127.0.0.1');
  assert.equal(c['allow-lan'],false); assert.equal(c.proxies[0].uuid,proxy.uuid);
  assert.equal(c.proxies[0].name,'MATRIX'); assert.equal(proxy.name,'fixture');
});
test('Xray translation preserves the exact wire credentials and REALITY settings',()=>{
  const c=configuration(proxy,'xray','firefox',35002);
  assert.equal(c.inbounds[0].listen,'127.0.0.1');
  assert.ok(equal(wire(proxy),xrayWire(c.outbounds[0])));
});
test('fresh readback detects changed key, UUID, short ID, SNI and endpoint',()=>{
  for(const key of ['address','uuid','sni','key','sid','port','tls','network','flow']) {
    const value=wire(proxy); value[key]='changed'; assert.equal(equal(wire(proxy),value),false);
  }
});
