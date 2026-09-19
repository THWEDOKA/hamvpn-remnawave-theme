const fs = require('fs'), yaml = require('yaml');
const { XrayJsonGeneratorService } = require('/opt/app/dist/src/modules/subscription-template/generators/xray-json.generator.service.js');
const { MihomoGeneratorService } = require('/opt/app/dist/src/modules/subscription-template/generators/mihomo.generator.service.js');
(async () => {
  const p = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (p.action === 'yaml') { process.stdout.write(JSON.stringify(yaml.parse(p.yaml))); return; }
  const hosts = p.hosts.filter(h => !h.metadata.isHidden);
  const byId = new Map(p.catalog.map(h => [h.uuid, h]));
  const templates = new Map(p.templates.map(t => [t.uuid, t.templateJson]));
  for (const h of hosts) {
    const item = byId.get(h.metadata.uuid);
    if (!item) throw Error('Resolved host not in catalog');
    h.metadata.tags = item.tags;
    if (item.xrayJsonTemplateUuid) h.clientOverrides.xrayJsonTemplate = templates.get(item.xrayJsonTemplateUuid);
  }
  const xray = new XrayJsonGeneratorService({getCachedTemplateByType: async () => structuredClone(p.defaultXray)});
  const mihomo = new MihomoGeneratorService({getCachedTemplateByType: async () => structuredClone(p.mihomo)});
  const x = JSON.parse(await xray.generateConfig({hosts, isExtendedClient: true}));
  const m = yaml.parse(await mihomo.generateConfig(hosts, false, false));
  const members = hosts.filter(h => h.metadata.tags.includes('AUTO_BASE_POOL'));
  const wires = members.map(h => xray.buildOutbound(h, 'proof'));
  process.stdout.write(JSON.stringify({xray:x, mihomo:m, memberNames:members.map(h=>h.finalRemark), wires}));
})().catch(() => {process.stderr.write('Native render failed');process.exitCode=1;});
