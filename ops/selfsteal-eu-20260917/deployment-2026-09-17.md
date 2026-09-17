# Four EU nodes: verified server-side installation, Russian access unresolved

Date: 17 September 2026. All four FQDNs explicitly approved by the owner.

| Visible VLESS host | Address / Host / SNI | Ingress and verified egress | Certificate expires (UTC) |
|---|---|---|---|
| 🇩🇪 Германия — 3 | de182.torcalc.ru | 217.60.68.182 | 2026-12-16 13:04:51 |
| 🇵🇱 Польша — 2 | pl150.torcalc.ru | 31.56.188.150 | 2026-12-16 13:04:48 |
| 🇳🇱 Нидерланды | nl82.torcalc.ru | 94.183.255.82 | 2026-12-16 13:04:48 |
| 🇩🇪 Германия — 4 | de94.torcalc.ru | 62.60.226.94 | 2026-12-16 13:05:34 |

Each has a second visible host with ` · Hysteria2` appended and one hidden
normal-auto-selection counterpart per protocol: eight visible and eight
hidden enabled hosts in total. Existing normal-server squads were discovered
from the live normal inbound: WHITE, BASE, OLD and site. No entitlement was
removed by this installation.

## Final protocol selection

The original request was REALITY self-steal. The owner subsequently supplied
a concrete template with `security: tls`, VLESS TCP fallback and Hysteria2,
and requested that scheme instead. The final state follows that revision:

- VLESS Vision, RAW/TCP 443, trusted TLS and own-domain SNI.
- Hysteria2 version 2, UDP 443, TLS/ALPN h3, the same trusted certificate.
- Browser fallback: local nginx on 127.0.0.1:9443 (HTTP/1.1) and 9444 (h2c).
  The separate h2 fallback corrects the one-port example for negotiated HTTP/2.
- Certificate files are mounted read-only into the host-network node container.
- Remnawave node 2.7.0 / Xray 26.3.27, pinned image digest
  `sha256:9d57375a8168d00252f4debe7a6ac29debd8449af60467ab26b4ee212b047525`.
- Normal auto-selection uses the pre-existing `AUTO_BASE_POOL` selector.
  Only the new hidden hosts receive that tag; shared templates are unchanged.
- Node API TCP/2222 accepts only localhost and panel 64.225.109.248;
  IPv6 access to that port is dropped. SSH and other firewall rules retained.

The active profiles are:

| Node ID | Panel node UUID | TLS+HY2 profile UUID |
|---|---|---|
| de182 | 2c0f93bf-ec0a-4dff-b0f1-b57badd920e1 | 597b8c2d-65a6-40a5-bb97-2fb633157812 |
| pl150 | b3db4b7a-5d9f-4179-88b8-8ee5203e6188 | 38e17416-ed14-41ef-b277-282dc518ea39 |
| nl82 | b680ba6e-fa4b-40d3-8542-f05de1fdd07e | 5489a7b9-127c-4bdf-bd0a-d91230daa031 |
| de94 | 98e15d09-88af-4c8f-8a97-6c2a62d36312 | 23829877-f156-4599-a4ce-a5bebf8d37cf |

## Verified checks

- SSH host-key checking retained; fresh Ubuntu installations and free ports
  established before installation. Original authorization and settings backed up.
- Four DNS-only A records read back through Cloudflare API and independent
  Google/Cloudflare public resolvers. No DNS token installed on the nodes.
- Four real Let's Encrypt ECDSA certificates, hostname/chain verification,
  external TLS 1.3 and both HTTP/1.1 and h2 fallback responses verified.
- All four templates pass `xray run -test` with the installed node binary.
- Eight direct authenticated VLESS/HY2 probes pass: HTTPS 204 and correct egress.
- Eight probes through the exact public Happ subscription outbounds also pass,
  including membership of both protocols in normal server auto-selection.
- Four staging certificate-renewal dry-runs pass. The new deploy hook reloads
  nginx and restarts only that node, then verifies TCP and UDP 443 returned.
  Ubuntu 22's older Certbot lacks `--run-deploy-hooks`, so its hook was executed
  separately after the successful dry-run. Post-renewal VPN probes pass.
- nginx, Docker, certbot.timer and scoped management-firewall services active;
  all four panel nodes connected and all sixteen owned hosts enabled.
- TCP/2222 is blocked from the independent jump host; panel connectivity works.
  Local Windows TCP-connect-only checks were misleading under its networking
  path, so these were not used as evidence of external firewall exposure.
- Browser DOM checks pass on all four sites and visual inspection passes on
  the shared page. Public HTML matches the deployed Git release byte-for-byte,
  is valid UTF-8, and contains no replacement characters.
- The disposable account was deleted and absence checked in the panel database.
  All four operation-specific rollback timers are stopped/inactive.

Two packaging defects were corrected before completion: Windows Git archive
line-ending conversion affected shell shebangs, and the initial renderer's
stdout encoding corrupted Cyrillic text. LF attributes, archive overrides,
UTF-8 generation and regression tests now protect these paths.

## Explicitly unresolved: client network in Russia

The owner reports that both the ordinary entries and the Hysteria2 entries do
not connect from Russia. Therefore **working access from that network and a
TSPU/allowlist bypass are NOT established**. Successful external probes prove
server configuration, not reachability through a particular operator.
Operator, client name/version and one redacted Hysteria2 connection log were
requested to distinguish UDP/QUIC filtering, address blocking, and client errors.
The supplied screenshot shows client version 5.7.0 and connectivity-check
timeouts to `www.gstatic.com/generate_204`, but its entries are dated
15 September, before this deployment. It does not identify the selected
Hysteria2 outbound or show a current handshake error. A fresh attempt after
subscription refresh is needed; the screenshot alone does not establish
IP-wide blocking, QUIC filtering, or a DNS failure.
No speculative mass protocol changes, third-party relays or IP purchases were
performed in response to the unlocalized failure.

## Preservation, release and rollback

Concurrent external administration removed eight pre-existing nodes and
seventeen old hosts after the operation snapshot and cleared two node links.
These exact deltas were reviewed and retained; this installer did not issue
those deletions. Thirteen remaining old nodes and fifty-four old hosts matched
their snapshot except those reviewed links; the shared normal profile and
existing squad entitlements were preserved. No claim is made that concurrent
third-party changes were performed by this deployment.

Public source: GitHub `THWEDOKA/hamvpn-remnawave-theme`, main. Installation,
TLS transition and corrective releases were pushed before deployment. Latest
EU runtime/source bundle is `6e73c40`; public operator reports may be newer.

Protected panel state and per-node intents/proofs:
`/root/hamvpn-selfsteal-eu-20260917`. Node backups:
`/root/hamvpn-selfsteal-ID-backup`, with the TLS revision in `tls-hy2/`.
SSH authorization pre-change copies remain under `/root/.ssh/`.

An explicit rollback can use `tls_panel.py rollback --id ID` from a verified
release, which disables only owned hosts and restores that node's saved
REALITY binding. It intentionally leaves the node unpublished, not advertised
as a working replacement. It preserves certificates, inactive profiles and
audit records. Do not restore a whole panel database or reset unrelated hosts.

Passwords, private keys, panel node credentials, subscription links and
temporary-user identifiers are absent from Git and this report.
