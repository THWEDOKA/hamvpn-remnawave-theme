# USA - 3 self-steal deployment — 2026-09-15

## Completed scope

- Visible host: `🇺🇸 США - 3`.
- Node: `GASAN US 2`, OS hostname `util-us-3`, `162.141.185.216`.
- DNS: `us3.torcalc.ru` A → `162.141.185.216`, TTL 300, DNS only.
- Existing hidden counterpart: `ABP-36-US-HIDDEN`, on the same node.
- Both host records now use `us3.torcalc.ru` for address, SNI and Host.
- Public endpoint remains VLESS / REALITY / TCP / 443, with no HTTP-header
  obfuscation. The Host field is inert for this transport.
- New isolated profile: `US3-SELFSTEAL`, UUID
  `2caa9583-8d5a-46af-93b9-d0a41bd691c4`.
- New inbound: `vless-reality-us3-selfsteal`, UUID
  `e28f2113-9667-4e1c-be3c-60316d30f219`.
- REALITY target: `127.0.0.1:8443`. This is a loopback-only nginx listener,
  not another publicly exposed VPN port.
- Original REALITY private key, short IDs, old SNI names and routing preserved.
- Access retained for WHITE, BASE, OLD and site. Old squad inbounds remain.
- Other 14 nodes still use the unchanged `G-CONFIG` profile.

## Site and certificate

Public site: <https://us3.torcalc.ru/>. A static, intentionally retro Russian
page about kettle repair, with no forms, analytics, third-party resources,
payments, invented reviews, contact details or founding date.

nginx serves HTTP/80 for ACME and redirects normal HTTP requests to HTTPS.
The local TLS site uses an ECDSA P-256 Let's Encrypt certificate (issuer YE2),
valid until **2026-12-14 18:06:23 UTC**. TLS 1.3 and HTTP/2 were negotiated with
hostname/certificate verification, both locally and through public REALITY/443.
The certificate key never left the node.

Certbot's systemd timer is enabled. An actual staging renewal dry-run, including
the nginx deploy hook, succeeded. The hook checks nginx configuration before
reloading it. No Cloudflare token was installed on the node.

## Verification evidence

| Check | Result |
|---|---|
| DNS API readback + Google and Cloudflare public DNS | Correct A record, no proxy |
| Configuration test with node's Xray 26.3.27 | Configuration OK |
| Cached IP + global.hambot.ru + qq client | HTTPS 204; exit 162.141.185.216 |
| New hostname/SNI + qq client | HTTPS 204; exit 162.141.185.216 |
| New hostname/SNI + chrome client | HTTPS 204; exit 162.141.185.216 |
| Unauthenticated public HTTPS browser request | Correct website and trusted certificate |
| Happ subscription generation | New address/SNI in USA - 3 and auto-selection |
| Raw TCP HTTP header in generated subscription | Absent, as before |
| Certificate renewal dry-run with deploy hook | Passed |
| Browser at default and 320px widths | Page readable; 16px body, 44px nav targets, no horizontal overflow |
| Deployment / isolation unit tests | 9 passed locally and on panel |
| Node health after transition | Connected, 946 users online at final operational check |
| Temporary technical test account | Deleted through API; database absence verified |
| Timed rollback guard | Cancelled after successful transition; inactive |
| Russian update journal | Entry saved and visible exactly once over verified HTTPS |

The client checks used a new technical BASE account with a one-hour expiry
and a 1 GiB limit, not a customer account. Its temporary client files were
removed after probes. Removing that disposable account did not remove any
customer records. No existing customer credentials were rotated.

During final verification a concurrent, unrelated operation added inbound
`GZ_WS_APIS` to WHITE and site. There were no removals of old or pilot access.
These additions were left intact; verification reports them explicitly.

## Release and rollback references

- Website/nginx deployed from verified GitHub main commit
  `7b8b7a6fc58face4c883e614f3a686bc1f94ec28`.
- Panel transition executed from verified main commit
  `d586aa07085e931742e75d698b27fe734172ef30`.
- Final verifier and test-account cleanup executed from verified main commit
  `994e9a4f513c766baa23d9d62d4930553eccc241`.
- Node backup: `/root/selfsteal-us3-backup-M3i3yKyT` (root-only; archive hashes
  checked). Includes original node deployment, container state and firewall.
- Panel backup: `/root/selfsteal-us3-panel` (root-only snapshot and SHA-256,
  created before profile mutation).
- One-shot rollback timer: `us3-selfsteal-rollback-20260915.timer`, inactive.
- Manual panel rollback: run `panel-selfsteal.py rollback` from the verified
  operational release **before** stopping the local HTTPS target. Review any
  concurrent node/host changes first. The inactive clone is retained for audit.

Installing the web packages did not restart the existing container or core.
The subsequent deliberate profile transition restarted only this node's Xray
core; users reconnected. UFW stayed enabled. Only TCP/80 was added publicly;
nginx TLS/8443 listens on loopback. Node API/2222 remains restricted to the
existing panel address. The node image and OS were not broadly upgraded.

## Scope of the result

This verifies a working server-side self-steal deployment and compatible
subscription output. It does **not** establish that the new domain/IP is
allowed by a particular Russian operator's active whitelist. No live test
from a restricted Russian mobile network was available during deployment.
Users should refresh their subscription and select `🇺🇸 США - 3` for that test.
