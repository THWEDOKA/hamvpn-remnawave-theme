# TLS245 self-steal — verified 16 September 2026 (Europe/Minsk)

The existing node at `196.251.107.245` now provides REALITY self-steal on
`tls245.torcalc.ru:443`. The owner's current host label, **🇩🇪  Германия 2**,
was read from the panel and preserved, rather than reverting its recent rename.

## Transport and compatibility

- Public VLESS/REALITY 443 uses the server's own TLS endpoint on
  `127.0.0.1:8443`, not a third-party website.
- The previous VLESS/TLS endpoint is retained on that loopback port with its
  certificate, client UUIDs, flow, transport and ALPN. Cached TLS clients still
  connect through public 443 and are forwarded to it.
- Ordinary HTTPS requests reach the static repair-reference site through
  separate nginx HTTP/1 and h2c loopback backends. No invented business history,
  reviews, contacts, payments or order-taking forms.
- Address, Host and SNI in the public host are `tls245.torcalc.ru`; the actual
  transport remains raw/TCP without HTTP obfuscation.
- Existing certificate reused: Let's Encrypt YE1, expires **2026-12-14
  19:38:40 UTC**. DNS-only record was read back from Cloudflare and confirmed
  through Google and Cloudflare public resolvers; no conflicting AAAA.
- Certbot changed from standalone to webroot `/var/www/acme`; staging
  reconfiguration and a complete renewal dry-run with the deploy hook passed.
  Initial LE staging busy/invalid-order responses were transient; subsequent
  bounded retries succeeded without reissuing the production certificate.

## Confirmed tests

| Check | Result |
| --- | --- |
| Migration unit tests | 8 passed |
| Installed Xray 26.3.27 configuration test | Passed; candidate hash matched |
| Cached TLS via IP and domain, before/after migration and renewal | HTTP 204, expected egress |
| New REALITY with Chrome and Firefox fingerprints | HTTP 204, egress `196.251.107.245` |
| Actual public Happ subscription | HTTP 200, exactly one target host, REALITY |
| VPN using the actual subscription outbound | HTTP 204 and expected egress |
| External HTTPS website | HTTP 200, trusted chain, TLS 1.3, ALPN h2 |
| Local target and public website HTTP/1 + HTTP/2 | HTTP 200 |
| External management/loopback ports 2222/8443/8080/8081 | Unreachable from separate external Linux host |
| Browser visual/DOM check | Readable at normal and 320px viewport; 16px text, no horizontal overflow |
| Target after renewal hook | Connected; existing users returned |
| nginx, Certbot timer, management firewall | Enabled and active |
| Temporary probe user | Deleted by API; database absence verified |
| Twenty-minute rollback timer | Cancelled, inactive/dead after final successful probes |

The other 22 node configurations and 72 pre-existing host connection settings
were preserved. The original isolated TLS profile was not edited. New inbound
rights were added only to the squads already granting this node: WHITE, BASE,
OLD and site. A concurrent, unrelated host addition shifted 50 view positions;
these changes were preserved and explicitly reported rather than overwritten.
The test subscription contained 21 configurations before that independent
addition and 22 afterwards; the target remained unique and usable.

## Recovery and publication

- Previous profile: `d67d1f67-62bc-4133-9183-5e9cfecc189c`.
- New isolated profile: `b4572f94-d216-471f-8824-d793b4eb53bd`.
- Node UUID: `dd62f99f-0464-413f-915e-05bb075098bd`.
- Host UUID: `f9e8c4e3-24f4-4771-8e09-69d366c8f5b6`.
- Root-only node backup: `/root/selfsteal-tls245-backup/before.tar.gz`;
  archive listing and saved SHA-256 verified.
- Root-only panel snapshot, key material and proofs:
  `/root/selfsteal-tls245-panel` (0700 directory, 0600 files).
- Manual rollback: `python3
  /opt/hamvpn-tls245-release/ops/selfsteal-tls245/panel.py rollback` on the panel.
  It guards current bindings, restores only this node/host and removes only the
  new inbound rights, retaining concurrent unrelated additions and audit data.
- Rollback guard: `selfsteal-tls245-rollback.timer`, inactive after completion.
- Deployment code published to GitHub before execution at
  `bd4fa21bc9b2894bb5ff0925810bad3851a11dbb`; concurrency-safe verification at
  `86c275592e3739cf280ce98b483f34f649bbef39`.
- The one-shot candidate secret file and disposable client configs were removed.
  Private keys and credentials were not added to the repository or journal.

Refresh the HAMVPN subscription to receive REALITY self-steal. Old cached TLS
profiles were also verified and remain usable. No active Russian mobile
whitelist test was available; this is not a claim of bypassing every operator.
