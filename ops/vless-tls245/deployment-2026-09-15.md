# TLS245 deployment — verified 15 September 2026

The owner selected **ordinary VLESS + TLS**, explicitly without self-steal,
and approved the domain and host label below.

| Item | Verified value |
| --- | --- |
| Server | `196.251.107.245`, Ubuntu 24.04.4 LTS, x86_64 |
| HAMVPN host | `VLESS TLS — 245` |
| Address and SNI | `tls245.torcalc.ru:443` |
| Protocol | VLESS / TCP (RAW) / trusted TLS / XTLS Vision flow |
| DNS | DNS-only A record, TTL 300; public Google DNS matched |
| Certificate | Let's Encrypt YE1; expires 2026-12-14 19:38:40 UTC |
| Node runtime | Remnawave 2.7.0; Xray 26.3.27 |
| Image digest | `sha256:9d57375a8168d00252f4debe7a6ac29debd8449af60467ab26b4ee212b047525` |
| Profile | `TLS245-VLESS`, `d67d1f67-62bc-4133-9183-5e9cfecc189c` |
| Inbound | `1957094e-0d78-4c48-9004-a11f2518a5d5` |
| Node UUID | `dd62f99f-0464-413f-915e-05bb075098bd` |
| Host UUID | `f9e8c4e3-24f4-4771-8e09-69d366c8f5b6` |
| Entitlements | Existing normal-server squads BASE, WHITE, OLD, site |

## Verification

- Eight deployment/guard unit tests passed; Python compilation, shell syntax,
  Git diff checks and uploaded script SHA-256 comparisons passed.
- The host remained disabled until authenticated VLESS tests passed by both
  IP and domain: HTTP 204 and egress `196.251.107.245`, with certificate
  validation enabled.
- A separate external TLS handshake verified the certificate's hostname,
  chain and TLS 1.3 negotiation.
- Public Happ subscription returned HTTP 200, 22 configurations and exactly
  one `VLESS TLS — 245` entry. An Xray client using that exact subscription
  outbound reached HTTP 204 and the expected egress IP.
- Certbot staging renewal, including the deploy hook, succeeded. The hook
  restarted only this new node and restored TCP 443. The authenticated VPN
  and actual subscription tests then passed again.
- `certbot.timer` and the management-firewall service are enabled and active.
  A separate external Linux host could reach TCP 443 but not TCP 2222.
  Firewall counters confirmed accepts from the HAM panel and drops elsewhere.
  A TCP-only connect from the operator workstation was not used as firewall
  evidence because its local proxy can accept SYNs before upstream completion.
- All 22 pre-existing node configurations, 77 hosts and 17 profiles were
  preserved. Squad changes were exactly the new inbound in the four squads.
- The disposable one-hour / 1 GiB test account was deleted through the API;
  its database absence was verified. No customer account or credentials were
  changed. Temporary client configurations were removed automatically.

No nginx, decoy website, REALITY target or self-steal was installed. TCP 80
has no permanent listener; standalone Certbot uses it during ACME challenges.
Certificate keys stay on this node and are mounted read-only into its runtime.
The one-shot node-key transfer file was consumed and removed.

## Release and recovery

- Bootstrap release: `63e0f3766d17421ed5f0f46d096fc4dded7c7421`.
- Panel deployment release: `1ba2cc794c87f21ebe38df86c5305ee101e4c817`.
- Public subscription verifier: `6298408`.
- Verified code was pushed to GitHub main before production execution.
- New-node preflight backups: `/root/tls245-backup`, mode 0700.
- Panel pre-change snapshot, transaction IDs and proofs:
  `/root/hamvpn-tls245-panel`, directory 0700 / files 0600.
- Panel operational release: `/opt/hamvpn-tls245-release/ops/vless-tls245`.
- Node operational release: `/opt/hamvpn-tls245`.
- Runtime compose: `/opt/remnanode/docker-compose.yml`, mode 0600.

For emergency withdrawal, run `panel_deploy.py rollback` from the verified
release. It disables only this host and removes only this inbound from the
four squads, retaining concurrent additions and audit artifacts. Then stop
only the new node's compose stack if needed. Never restore the full panel
database or change an unrelated node to roll back this installation.

This proves functioning ordinary VLESS + TLS, not allowlisting by every
Russian mobile operator. No test from an actively restricted Russian mobile
network was available. Refresh the HAMVPN subscription before selecting the
new host on a phone.
