# TLS245: self-steal without breaking cached TLS clients

Scope: existing HAMVPN node `196.251.107.245`, `tls245.torcalc.ru`, exact UUIDs
revalidated through the panel. Preserve the current user-facing host name.

The previous transport is TLS, not REALITY. A plain switch to a nginx target
would break cached TLS clients. Instead, this installation preserves the
original VLESS+TLS inbound on **127.0.0.1:8443**, with identical certificate,
client UUIDs and TLS settings. REALITY on public TCP 443 uses it as its local
TLS target. Old TLS clients pass through REALITY to that compatibility inbound;
ordinary browsers fall through to the static site over nginx loopback HTTP/1
8080 or h2c 8081. New clients use REALITY directly. All are independently tested.

This adapts the selfsteal skill's renderer templates to an existing TLS node;
the default nginx TLS listener is replaced by Xray TLS to retain compatibility.
The site is a factual repair reference page, not a claimed real business.
DNS and the already-issued certificate are reused; no fresh production ACME
issuance or secret transfer to nginx or GitHub is required.

Publish verified code to GitHub before running it. `deploy-web.sh` backs up
node configuration first and changes Certbot from standalone to webroot using
its staging-tested `reconfigure` command. No global firewall/container upgrade.

Panel workflow: `prepare`, `create-test`, `probe-before`, transfer the generated
candidate privately to the node and run its installed Xray configuration test,
arm the scoped rollback timer, `switch`, `probe-after`, `publish`, `verify`,
`subscription`, Certbot renewal dry-run with deploy hook, repeat probes,
`cleanup-test`, cancel and verify the rollback timer.

Backups and secrets belong under root-only `/root/selfsteal-tls245-panel` on
the panel and `/root/selfsteal-tls245-backup` on the node, never this repository.
Rollback restores the old node/profile/host binding, removes only the newly
added squad inbounds and preserves concurrent unrelated additions. It refuses
unexpected target bindings and retains inactive profiles for recovery.

Sources: [Xray fallback/ALPN](https://xtls.github.io/en/config/features/fallback.html),
[REALITY](https://github.com/XTLS/REALITY),
[Certbot reconfigure](https://eff-certbot.readthedocs.io/en/stable/using.html#modifying-the-renewal-configuration).
