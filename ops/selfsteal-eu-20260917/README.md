# Four additive EU self-steal nodes

Owner-approved addresses and FQDNs are in `nodes.json`. This directory is not
a generic installer: it refuses other targets and existing VPN/web deployments.
Sites/nginx/DNS templates were generated with the installed selfsteal skill.

Deploy only a verified GitHub commit. First verify SSH host keys and empty
ports 80/443/8443/2222. `node.py ID install` records a root-only backup, installs
Docker/nginx/certbot, and serves HTTP challenges. Create only approved DNS-only
A records, verify propagation externally, then run `node.py ID certificate`.
`node.py ID start` accepts the panel `/api/keygen/` response only through private
stdin and stores the node configuration root-only. No credentials belong here.

The existing fleet-compatible Remnawave 2.7.0 image is resolved and pinned by
digest. Host networking lets REALITY reach nginx on 127.0.0.1:8443. Public 443
belongs to VLESS/REALITY Vision; browsers see the local trusted HTTPS site.
The node API on 2222 accepts only localhost and panel 64.225.109.248, including
after reboot. No global firewall reset, general upgrade, or SSH policy change.

Run a real authenticated VPN probe before publishing hosts. Check the actual
Happ subscription, normal server auto-selection, external HTTPS/TLS1.3/h2,
certificate renewal dry-run, and remove the operation's temporary account.
No guarantee of Russian operator allowlist reachability is implied.

Rollback is additive: disable only newly created hosts, remove only this
operation's inbound UUIDs from their entitlement squads, and retain disabled
profiles, certificates, and protected backups for audit. Never restore a whole
panel database or touch unrelated node bindings. Stop the new node container
only after disabling its public hosts. Node backups are under
`/root/hamvpn-selfsteal-ID-backup`.

References: [Remnawave node](https://docs.rw/install/remnawave-node/),
[Xray REALITY](https://xtls.github.io/en/config/transport.html#realityobject).
