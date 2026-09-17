# Four additive EU self-steal nodes

## Final owner-selected mode

During installation the owner supplied a different Remnawave template and
explicitly requested ordinary TLS plus Hysteria2. The final live profiles use
**VLESS Vision + TLS on TCP/443 and Hysteria2 + TLS on UDP/443**, not REALITY.
The original self-steal profiles below are retained inactive for rollback.
Each node has an HTTPS fallback site: decrypted HTTP/1.1 goes to loopback
9443 and HTTP/2 to loopback 9444. The original loopback TLS site remains
available only locally for rollback compatibility.

`tls_node.py` adds the read-only certificate mount, validates the revised
template with the installed Xray, and installs the reload/restart renewal hook.
`tls_panel.py stage/switch/probe/publish/subscription/finish` controls the
separate TLS+HY2 profiles. Its limited timed rollback is disarmed only after
both protocols work from the real Happ subscription. Hidden hosts join the
existing `AUTO_BASE_POOL` tag selector; the shared template is not rewritten.

See `deployment-2026-09-17.md` for verified outcomes and the explicit limitation:
the owner reports Hysteria2 also fails from their Russian access network.
External successful checks are not evidence of an operator/TSPU bypass.

## Initial preparation and retained rollback implementation

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
