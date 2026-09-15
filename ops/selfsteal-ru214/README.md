# RU214 self-steal

Scoped migration of the existing HAMVPN host «🇷🇺 Россия», node `161.104.90.214`,
to a dedicated REALITY profile using `ru214.torcalc.ru:443` and local nginx
TLS target `127.0.0.1:8443`. This directory is not a generic installer.

The current node already uses REALITY. The migration preserves its private key,
all short IDs, existing SNI names, Firefox fingerprint, client identities,
traffic routing and existing squad access. No plain-TLS migration is needed.
Do not change the shared RU profile or the separate TLS245 node.

## Release/run order

1. Verify canonical remote/main, run `python -m unittest discover -s ops/selfsteal-ru214 -v`,
   coordinate the shared repository commit lock, commit and push before production.
2. Confirm DNS-only A `ru214.torcalc.ru` → `161.104.90.214`, without conflicting records,
   and verify both Cloudflare API readback and two public resolvers.
3. Deploy this exact Git release. Run `deploy-web.sh http`, validate public HTTP,
   provision the explicitly authorized DNS-01 broker and node hook, then run
   `deploy-web.sh tls`. The installer snapshots node/firewall configuration,
   never restarts the VPN container and exposes only port 80 in addition to existing rules.
4. On the panel run `panel.py stage`, then `create-test` and `probe-before`.
   Test the protected candidate with the installed node Xray. Record its SHA256
   and successful test in `/root/selfsteal-ru214-panel/xray-test.json`.
5. Validate local TLS 1.3, ALPN h2, certificate hostname/trust, namespace reachability,
   renewal staging dry-run and reload hook. Arm a scoped rollback timer on the panel
   for `panel.py rollback`; verify it is active before `switch`.
6. Run `switch`, `probe-after`, `publish`, `verify`, `subscription`. Failed post-switch
   probes automatically restore the previous node and host binding. Verify ordinary
   public HTTPS and inspect the static site. Stop the timer only after success.
7. Run `cleanup-test`, verify timer inactive and node connected. Publish only confirmed
   outcomes to the HAM journal and record the final evidence in this directory.

`ssh_session.py` is an operator-only password-hidden transport. No credentials,
private keys, production snapshots or subscription links belong in this repository.
Node backup: `/root/selfsteal-ru214-backup`. Panel snapshots and test intent:
`/root/selfsteal-ru214-panel` (root-only). The inactive clone is retained after rollback.

Existing allowed traffic is not proof of a bypass of active mobile-operator allowlists.
No such operator test is claimed without direct evidence.

## Authorized certificate-only egress

Direct TLS handshakes to the production and staging ACME endpoints timed out on
RU214, while TCP connections and 1500-byte path MTU tests succeeded. There is no
global IPv6 or configured system proxy. The user explicitly authorized a narrow
maintenance channel through the existing HAM panel, not a general-purpose proxy.

`acme-node.sh key` generates a dedicated key locally on RU214. Send only its public
half to `acme-panel.py` on the trusted panel. Independently obtain the panel's
ED25519 host public key through the existing verified SSH connection and install
it in `/etc/hamvpn-acme-ru214/known_hosts` for `64.225.109.248`. Never TOFU this channel.
After SSH configuration validation and successful unchanged-root comparison,
activate the node service with `acme-node.sh activate`.

The panel user has no SSH session, shell, SFTP, remote forwarding, Unix-socket
forwarding, agent/X11 forwarding, tunnel, TTY, password login or user RC. Both the
key and sshd constrain local forwarding to exactly the production/staging ACME
hostnames on port 443; the key is accepted only from RU214's IP. The local SOCKS
socket binds `127.0.0.1:18089`. Only certbot receives proxy environment variables.
Python Requests/PySocks performs remote DNS using `socks5h` and still validates
the end-to-end ACME TLS certificate. Test both allowed endpoints and negative
destinations (`example.com:443`, `127.0.0.1:22`), shell/session and remote forwarding
before relying on the relay for issuance or renewal.

References: [Requests SOCKS support](https://requests.readthedocs.io/en/stable/user/advanced/#socks),
[OpenSSH forwarding/session restrictions](https://man.openbsd.org/sshd_config).

Relay rollback is scoped: stop/disable only `hamvpn-acme-ru214.service` on RU214,
remove only its certbot drop-in, and revoke only the dedicated key on the panel.
Keep the protected snapshot `/root/selfsteal-ru214-acme-panel`; do not restore the
whole SSH config over later administrator edits. Never revoke maintenance access
while the active self-steal certificate depends on it without an alternative.

## DNS-01 after secondary HTTP validation failed

Both production and staging HTTP-01 validation failed at a secondary validator,
although three validators and independent Windows/panel probes fetched HTTP 200.
No AAAA record or HTTP redirect caused the failure. The user explicitly approved
DNS-01 with the Cloudflare credential remaining only on the trusted panel.

A separate key `/etc/hamvpn-acme-ru214/dns_ed25519` is generated only on RU214.
The fixed-command panel identity `hamvpn-dns-ru214` accepts JSON on stdin:
`{"action":"present|cleanup","validation":"<43-character base64url TXT>"}`.
It is distinct from the forwarding-only ACME identity and has no forwarding or
general command access. Its only DNS scope is `_acme-challenge.ru214.torcalc.ru`;
cleanup must prove the broker owns the exact record before deletion.

`dns-hook.py` validates the certificate domain and challenge value, connects using
the pinned panel host key, and requires the broker's explicit verified propagation
proof (both authoritative nameservers as checked from the panel). The hook
also requires TXT visibility from Google and OpenDNS as seen by the node (both
verified reachable; most authoritative Cloudflare addresses and Cloudflare/Quad9
resolver UDP timed out from RU214). Its 420-second local propagation timeout fails
closed without publishing the challenge or credentials
in output. `acme-node.sh dns-activate` installs the hook and dnspython dependency.
Certbot stores the manual auth/cleanup hooks in the renewal configuration; the
existing certificate-only SOCKS path remains limited to ACME API endpoints.
