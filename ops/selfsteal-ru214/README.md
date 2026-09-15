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
3. Deploy this exact Git release. Run `deploy-web.sh http`, validate public ACME HTTP,
   then `deploy-web.sh tls`. The installer snapshots node/firewall configuration,
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
