# Ordinary VLESS + TLS node 245

Scope approved by the owner: `196.251.107.245`, `tls245.torcalc.ru`, host
`VLESS TLS — 245`. No REALITY, self-steal or decoy website. TCP 443 carries
VLESS with trusted TLS; TCP 80 is used only by standalone ACME challenges.
Remnawave node management TCP 2222 accepts only localhost and the HAM panel.

Use the committed GitHub revision, not a downloaded third-party installer.
Verify SSH host identity and the empty-server preflight before execution.
Passwords, Cloudflare credentials, node key, certificate keys and probe users
are runtime-only secrets: never add them to this directory or a report.

1. `dns_setup.py`: hidden token prompt; creates exactly one DNS-only A record.
   Existing conflicting records are never overwritten.
2. Upload this directory to `/opt/hamvpn-tls245`. Run `bootstrap.sh` as root.
   Retain logs and the root-only preflight backup; stop on any error.
3. Relay `/api/keygen/` response privately into `node-key.json` on this node.
   Run `launch_node.py`; it consumes that file without printing the key.
4. Stage the dedicated config/profile/node and disabled subscription host.
   Add only this inbound to the existing normal-server entitlement squads.
5. Test trusted TLS, authenticated egress and actual subscription serialization,
   then publish the host. Run `certbot renew --cert-name tls245.torcalc.ru
   --dry-run --run-deploy-hooks` and retest egress.

The node image uses the existing fleet's 2.7.0 release and is pinned to its
resolved digest at installation. Certificates are mounted read-only on this
node. The deployed panel's certificate resolver preserves file paths when they
do not exist locally, so no certificate private key is copied to the panel.
Recheck this behavior before a future panel upgrade.

Rollback: first disable the new host, then detach only its inbound from the
four affected squads, delete only the newly created node/profile using the
recorded UUIDs, and stop only `/opt/remnanode` on `196.251.107.245`.
Keep backups, certs and disabled artifacts until recovery is confirmed. Do not
restore a full panel database or flush global firewall rules. The ACME timer
may be stopped on this dedicated node if rollback leaves it unused.

Sources: [Remnawave node](https://docs.rw/install/remnawave-node/),
[Xray transports](https://xtls.github.io/en/config/transport.html).
