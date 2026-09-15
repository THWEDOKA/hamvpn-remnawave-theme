# Self-steal pilot: USA - 3

Requested scope: the visible host `🇺🇸 США - 3` only, plus its existing hidden
auto-selection counterpart if needed to preserve service on the same node.

- Target node: `GASAN US 2`, address `162.141.185.216`.
- Visible host UUID: `a2302256-68a3-4e3e-8213-5817b0177712`.
- Node UUID: `22ac9320-4762-461d-b877-a9f33b58d492`.
- Intended hostname: `us3.torcalc.ru`; A record, DNS only, TTL 300.
- The current REALITY/raw/443 profile is shared by 15 nodes. Do not modify
  that shared profile in place. The eventual pilot requires an isolated copy
  while preserving existing credentials and checking cached-client compatibility.

## DNS change safety

`dns-record.json` is the desired record. Publish this verified file to GitHub
main before applying it. The preflight lookup found no record at this exact
name. Re-read before creation; never overwrite a different A/AAAA/CNAME record
or a concurrent change. No changes to the apex or other subdomains are allowed.
After creation, re-read the record through the authenticated API and check
public resolvers. Keep the created record ID for an exact rollback. A rollback
would remove only this newly created record after verifying that it still
matches this manifest; no automatic deletion is performed by this change.

The Cloudflare token must stay outside this repository and command output.
An account-scoped token may authorize zone operations while the user-token
verification endpoint rejects it; judge zone access using the actual zone API.

API reference:
https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/

## Current state

2026-09-15: SSH access confirmed on `util-us-3` (Ubuntu 24.04). DNS record
`8744cbaad10e927459214fa1d8f51d63` was created and verified through the API,
Google DNS and Cloudflare DNS, with exactly the manifest values.

The self-steal endpoint is deployed and verified. See
[deployment-2026-09-15.md](deployment-2026-09-15.md) for the completed checks,
release provenance and rollback references. `deploy-web.sh http` creates
protected configuration/firewall backups,
installs nginx and Certbot without restarting the existing node, then serves
the static page and ACME on port 80. `deploy-web.sh tls` obtains an ECDSA
certificate using HTTP-01 and enables TLS 1.3 / HTTP/2 only on 127.0.0.1:8443.
No Cloudflare token is copied to the server. Certbot's systemd timer and a
checked nginx reload hook handle renewal. Port 443 remains owned by Xray.

Run the script only from an archive of the verified GitHub main commit. The
HTTP phase refuses an existing nginx installation or occupied port 80; review
existing state rather than bypassing those checks. The TLS phase requires
correct public DNS and reachable HTTP. Check the certificate and TLS locally
before changing any panel profile or subscription host.

The page uses an intentionally retro system-font layout with tested contrast,
mobile reflow, semantic headings and no third-party resources, forms, payments,
fabricated reviews, business history or contact details.

Web rollback: restore the saved HTTP config if TLS validation fails. Never
stop nginx or remove certificates while REALITY still targets localhost:8443;
restore the panel's original profile first. Root-only backups must remain on
the server and must never be included in Git or the public journal.

## Isolated panel transition

Run `panel-selfsteal.py` as root on the panel server, from the verified Git
release. `panel_api.py` derives a short-lived existing-admin API session from
local runtime secrets; neither secrets nor session tokens are logged or stored
in this repository. No persistent API credential is created. All writes use
the panel API, not direct database updates.

Sequence: `create-test`, `probe-before`, `stage`, `switch`, `probe-after`,
`publish`, `verify`, `cleanup-test`.
Before `stage`, independently verify the node's loopback HTTPS certificate,
TLS 1.3 and HTTP/2. Before `switch`, validate the staged config using the actual
node's Xray version. The operator backs up the original profile, node, hosts
and four affected squads under `/root/selfsteal-us3-panel` before its first
mutation. This protected directory is not a release artifact.

The clone has a globally unique inbound tag, preserves the existing REALITY
key, short IDs, old server names and routing, and adds the new inbound to the
same four user squads without removing their old inbound access. Only the
specified node moves. The visible host and its hidden same-node counterpart
receive the new address, SNI and Host field after fresh VPN probes pass.
For raw TCP, Host is inert unless HTTP header obfuscation is enabled; this
pilot does not enable or change HTTP obfuscation.

The previously existing test account has no access to this node. Probes instead
use a new temporary technical account in the BASE squad, limited to one hour
and 1 GiB, with no Telegram ID or email. Its creation intent is saved before
the API request; never repeat an uncertain create. `cleanup-test` matches its
exact UUID, name, tag and description before removing it and verifies absence
in the database. No customer account is modified. Client files are root-only
and temporary; they are removed after each
bounded probe. The test executable is copied from the running node, verified
by SHA-256, and runs only a loopback SOCKS listener on the panel server.
Both the cached IP/global.hambot.ru/qq route and the new domain route (qq and
Chrome fingerprints) must reach HTTPS 204 and return the expected exit IP.

If any post-switch check fails, execute `rollback` immediately. It restores the
original node and host bindings through the API and removes only the added
inbound from the affected squads, retaining other concurrent squad additions.
The inactive clone and protected backup remain for recovery; no profiles,
users or databases are deleted. Investigate concurrent node/host changes
before proceeding. Do not blindly retry an uncertain profile-creation POST.

Final verification requires all original squad inbounds plus the pilot inbound
to remain present. It reports, but does not remove, additional concurrent
inbounds. During this deployment a separate change added `GZ_WS_APIS` to WHITE
and site after the initial checks; both additions were preserved.
