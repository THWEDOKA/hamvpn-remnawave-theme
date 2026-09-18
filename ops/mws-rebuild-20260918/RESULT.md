# MWS rebuild — verified 2026-09-18

## Deployed topology

- Entry and Russian egress: `176.109.85.244` (provider NAT, NIC `10.1.7.10`).
- One international egress: `72.56.101.218`.
- New frontend: `mws.torcalc.ru:18443`, VLESS / REALITY / Vision,
  compatibility floor `minClientVer=1.8.2`.
- Existing host `🇬🇧 🌐 Обход все операторы G` was replaced **in place**:
  subscription identity, display name and unrelated host fields preserved.
- Cached XHTTP/TLS clients retain the old hostname, certificate and port `2083`.
  They now receive the same split routing as the new frontend.
- Russian domain/category and GeoIP rules use `RU-DIRECT`; other traffic uses
  the foreign outbound. There is no automatic international-to-direct fallback.
- The selected host was not a member of the inspected Happ automatic pools
  before migration; this operation did not add it to those pools.

## Why the transport differs from the initial candidate

Direct entry-to-exit TCP/443 connected but TLS and authenticated VPN requests
timed out. A dedicated reverse SSH connection initiated by the exit succeeded.
The entry uses loopback `127.0.0.1:27443`, carrying authenticated REALITY inside
the encrypted SSH channel to the exit's local backend.

The dedicated SSH identity permits only remote forwarding to that exact
loopback listener. Shell/exec sessions, local/dynamic forwarding, agent/X11/PTY
and password authentication are prohibited. Entry host key is pinned. The
private tunnel key remains on the exit. Restart/reconnection and subsequent
authenticated HTTP 204 plus foreign IP were tested. `PermitListen` constrains
the listener, **not** the client destination; the root-owned client unit fixes
the destination to `127.0.0.1:443`.

Entry public 443 also accepted TCP but did not receive the test TLS payload
observed from the panel, while local TLS worked. No specific filtering vendor
or operator is proven. Public 18443 passed the same full VPN and HTTPS tests,
so it is the published frontend port. Public 443 is not advertised as working.

## Verification completed

- Installed Xray 26.3.27 validates the final configuration.
- Real external Xray and isolated Windows mihomo clients pass HTTPS 204.
- Foreign IP is `72.56.101.218`; Yandex's Russian IP check reports
  `176.109.85.244` through the VPN.
- Actual Happ and mihomo subscriptions were fetched and checked. Connections
  using their exact generated outbound/proxy fields passed the same tests,
  including again after retirement of the original node/profile.
- Cached legacy XHTTP/TLS 2083 passed HTTPS 204 and both egress checks.
- Self-steal sites return trusted HTTPS 200:
  `https://mws.torcalc.ru:18443/` and `https://mws-exit.torcalc.ru/`.
- Both DNS A records are DNS-only. Google and Cloudflare resolvers returned
  the expected IPv4 addresses and no AAAA records.
- Both new certificates expire 2026-12-17. Certbot renewal dry-runs with deploy
  hooks passed on both servers; persistent renewal timers are enabled.
- Other 27 node bindings and 59 hosts are unchanged. `remnanode-gas` and
  `remnanode-friend` retained their original container IDs and start times.
- Both rollback timers **and services** are inactive, no current rollback
  marker remains, and the operation's disposable test account was deleted.
- Eighteen offline unit tests passed.

These are server and control-client checks, not a guarantee of reachability
through active mobile-operator allowlists. An actual MTS-network test is still
needed from the user's device.

## Retirement, recovery, and retained data

The old MWS node and its unshared profile were removed via Remnawave API after
successful replacement checks. The old customer host was updated in place,
not deleted and recreated. The original container is stopped, not erased;
its certificate directory is still mounted read-only for cached clients.
The legacy certificate expires 2026-12-12; its original certificate material
was preserved, not replaced by the new self-steal lineage.

The original MWS-only watchdog tried to restart the stopped container during
the first cutover. That attempt was rolled back and the exact original Docker
network restored. On the successful attempt, only that legacy watchdog timer
was disabled; unrelated watchdogs and containers were preserved.

Protected state and snapshots remain under `/root/hamvpn-mws-rebuild-20260918`
on the panel and selected nodes. Original panel snapshot SHA-256:
`00ded22ba3d77cf169ecafaa635c6c35f5365aa37f9e81db00f05edb39b098e0`.
Private keys, API responses, test identities and configurations are not stored
in Git. Published releases are under `/opt/hamvpn-mws-rebuild/releases/`.

Do not rerun cutover or deletion actions blindly: inspect their protected
intent/readback files. Restoring a removed panel object now requires an
explicit, scoped recovery plan; the cancelled cutover timer is not a general
post-retirement restore mechanism.

## Follow-up: renamed host and Firefox verification

The user renamed the host to `🇳🇱 🌐 Обход #2` and changed its fingerprint to
`firefox`. Fresh readback showed Firefox **before** the operation's idempotent
apply step, so that step made no further host mutation. Current Happ and
mihomo generated subscriptions both advertise Firefox. The operator preference
is recorded in `codex/rules/vpn-fingerprint.md` and the local global AGENTS rule.

Full-page tests through the actual generated Firefox outbound returned HTTP
200 for Instagram (about 411 KB), Wikipedia (about 119 KB), and the Yandex
Russian-IP check. Foreign egress remained `72.56.101.218`, Russian egress
`176.109.85.244`. Isolated Windows mihomo also passed the three egress/204 tests.
The probe's JSON serialization was corrected to emit real UTF-8: YAML parsing
of escaped emoji surrogate pairs was an issue in the diagnostic harness,
not evidence of an invalid production subscription. The separate short-lived
diagnostic account was deleted and absence confirmed.

Adding this host to automatic bypass was paused at the user's request during
their Wi-Fi incident. No automatic-pool changes were made. Read-only discovery
found that the active `⚡ Автовыбор Обхода` is a server-side Hysteria2/leastPing
route on Selectal, not the disabled older Xray-template host with the same
display name. Reachability from that selector must be tested before adding a
backend. The Wi-Fi-specific symptom is not declared fixed without user feedback.
