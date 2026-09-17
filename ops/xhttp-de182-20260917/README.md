# DE182 XHTTP/TLS pilot

One owner-authorized test on existing Germany 3, not a reinstall or fleet change.
The two current VLESS/TLS and Hysteria2 listeners remain. A third VLESS/XHTTP
inbound listens only on loopback 10080. Existing trusted TLS on public TCP/443
terminates at the VLESS fallback, then nginx sends only `/ham-xhttp-pilot/`
to the new inbound with buffering disabled. Use packet-up on both sides.
Pin the pilot's client ALPN to HTTP/1.1: the unchanged TLS frontend prefers it,
and the initial H2 client received an HTTP/1.1 fallback response. The single
HTTP/1.1 setting passed authenticated probes without changing the old listener.
The dedicated visible host forces TLS/443, has no Vision flow, and is excluded
from the normal auto pool by having no AUTO_BASE_POOL tag or hidden counterpart.
The path is routing, not authentication; existing subscription UUIDs authenticate.

Publish and verify GitHub main before deploying. Export with
`git -c core.autocrlf=false archive` including this directory,
`ops/selfsteal-eu-20260917`, `ops/selfsteal-us3/panel_api.py` and
`ops/selfsteal-ru214/panel.py`. Verify archive SHA-256 on panel and node.

Sequence: node.py prepare; panel.py snapshot/create-test/before-probes;
node.py apply; panel.py apply/after-probes/verify/publish/subscription;
panel.py cleanup/finish; node.py finish. Tests must all pass before finish.
Node and panel arm independent 30/25-minute scoped rollback timers. If a
verification fails, explicitly rollback both components; do not disable the
old hosts. A panel config update may briefly reconnect existing clients.
Runtime backups and proofs are root-only under `/root/hamvpn-xhttp-de182-20260917`.
Rollback checks for concurrent edits; it cannot overwrite unrelated changes.
No passwords, private keys, user UUIDs or subscription URLs belong in Git.

External success is not proof of reachability from Russian operators. The owner
must refresh the subscription and explicitly select the new XHTTP TLS test host.
Do not claim a TSPU/allowlist bypass before that test succeeds.

## Additional owner request: three Timeweb auto candidates

`auto_timeweb.py prepare/apply/verify/finish` adds only the three explicitly
named existing Timeweb nodes as hidden AUTO_BASE_POOL hosts. All use the existing
shared REALITY inbound. It does not modify that profile, node bindings, visible
hosts, squad entitlements or the shared auto template. Before addition each node
must pass an authenticated probe; afterwards its exact public auto-subscription
outbound must be present once and pass again. A 15-minute rollback disables only
the three newly owned entries. It uses the same disposable pilot test account;
finish these checks before `panel.py cleanup`.

References: [XHTTP upstream](https://github.com/XTLS/Xray-core/discussions/4113),
[Xray transport](https://xtls.github.io/en/config/transport.html).
