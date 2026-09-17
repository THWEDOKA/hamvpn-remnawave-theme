# DE182 Hysteria2/Salamander UDP8443 — verified 17 September 2026

Owner requested a trial of Hysteria2 with Salamander on a different UDP port.
Added one visible test entry on existing Germany 3:

- **🇩🇪 Германия — 3 · HY2 Salamander**
- Endpoint: **de182.torcalc.ru:8443**, UDP, ingress/egress **217.60.68.182**.
- Hysteria2 over TLS, ALPN h3, with `finalmask.udp` Salamander.
- Existing trusted certificate and its renewal process reused unchanged.
- No AUTO_BASE_POOL tag or hidden auto counterpart; manual selection only.

This is additive to the existing VLESS/TLS TCP443, ordinary Hysteria2 UDP443,
and XHTTP/TLS TCP443/loopback10080. Their config blocks, inbound UUIDs and hosts
are unchanged. UDP8443 does not conflict with nginx's loopback TCP8443.
No reinstall, firewall reset, certificate replacement or other-node change.
The panel's core config update can reconnect sessions; uninterrupted sessions
are not claimed.

## Verification

- GitHub release `87083d9d38693576b34641d7ab82e3cd1b54b3be` published before use.
  Archive SHA-256 checked independently on panel and node:
  `1312f5f9039320cb002af45f29dc62b8bc8031dc8ec87fecda47d2dd5ca6b1e4`.
- Seven dedicated tests passed locally and on Linux, plus eight existing
  XHTTP/auto regression tests locally. Installed Xray **26.3.27** accepted the
  actual candidate, including Salamander, before deployment.
- UDP8443 was free before the change; the node INPUT policy already allowed it.
  Existing SSH and management-port restrictions were not changed.
- All three existing protocols passed authenticated baseline probes.
- First post-update round: the old VLESS HTTPS-204 request passed, but its
  separate external-IP request returned curl error 56. The new Salamander and
  other two protocols passed. No cause is inferred from that one transient
  reset. Publication remained gated until the next full round passed.
- Two subsequent full rounds of **all four protocols passed**, each returning
  HTTPS 204 and the correct exit IP 217.60.68.182.
- The **actual Happ/5.7.0 public subscription** contained the new host exactly
  once, with UDP8443, verified TLS and identical server/client Salamander
  settings. Its exact outbound passed twice. It is absent from auto selection.
- A negative control with the same valid user but **without the mask failed**
  (curl codes 35/35). A subsequent correct subscription probe passed again.
- Website remained HTTP200 with TLS verification result zero. New UDP8443,
  old UDP443/TCP443 and loopback XHTTP10080 listeners were confirmed.
- nginx, certificate timer and management-firewall service active. Docker
  compose, nginx route, renewal config/hook and firewall script hashes unchanged.
- All 25 pre-existing node identities/bindings and 85 hosts were preserved
  against the operation snapshot (ordering ignored); squad changes only add
  this inbound to the existing ordinary-HY2 entitlement groups.
- Disposable two-hour/256 MiB account deleted and absence verified with a
  read-only database query. The 25-minute rollback timer is stopped/inactive.

These are external core/subscription checks, **not a test on the user's actual
iPhone or Russian operator**. Operator/TSPU bypass remains unconfirmed. The
owner must refresh the subscription and select the exact new entry.

## Secrets and recovery

The masking secret is generated on the panel using 32 random bytes, stored
only in protected operational state/panel configuration and delivered to
authorized subscribers through their subscription. Per-user authentication
is retained. Neither the masking secret nor a subscription/user credential
is printed, committed, or put in the public journal.

State/backups on both owned hosts:
`/root/hamvpn-hy2-salamander-de182-20260917`, mode 0700; JSON files 0600.
Private candidate transit used memory and verified encrypted SSH, not a local
plaintext file. Private node config-test diagnostics remain inside that directory.

Release directory on both hosts:
`/opt/hamvpn-hy2-salamander-de182/releases/87083d9/ops/hy2-salamander-de182-20260917`.
Run `pilot.py rollback` on the panel only for an intentional recovery: it
disables the owned host, detaches only its entitlement/inbound, and restores
the exact saved three-inbound profile after checking for concurrent edits.
It does not restore a database or modify another node. Backups are retained.
