# XHTTP pilot and three Timeweb auto candidates — verified 17 September 2026

## Germany 3: additive XHTTP/TLS

Owner requested one pilot of VLESS + XHTTP + TLS. Target is existing node
`HAM-DE182-SELFSTEAL`, `217.60.68.182`, public domain `de182.torcalc.ru`.
The new visible subscription entry is **🇩🇪 Германия — 3 · XHTTP TLS**.

- Public TLS remains on TCP/443 using the existing trusted certificate.
- The existing VLESS/TLS fallback passes the pilot path through nginx to
  VLESS/XHTTP on **127.0.0.1:10080**. The internal listener is not public.
- XHTTP uses **packet-up**, client ALPN **http/1.1**, and no Vision flow.
  TLS verification stays enabled; no insecure-certificate option is used.
- The initial HTTP/2 client failed with an HTTP/1.1 response/frame mismatch.
  An explicit HTTP/1.1 client passed. Only the pilot's client/host ALPN was
  corrected; the existing frontend ALPN and other protocol settings were kept.
- Existing VLESS/TLS and Hysteria2 inbounds, UUIDs, hosts, domain, certificate,
  renewal configuration, Docker compose and management firewall are preserved.
  API configuration updates reloaded the core; no claim of zero reconnections.
- The pilot has no AUTO_BASE_POOL tag or hidden counterpart. It is not
  automatically selected for all users while its operator compatibility is unknown.

Verified before publication: the installed Xray 26.3.27 accepts the candidate;
authenticated old VLESS and Hysteria2 pass before the change. After correction,
all three protocols pass twice (HTTPS 204 and exit IP 217.60.68.182).
The exact public Happ/5.7.0 subscription XHTTP outbound also passes twice,
appears once, uses TLS/443 with certificate checks and no Vision flow, and is
absent from the auto-selection configuration. These are core/subscription
checks, not a claim that an actual iPhone was remotely tested.

External HTTPS site remains HTTP 200 with successful TLS verification. The
node's loopback-only XHTTP listener, existing TCP/UDP 443, active nginx,
certbot timer and scoped firewall service were checked. Twenty-two existing
node bindings and seventy-six pre-existing hosts were preserved against the
pilot snapshot (host ordering excluded).

**Russian operator/TSPU reachability remains unverified.** The owner must
refresh the subscription and explicitly test the new XHTTP TLS entry through
the affected network. Successful server-side tests are not evidence of that bypass.

## Explicit additional request: normal auto selection

Only these three existing nodes were added:

| Panel node name | Address | New hidden candidate |
|---|---|---|
| Netherlands-HAM-TMWEB-1 | 83.217.194.44 | ABP-TMWEB-NL1-HIDDEN |
| HAM-GERMANY-TMWEB-1 | 89.19.211.249 | ABP-TMWEB-DE1-HIDDEN |
| HAM-NL-TMWEB-2 | 201.51.22.125 | ABP-TMWEB-NL2-HIDDEN |

Each uses its existing shared VLESS/REALITY inbound, port 443 and node binding.
Three hidden hosts tagged AUTO_BASE_POOL were added; no existing visible host,
shared G-CONFIG profile, entitlement squad, node runtime or auto template was edited.
The third node had no existing visible host; no unrequested visible entry was added.

All three passed authenticated direct checks before inclusion, and all three
exact outbounds extracted from the actual **⚡ Автовыбор Серверов** subscription
passed afterwards: HTTP 204 and the expected distinct exit IPs. Each address
appears once. All three match both the existing leastLoad balancer selector
and the health-check subject selector `basepool`. Hidden entries do not appear
as standalone subscription items. The seventy-eight hosts present at this
second snapshot were preserved, excluding ordering.

## Releases, cleanup and recovery

Implementation was tested and published directly to GitHub main before deployment:

- `826d772497f31b82417d42d35a159440084ebf19`: initial isolated pilot and node route.
- `47f5d3a8cfea1b89c4ff884c49548eb80c072d80`: verified client ALPN correction.
- `f4baa424ca670bd97578724c420e94456ed7bb97`: three Timeweb auto candidates.

Eight pilot/auto regression tests and six existing EU-template tests pass.
LF-preserved archives were SHA-256 verified before extraction:

- Initial node/panel bundle: `497ebbd4cd90f4493fc3c8e13bfcc24c779f97e7ee7e3d0ed265c77cee288d1d`.
- Corrected panel bundle: `b607806fc07298acfc5ece4e705be9464f3a848c045071afff5777abf8ad4489`.
- Timeweb panel bundle: `3d623093a6cb104a037c87d777ed6afbf4d0a9d8853f9900f49d21ac43691f4d`.

All three scoped rollback timers are stopped/inactive after verification.
The one disposable two-hour/256 MiB account was deleted; absence was verified
with a read-only database query. No customer credential was changed.

Node and panel snapshots/proofs: `/root/hamvpn-xhttp-de182-20260917`, mode 0700,
with JSON state 0600. Public release code lives under
`/opt/hamvpn-xhttp-de182/releases/<short-commit>/ops/xhttp-de182-20260917`.

Manual recovery is narrow: panel.py rollback removes only the owned XHTTP
inbound/entitlement and disables its host, preserving the old two inbounds;
node.py rollback restores only the checked nginx fallback file;
auto_timeweb.py rollback disables only its three owned hidden hosts. Concurrent
edits are checked before restoration. Protected snapshots are retained, not
copied into Git. No passwords, private keys, user UUIDs or subscription URLs
are in this report.
