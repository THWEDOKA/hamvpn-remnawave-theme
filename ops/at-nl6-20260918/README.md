# AT / NL6 continuation — 18 September 2026

This scope preserves the completed CLOUDru PL/CZ/GBpower migrations and the
20-member native Mihomo automatic-selection template. It does not reuse the
closed six-route probe identity or rollback state.

## Protected preparation

- Canonical preflight release: `09fbae986e0f71fe48a70a1c9db9463be0163c6c`.
- Panel archive SHA-256:
  `5e6a86f43516ec79e5caaafcd1d2d4271e62d4104f2d53b0302ccb0259628f97`.
- Root-private snapshot:
  `/root/hamvpn-at-nl6-20260918/preflight/cloud/before.json`.
- Verified snapshot value SHA-256:
  `63bcc8c51cf53eca0333f7fb6bce806b3fb49c32bba5b01220371e8a284e43de`.
- Both entries, both exits, four profiles, six dependent nodes and thirty
  relevant hosts were saved. The shared G-CONFIG was not modified.
- Temporary technical identity: maximum three hours / 512 MiB, exact owned
  lifecycle; no customer accounts, UUIDs, payment records or rights changed.
- The temporary identity was deleted through its owned lifecycle and actual
  absence was verified. The password-in-memory AT SSH relay was closed.

## Observed AT results, approximately 01:00–01:16 UTC

`diagnose_at.py` is an operator-local diagnostic, not an installer. It uses
the new owned probe through private SSH pipes and starts bounded isolated cores.

- AT `147.45.71.38` runs Xray 26.7.28. Its current main and hidden auto host use
  Hysteria2; the same dedicated profile also retains a VLESS/REALITY listener.
- Fresh current Hysteria2 subscription passed external Mihomo 1.19.29 and
  Xray 26.3.27: HTTPS 204 and independently checked egress `147.45.71.38`.
  This is not a test from a restricted Russian subscriber network.
- The existing VLESS listener passed external Xray but failed external
  Mihomo. No version-policy change was applied; future REALITY frontends must
  include explicitly approved PC compatibility and real Mihomo verification.
- From actual CLOUDru and AEZA host-network namespaces, authenticated VLESS
  and Hysteria2 tests failed. TLS ClientHello fragmentation also failed.
- The assigned AT IPv6 `2a12:5940:6020::2` was read on the pinned AT machine.
  AEZA produced one successful authenticated egress request over IPv6, but
  complete 204+egress probes failed repeatedly. IPv6 is not production-ready.
- TCP/SSH header-only capture on AT showed a handshake and acknowledged server
  banner, with no client SSH payload arriving during the failed KEX test.
  This locates the symptom but does not independently identify the filtering
  authority or prove a specific operator policy.
- A temporary checked-TLS listener using AT's existing certificate on 15444
  also timed out from CLOUDru. Diagnostic listeners 80/18080/28443/15444 were
  closed afterward; no persistent firewall/service changes were made.
- The existing Germany-3 exit `217.60.68.182` passed authenticated VLESS to AT
  **three times out of three**, each with HTTPS 204 and the expected AT egress.
  It is panel node `#633`, **not** node `#650` (`196.251.107.245`). Additional
  transit through it requires explicit user approval before deployment.

## Not complete / pending

- AT has **not** been published through either entry; its old profile, hosts,
  DNS and active clients remain intact. Do not call successful direct probes
  an implemented three-hop route.
- NL6 `31.76.9.211` is inventoried; its shared profile has two other consumers.
  Self-steal choice and first-use SSH trust remain unanswered. No SSH
  authentication, DNS, certificate or profile installation was performed.
- Pending NL6 key fingerprint (observation only; not accepted):
  `SHA256:dqy9TEUEfByQWFJGZ/jLPVki+py35emXHd8v62yEFjM`.
- There is no scheduled PC shutdown. Existing working service is preserved.

## NL6 read-only preparation, approximately 01:22–01:27 UTC

- A separate immutable snapshot was created under
  `/root/hamvpn-at-nl6-20260918/preflight/aeza/before.json`, with value SHA-256
  `25d3112e2a9303c151ceaa7f5508488ad49ba75b372cb889963eb165848dbed1`.
  A distinct short-lived, quota-limited probe was used; the closed AT identity
  was not reused. The NL6 probe was subsequently deleted and absence verified.
- `diagnose_nl6.py` fetched current Happ/Xray and Mihomo subscriptions for that
  probe. Main host and existing hidden automatic candidate each passed in both
  clients: **4/4**, HTTPS 204 and egress `31.76.9.211`. Exact returned client
  wires were used; this is not proof from a restricted Russian user network.
- The actual Mihomo URL-test group uses `include-all-proxies: true`, not
  `include-all`. Its filter includes `ABP-53-NL-HIDDEN`; the effective candidate
  count remains **20**. No template change was made.
- Actual CLOUDru/AEZA namespace tests to NL6 failed on the current REALITY wire.
  TLS ClientHello fragmentation and the already-allowed `global.hambot.ru`
  test SNI also failed. Only disposable client wires changed, not server SNI.
- Germany-3 `217.60.68.182` → NL6 passed **3/3** authenticated tests, each with
  HTTPS 204 and expected NL6 egress. Using this additional transit still needs
  explicit approval for NL6 as well as AT. It has not been installed.
- All temporary clients/listeners were removed. No NL6 SSH authentication,
  DNS writes, certificates, node/profile changes, host publication or PC app
  reload occurred. Self-steal and first-use SSH trust remain unanswered.

No secret snapshot, subscription URL, user identifier, private key or password
belongs in this repository or the public update journal.
