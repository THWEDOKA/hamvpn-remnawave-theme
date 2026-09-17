# TLS245 capacity repair — verified 17 September 2026

Only existing node **VLESS TLS — 245**, IP `196.251.107.245`, UUID
`dd62f99f-0464-413f-915e-05bb075098bd`, public host **🇩🇪  Германия 2**,
`tls245.torcalc.ru`, was in scope. Fresh panel reads confirmed profile
`TLS245-SELFSTEAL` / `b4572f94-d216-471f-8824-d793b4eb53bd` and host
`f9e8c4e3-24f4-4771-8e09-69d366c8f5b6`. Concurrent fleet changes were neither
attributed to this repair nor reverted.

## Confirmed cause and live repair

- Kernel history contained **12,835 conntrack table-full / packet-drop log
  lines**, first observed at 12:19:17 UTC and last at 14:08:47 UTC. These are
  log lines, not a claim about exact packet loss count.
- The conntrack ceiling was 65,536; 39–43 thousand entries and 35–40 thousand
  established sockets were present during initial inspection, plus about
  16,200 orphan FIN-WAIT-1 sockets against an orphan ceiling of 16,384.
- Cumulative `TCPAbortOnMemory` was 334,163 during initial inspection and
  421,508 by the post-application observation. There was no process OOM or TCP
  memory pressure, making the orphan ceiling consistent with these resets;
  the counter itself does not individually identify each reset cause.
- Xray/container had been running continuously since 15 September 22:08:56
  UTC, with restart count zero. Disk was 9% used, CPU was not saturated,
  certificate valid, and panel connection intact. Reinstallation was not
  justified.

At **14:37:51 UTC**, applied release
`c7735af446523b8d4f6a3041c57f06d642ae5c2d` from verified GitHub main:

| Setting | Before | After |
| --- | ---: | ---: |
| `net.netfilter.nf_conntrack_max` | 65,536 | 262,144 |
| `net.ipv4.tcp_max_orphans` | 16,384 | 32,768 |
| `net.ipv4.tcp_orphan_retries` | 0 (kernel default handling) | 4 |

Existing 65,536 conntrack hash buckets and active-client retry settings were
not changed. Observed conntrack slab objects were 256 bytes: entry bodies at
the new ceiling represent about 64 MiB, plus allocator/extensions overhead,
instead of about 16 MiB at the old ceiling. The node has 3.82 GiB RAM and had
about 1.34 GiB available before repair. Orphan cleanup limits retention only
after an application has already locally closed its socket.

Persistence is configured in the two owned files:

- `/etc/sysctl.d/99-hamvpn-tls245-capacity.conf`
- `/etc/modules-load.d/hamvpn-tls245-conntrack.conf`

The systemd merged sysctl configuration contains exactly the expected three
definitions. Early module loading ensures the conntrack sysctl exists at
boot. No reboot was performed or needed to apply the live settings.

## Verification

- Seven guard/regression tests passed on Windows and on the node.
- Archive transferred with LF preserved; SHA-256 matched:
  `2caed3d6ab3c0e01ec48e7cdf6f498ecdd65d13b02bc12c297e0c20414d0bb8c`.
- Three full probe rounds (before repair, immediately after, and after the
  observation/renewal check): all **15 scenarios passed**. Each round included
  legacy VLESS/TLS by IP and domain, REALITY Chrome and Firefox, and the actual
  Happ subscription outbound. Each returned HTTP 204 and expected exit IP
  `196.251.107.245`. The public subscription contained one matching target.
- All three disposable one-hour / 128 MiB probe accounts were removed through
  the API, with database absence verified. No customer credentials changed.
- External trusted TLS 1.3 / h2 handshakes: 9/9 passed from the panel host.
  External HTTPS website: 6/6 HTTP 200 from the bot host.
- Certificate still expires **14 December 2026, 19:38:40 UTC**. Certbot timer
  enabled, webroot configuration and existing deploy-hook hash preserved.
  A fresh staging renewal dry-run succeeded. The deploy hook was deliberately
  not executed in this dry-run to avoid restarting the busy VPN; it had been
  verified during the prior deployment and was not changed by this repair.
- Two-minute sampled interval 14:38:57–14:40:57 UTC: conntrack occupancy
  27,786–33,024 / 262,144; orphan sockets dropped from 2,842 to 1,142 (about
  16,200 before repair); available memory increased to 2,093,376 KiB.
- No new conntrack table-full or OOM log lines since application. No increment
  of `TCPAbortOnMemory` during the sampled interval (421,508 throughout).
  `ListenDrops` increased by eight; therefore this report does **not** claim
  zero drops of every kind or prove the absence of all external network loss.
- Docker start time, runtime compose, nginx, renewal configuration/hook and
  normalized firewall policy hashes remained identical. No restart, profile
  edit, protocol migration, key rotation or user disconnection was performed.
- Final authenticated probe at approximately 14:41 UTC: node connected,
  unchanged bindings, 31 users online.

## Recovery and protected proofs

- Node release: `/opt/tls245-repair-20260917/c7735af44652/ops/tls245-repair-20260917`.
- Node backup and proofs: `/root/tls245-repair-20260917/verified` (0700;
  archive, baseline, application and observation JSON files 0600). Archive
  readability and SHA-256 checked before mutation.
- Panel disposable-user intents and sanitized results:
  `/root/tls245-repair-20260917-probes` (root-only).
- Scoped rollback: `python3
  /opt/tls245-repair-20260917/c7735af44652/ops/tls245-repair-20260917/capacity.py rollback`.
  It checks current settings and exact owned files before restoring only the
  three prior values and removing only the two owned files. Under high traffic,
  restoring the old limits can reintroduce the original capacity problem.
- Initial attempt was automatically rolled back because an overly strict
  firewall guard included live traffic counters. Old values, no owned sysctl
  file, unchanged VPN files and unchanged container start were read back.
  These earlier records remain in `/root/tls245-repair-20260917`; the corrected
  guard ignores counters, not policy. No broad restore was used.
- Implementation and follow-up fixes were published directly to GitHub main
  before their respective deployments. No secrets were committed.
- Public journal publication is intentionally left to the coordinating task
  for one verified entry after integration, avoiding duplicate announcements.

This repairs demonstrated local capacity exhaustion. It does not prove
reachability under Russian mobile allowlists or promise immunity to future
overload. The test interval is short and was not an artificial load test.
