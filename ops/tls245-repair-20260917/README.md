# TLS245 targeted capacity repair — 17 September 2026

Only existing node `196.251.107.245`, UUID
`dd62f99f-0464-413f-915e-05bb075098bd`. No reinstall, protocol change, account
change, firewall relaxation, Docker upgrade or restart. Other nodes/profiles
and concurrent removals are outside this operation.

Read-only evidence found 12,835 kernel `nf_conntrack: table full, dropping
packet` messages between 12:19 and 14:08 UTC. The 65,536-entry ceiling was
insufficient for observed traffic. Around 16,200 orphan FIN-WAIT-1 sockets
also approached the 16,384 ceiling; cumulative TCPAbortOnMemory was 334,163,
without TCP memory pressure, process OOM, or container restarts. The kernel
counter does not distinguish each individual reset cause.

The target has 3.82 GiB RAM, about 1.34 GiB available at inspection, and
conntrack entries of 256 bytes plus overhead. The existing 65,536 hash
buckets remain unchanged. The conservative live repair raises conntrack
capacity to 262,144 (roughly 64 MiB for entry bodies at the ceiling), doubles
the orphan ceiling to 32,768, and limits retransmissions of **already locally
closed** sockets to four. Retries/timeouts of active clients stay unchanged.
The latter prevents merely allowing stale FIN-WAIT-1 sockets to grow longer;
it is not a promise against arbitrary volumetric traffic or operator blocking.

Sources: [Linux conntrack sysctls](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)
and [Linux TCP sysctls](https://docs.kernel.org/networking/ip-sysctl.html).

`diagnose.py` and `deep_inventory.py` are read-only, aggregate-only probes.
`capacity.py apply` verifies exact host/runtime, saves root-only configuration
and baseline snapshots to `/root/tls245-repair-20260917`, and writes only
`/etc/sysctl.d/99-hamvpn-tls245-capacity.conf`. It loads only that file, never
global sysctl files. Existing connections/conntrack entries are not flushed.
`capacity.py rollback` checks that the live settings and owned file still
match this repair, then restores only these three values and removes only
its own file. Use the same verified GitHub release for either action.

Publish and verify this directory on GitHub main before application. Preserve
all existing REALITY keys, legacy TLS clients, certificates, subscription
settings and squad membership. Re-test both protocols and actual public
subscription, inspect kernel counter deltas, and remove the disposable probe
account before claiming a verified result.
