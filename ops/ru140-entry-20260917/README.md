# RU140 entry and four independent encrypted exit links

Approved scope: 176.108.245.140 (`gasan`, sudo) as the replacement entry;
DE182, PL150, NL82 and DE94 as exits. Three Timeweb nodes are excluded. The
owner approved self-steal and the four `in-*.torcalc.ru` names in nodes.json.
The previously suggested shared transit through DE94 was explicitly rejected.

Preflight: sudo works; ports are free. Direct TLS works only to PL150, while
authenticated SSH and a 256 KiB integrity test work independently to all four.
Use four separately supervised SSH local forwards, each restricted to the
respective exit's loopback TCP443. Dedicated keys are generated on the entry;
no operator private key is copied. Exit identities cannot execute commands,
open a shell, forward to other destinations, or log in from other IPs.

Client-facing plan: nginx SNI routing on TCP443 to four loopback REALITY
inbounds; local HTTPS self-steal target on 8443 with a four-name certificate.
Per-inbound encrypted VLESS outbounds use the corresponding SSH local forward.
No DIRECT fallback on the entry. Existing foreign profiles and cached clients
remain intact. Only the four main hosts and their four hidden auto candidates
are migrated after authenticated checks; obsolete direct experimental entries
are disabled, not deleted, with guarded rollback.

Publish tested code to GitHub main before deployment. Releases use Git archive
with LF preservation, verified SHA256, strict SSH host keys, and root-only
remote directories. Stage DNS/HTTP/certificate/links first, then isolated panel
profile and service account, installed-Xray configuration test, end-to-end
egress tests, guarded host migration, real Happ subscription tests and cleanup.
Private state/backups: `/root/hamvpn-ru140-entry-20260917` on affected servers.

No server-side check alone establishes availability through a particular
Russian operator. SSH transports add overhead and possible TCP head-of-line
blocking; each exit has its own connection so one exit does not transit others.

References: [nginx SNI passthrough](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html),
[OpenSSH forwarding restrictions](https://man.openbsd.org/sshd_config),
[Xray routing](https://xtls.github.io/en/config/routing.html).
# Rollout status: entry140 superseded, not published

On 2026-09-17 the user replaced the proposed public entry with 162.141.185.208.
The entry140 backend and loopback VPN probes succeeded, but authenticated public
ingress probes did not. Customer hosts were **not** switched to entry140.
Do not run its `publish` action for the new entry or reuse its snapshot as a
fresh migration baseline. Staged services and root-only recovery data remain;
this is not a claim that entry140 was uninstalled.

`prune_hosts.py` is a separate, narrowly scoped operation authorized by the user:
retire the eight Hysteria2/XHTTP/Salamander host records belonging to these four
exits, preserving their four ordinary visible hosts and four hidden VLESS auto
pool records. It changes only `isDisabled`; records remain recoverable. It
does not alter DNS, nodes, profiles, credentials or another server's hosts.
The script snapshots all hosts, node bindings, exit profiles and a real Happ
subscription in `/root/hamvpn-four-exit-host-cleanup-20260917`, verifies the
restricted delta and subscription, and rolls back its flags on a failed check.
Its operation order is `snapshot`, `apply`, `verify`; `rollback` restores the
saved flags with concurrent-change guards. Do not blindly repeat `snapshot`
or `apply` after an interrupted response.

## Entry244 direct-listener recovery

The three nginx public SNI-router attempts were rolled back before DNS or
customer-host publication. Isolated direct Xray listeners passed all eight
Chrome/Firefox authenticated probes for the four exits. `direct244.py` promotes
this tested layout only after archiving the third failed attempt, checking
the old bindings, preserving the inactive isolated profile, and testing with
the node's installed Xray. It does not modify any shared profile.

TEST retains its original direct port443, REALITY identity and routing. The four
own-domain REALITY frontends use 18443 (DE3), 18444 (PL2), 18445 (NL), and 18446
(DE4), with inbound MSS1200 and local HTTPS target127.0.0.1:9443. Public nginx
stream routing is absent; nginx serves HTTP80 and local HTTPS9443 only.
Existing reverse-SSH exit channels remain independent and loopback-only.
Published direct hosts use the entry IP as Address and the own domain as SNI/Host,
avoiding stale DNS sending the new ports to the old entry. The four website DNS
records are still migrated and checked. Update the subscription after cutover.

Order: `direct244 prepare`, node244 installed `test`, panel244 `accept-test`,
`direct244 stage`, fresh node244 backend `probes`, stop isolated diagnostic
units, `direct244 entry-check`, transfer its SHA-bound proof to panel244
`accept-entry`, panel244 `activate` (guarded timer), `probes`,
`direct244 sites`, panel244 `publish`, dns244 `move`, real panel244 `subscription`,
node244 `renew`, `direct244 entry-finish`, panel244 `finish`, test-user cleanup.
Failed activation rolls back through panel244; no public nginx mutation is
required. Do not reuse the historical nginx arm/activate/finish actions for
this direct layout. Root-only state stays in `/root/hamvpn-entry244-20260917`.
Read actual proof markers before resuming; this runbook is not proof of rollout.
