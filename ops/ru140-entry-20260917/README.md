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
