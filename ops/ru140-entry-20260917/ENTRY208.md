# Existing US2 node as the four-exit entry

Target: 162.141.185.208, a secondary address of util-us-3 (primary egress
162.141.185.216). The operator explicitly selected this IP, self-steal and
relocation of the four in-*.torcalc.ru DNS records from unpublished entry140.

This is not a fresh-node reinstall. The existing US2 profile remains unchanged
in the panel. A separate profile preserves its keys, short IDs, names, settings
and direct route, moves its listener to loopback 15443, and adds four separate
REALITY inbounds with a TLS target at loopback 9443. nginx routes the four names
to loopback 11443/12443/13443/14443; every other SNI follows the legacy listener.
Existing US2 host records change only their profile/inbound binding.

Four explicitly matched outbound routes use authenticated VLESS to the existing
foreign servers, with TLS or REALITY matching each server's live profile. They
precede legacy DIRECT rules, so their traffic cannot escape through the entry's
direct route. No SSH intermediate is required if full backend probes pass.

Root-only recovery state on entry and panel: `/root/hamvpn-entry208-20260917`.
Entry nginx rollback is armed for 30 minutes, panel rollback for 31 minutes.
For a manual rollback, run `node208.py rollback` on entry **first**, then
`panel208.py rollback` on panel, and verify the original service externally.
The first removes only the operation-owned stream config after a hash check;
the second restores only original node/host bindings with later-edit guards.
TLS preparation and snapshots are retained for recovery, not deleted blindly.

Use transport208.py with a pushed main revision. Order: panel snapshot and
baseline; entry prepare; confirmed DNS move; certificate; installed Xray test
and panel accept-test; authenticated backend probes; panel stage; arm both
timers during activation; activate entry SNI router; public old/new client
probes; publish precisely eight foreign visible/auto hosts; validate the actual
Happ subscription and egress; renewal dry-run; finish both timers. Keep the
four visible hosts' four hidden auto pool records. Duplicate cleanup is separate.
All secret exports must be sent through the operator's binary SSH pipe, never
printed or stored in Git. The existing private backend service account is reused.

Files and test success alone are not deployment evidence. See the final verified
operation report (when present) for what was actually switched and tested.
