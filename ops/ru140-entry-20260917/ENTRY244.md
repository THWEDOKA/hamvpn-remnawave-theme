# Entry244 migration, 2026-09-17

Explicit operator-selected target: **193.233.222.244**, existing panel node
`PITER TEST`. Self-steal and movement of the four existing in-*.torcalc.ru names
were explicitly approved. This replaces entry208 for the same four exits only.
The eight experimental duplicate host records were already reversibly disabled;
the other hosts and the global auto-selection template are out of scope.

## Design

- Keep the original shared G-CONFIG unchanged. Clone its legacy TEST inbound
  into a dedicated entry244 profile, preserving its keys/names and route.
- Copy the four currently published entry208 REALITY key/short-ID/name tuples
  into four entry244 loopback inbounds. Cached client settings remain compatible.
- nginx SNI passthrough on TCP443 sends each confirmed name to its own inbound;
  unknown/legacy SNI goes to the preserved TEST inbound on loopback15443.
- Four separate outgoing VLESS routes use loopback21443/22443/23443/24443 and
  authenticated reverse SSH connections initiated by each foreign exit.
- Reverse SSH keys are distinct and generated on the exits. The Russian entry
  receives only public keys. Each key allows one loopback listener, from one exit
  source address; no session, agent, PTY, password login or local forwarding.
- Forwarded traffic on each exit can reach only its own loopback443. This is
  not a shared transit through Germany4 or USA2. Failure of one link cannot
  cause a fallback to direct Internet through the entry.
- Preserve the existing TEST host and exactly eight main/hidden host UUIDs.
  Do not delete the concurrently created unrelated `test2` host on entry140.

## Evidence before installation

Direct TLS from entry244 to all four foreign 443 ports timed out. Direct SSH
authenticated to NL and DE4 with the compact diagnostic; reverse SSH
authentication and 256KiB transfer were verified for all four exits. DE182's
reverse verification used a native operator SSH transport to that exit and
Paramiko for the exit-to-entry connection, avoiding a Windows diagnostic-layer
failure. Native OpenSSH reverse diagnostics were unreliable on three paths, so
the bounded Paramiko service must pass actual server-side VLESS tests before DNS.

The existing TEST client was checked externally: HTTPS204, egress193.233.222.244.
These results are not proof of accessibility from the user's Russian operator.

## Protected operation

Private state: `/root/hamvpn-entry244-20260917` on panel, entry and four exits.
Release scripts are under the common versioned `hamvpn-ru140-entry/releases`
tree; the historical parent directory does not change the explicit244 guards.
Use transport244.py and the exact pushed main commit.

Prepare sites/TLS and reverse channels in parallel without touching public443.
The already issued four-name certificate and its ACME account are transferred
over authenticated SSH directly in memory; no private material enters Git or
operator output. CF credentials remain on the panel. Verify the candidate with
the installed Xray26.7.28, authenticate through all four backend channels, stage
the isolated profile and add only required squad rights, then activate under
paired bounded rollback timers. Check public full routes before publishing.

Publish host bindings while DNS still points to the compatible entry208, then
move exactly the four owned A records after the new public probes pass. Verify
CF readback, two public resolvers, the actual Happ subscription (main and auto),
old TEST client, HTTPS site, expected foreign egress and certificate renewal.
Only then disarm the rollback timers and remove the temporary test account.

For explicit rollback remove the entry244 SNI-router file with node244.py first,
then use panel244.py rollback, which also restores operation-owned DNS records
if they were moved. Snapshot guards refuse to overwrite later unrelated edits.
Allow for DNS cache TTL on rollback. Keep old entry208 working for cached users.

The former entry208 rollout passed public and subscription probes, certificate
renewal and an additional Windows-client check; the operator reported that it
was still unavailable in their network. Both of its old automatic rollback
timers were explicitly stopped before starting this replacement. Its protected
state and legacy USA2 service remain available. This document describes the
procedure, not a claim that entry244 has already been published.
