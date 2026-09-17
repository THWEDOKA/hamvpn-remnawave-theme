# Mihomo / REALITY compatibility incident — 2026-09-18

Confirmed control experiment (no local app changes): the existing subscription
credentials for AEZA Germany 3 and Netherlands 1 pass HTTPS 204 and expected exit
IP using Xray 26.3.27. The running Mihomo 1.19.29 rejects REALITY authentication.
A clean isolated Mihomo process reproduces AEZA's rejection with firefox, chrome
and qq; the working Auto control passes all three fingerprints. Public keys,
short IDs, SNI and subscription rights match the panel. No ICMP-only diagnosis.

Relevant primary reports/source:

- https://github.com/MetaCubeX/mihomo/issues/3039
- https://github.com/MetaCubeX/mihomo/issues/3042
- https://github.com/XTLS/Xray-core/commit/af7eb68
- https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.29/component/tls/reality.go

Mihomo announces REALITY client version 1.8.2. New Xray releases default an absent
minimum version to a newer threshold. This patch intentionally admits 1.8.2,
not 0.0.0, and never changes an explicit existing policy. Keys, identities,
transport, routes, hosts, squads and node assignments remain unchanged. The
operator obtained the user's explicit compatibility approval. This does not
promise to overcome an independent IP/transport block from a Russian carrier.
That approval explicitly acknowledged the upstream warning: admitting older
implementations can also admit more distinguishable TLS fingerprints. Key and
certificate verification are not disabled.

## Canary workflow

Publish and verify the release before copying this directory and
`ops/selfsteal-us3/panel_api.py` to the panel. Run the published helper under root.
Only `--scope aeza-de3` exists: AEZA profile, Germany 3 inbound, port 18443. Four
other inbounds must remain byte-for-byte equivalent as decoded JSON.

1. `plan` saves the full private snapshot to
   `/root/hamvpn-mihomo-compat-20260918/aeza-de3`; normal output is non-secret.
2. `export-candidate --secret-stdout` is **only** a protected RAM/stdin pipe to
   the installed node Xray `run -test -c stdin:`. Never display its output body.
3. `accept-installed` consumes a JSON proof over stdin with candidate `sha256`,
   fresh Unix `timestamp`, `passed: true`, `returncode: 0`, `version: "26.7.28"`.
4. `apply` arms a verified 600-second independent systemd rollback before PATCH.
5. Run real isolated Mihomo and Xray firefox/chrome tests from the external
   control machine, plus the running app's canary delay. No app reload/switch is
   needed for this server-only change. Record HTTPS 204 and exact exit IP.
6. `finish` takes a JSON proof with `sha256`, fresh `timestamp`, positive
   `live_mihomo_delay`, and exactly four `tests` with IDs `mihomo-firefox`,
   `mihomo-chrome`, `xray-firefox`, `xray-chrome`. Every test needs `http: "204"`,
   `exit_ip: "217.60.68.182"`, `curl_codes: [0,0]`, `listener_removed: true`.
   The timer is disarmed only after these proofs. Operator attestation records
   actual executed checks, never synthesizes success.
7. `status` verifies candidate state and timer status; `rollback` restores only
   the snapshotted candidate/original, refusing to clobber unrelated changes.

The helper holds one file lock per scope, including timer rollback. Snapshot and
proof files are immutable, root-owned 0600, in a 0700 directory. No deployment
credentials or customer subscription content belong in this repository.

Tests: `py -3.13 -B -m unittest discover -s ops/pc-outage-20260918 -p 'test_*.py'`.
