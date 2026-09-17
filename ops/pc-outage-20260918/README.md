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
The initial scope is `--scope aeza-de3`: AEZA profile, Germany 3 inbound, port 18443. Four
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

## Verified canary outcome

Germany-3 passed isolated Mihomo and Xray checks with both Firefox and Chrome
fingerprints: HTTPS 204, German egress, and all temporary listeners removed.
The running Mihomo application reported 444 ms; the user separately confirmed
successful websites in Koala from Russia. The candidate hash is
`ba2278601575fc11cdf82f9a5335e527f39775b225308a067259165281cadfed`.
Both the original rollback and the additional safety timer/service were verified
inactive after the accepted proof. No client identity or DNS was changed.

The next explicit scope, `aeza-remaining`, only adds the same field to the
Poland-2, Netherlands-5 and Germany-4 public inbounds on this single entry.
It preserves the successful canary and disabled legacy host. Completion requires
four real protocol/fingerprint checks per route, expected foreign egress and
running-application delay checks for each. All twelve checks passed, with
positive live Mihomo delays (546/394/546 ms for PL2/NL5/DE4), matching egress,
and temporary listeners removed. Its rollback timer/service were disarmed
after accepted proof. Candidate hash:
`a0c490f2805adc03ee13ae75f4e49b9b67d517758d82725e2efd9976d9d2ec79`.

## Isolated six-node cohort

`cohort_compat.py` leaves the shared G-CONFIG and five non-target consumers
untouched. It plans a separate profile for the six specifically enumerated
new-core Germany/Netherlands nodes. The clone preserves keys and configuration,
except its inbound tag (including routing references) and `minClientVer`.
Existing main/hidden-auto host UUIDs, wire settings and subscription rights
are preserved. This section describes the workflow, not a deployment claim.

1. `plan` captures private state and verifies exactly six nodes/twelve hosts.
2. Pipe `export-candidate --secret-stdout` into an installed Xray 26.7.28 config
   test. A same-version AEZA validation is a control, not SSH validation on each
   target. `accept-installed` records the actual fresh result.
3. `stage` arms an independent 900-second rollback before clone/rights creation.
4. `apply` moves only the six node assignments and twelve host inbound links.
5. `local_matrix.cjs` performs 24 real isolated HTTPS/egress checks and obtains
   running-Mihomo delays, without switching or reloading the user's app.
6. `subscription_readback.cjs` fetches the active subscription anew in Mihomo
   and Happ formats, holding URL/credentials in RAM. Check all six main routes
   and six Happ auto members against the existing wire credentials, then submit
   its result to `accept-subscription`. It does not claim the separate Mihomo
   automatic proxy is a local url-test group.
7. `finish` requires both fresh subscription proof and all 24 traffic checks,
   then disarms rollback. On failure `rollback` restores owned bindings/grants
   while retaining the inactive clone and preserving unrelated permissions.

Node helper tests: `node --test ops/pc-outage-20260918/test_local_helpers.cjs`.
