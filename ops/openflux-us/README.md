# OpenFlux pilot on GASAN US

Target: `util-us-1`, `162.141.185.219`. This is separate from the existing
Remnawave node. Do not change its profile, users, container, firewall or ports.

Upstream: https://github.com/p1neappleXpress/OpenFlux at
`7835b7155e193242d03c46ea6f3cf2b528aaa685` (GPL-3.0-or-later).
The user-provided iPhone screenshot confirms that their TestFlight build has
a **VOLGA** transport selector, newer than the iOS sources in this commit.

## Scope and safety

- One private test channel using `vyandex`; not a multi-user subscription service.
- Proxy exit mode, non-root, read-only container, all capabilities dropped,
  no host networking, no published port and no RST suppression rules.
- Public IPv4 destinations only. Private, loopback, metadata, special-purpose
  addresses and this server's public interface addresses are denied in the
  proxy's dial path. This is not a complete OS-level egress firewall.
- Bounded CPU, RAM, PIDs, logs and relay queue/concurrency.
- The document URL is a channel credential: keep it only in
  `/etc/hamvpn-openflux-us/document-url`, never in Git, logs or process arguments.
  Parent directory is root-only; mount the file read-only, owned by UID/GID
  65534 with mode 0400. No document URL is supplied by this repository.
- The upstream Docker entrypoint is deliberately not used: it prints command
  arguments and installs an unnecessary RST rule for proxy mode.
- The iPhone-compatible pilot uses the transport's HTTPS/WSS, without the
  CLI's optional additional AES layer. This is not end-to-end confidentiality
  from Yandex. HTTPS destinations retain their own TLS; do not use the pilot
  for sensitive unencrypted application traffic or distribute the channel.

## Deployment

Publish and verify this directory in GitHub `main` first. Transfer an archive
of that exact commit to a new release directory under
`/opt/hamvpn-openflux-us/releases/`. Preserve a root-only, verified snapshot
of the existing container identity/start time and firewall before staging.
Do not overwrite an existing channel file or an unrelated deployment.

```sh
python3 test_deployment.py
docker compose config --quiet
docker compose build
docker compose up -d --no-build exit-node
```

The image build runs upstream and overlay tests. A running process or a
successful Volga login is **not** proof that the tunnel carries traffic.
Verify an HTTPS request through an independent OpenFlux client and verify
its exit IP. Then test the iPhone on mobile data while restrictions are active.

Only one iPhone mode should be active at a time: upper Start/Test is the
local SOCKS diagnostic; lower Start VPN is the system-wide tunnel. Do not
run both together while testing this single channel.

## Rollback

Run `docker compose stop exit-node` in this release directory. It stops only
the separate OpenFlux pilot. Do not reset the host firewall or restart
Remnawave. Keep the release, image and root-only channel file for diagnosis.

## Verified deployment: 2026-09-14 (Europe/Minsk)

- Deployed from GitHub commit `07599f2004ed21d0a12a0b688010934251aebd8f`.
  Image ID: `sha256:ae0ac0502a8da54c5d9ca611bd2c6d8ef5cec5e575c9825345750f213636209f`.
- Full Go tests passed on Windows and during the Linux image build. Deployment
  configuration tests passed. Explicit LF attributes fix Windows-to-Linux
  archive conversion; the initial failed build never started a container.
- Independent Windows client -> Volga document -> GASAN US -> HTTPS passed:
  Cloudflare trace reported `162.141.185.219`; example.com returned its expected
  content; DNS-over-HTTPS returned a real IPv4 address. Individual HTTPS probes
  took 0.51-0.88 seconds after transport startup, not a throughput benchmark.
- DNS-over-TLS queries through the tunnel passed with certificate verification
  for Google and Cloudflare. Yandex DoT failed in the local Python probe with
  `unable to get local issuer certificate`; verification was not disabled.
  This does not establish the iPhone's trust-store behavior.
- Initial domain-name probes failed because the workstation's resolver supplied
  fake addresses in `198.18.0.0/15`, correctly denied by the exit policy. Repeating
  with real addresses obtained through encrypted DNS passed.
- All temporary probe clients were stopped before handing the channel to the
  iPhone. The exit container is running without restart or OOM; observed idle
  memory was about 13 MiB. This is not a long-duration stability test.
- Existing Remnawave container ID, start time, PID and zero restart count are
  unchanged; Xray still listens on 443. Existing firewall rules are preserved.
  Docker added only its standard raw-table ingress protection for the new
  bridge container at `172.17.0.2`; there are no published ports or RST rules.
- Root-only pre-deployment snapshot is stored at
  `/opt/hamvpn-openflux-us/backups/pre-openflux/` and was read-back verified.

iPhone handoff: select **VOLGA**, use the owner's same document with the
`disk.yandex.ru` hostname, keep DNS **Default**, stop other VPNs, then use the
lower **Start VPN** button. Test Wi-Fi first, then mobile data with Wi-Fi off.
Do not publish the document URL. iPhone compatibility and operation under active
Russian mobile allowlists still require the owner's test; no all-operator claim.
