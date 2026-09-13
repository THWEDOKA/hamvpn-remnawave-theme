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

Status: deployment/testing pending; no availability or all-operator claim.
