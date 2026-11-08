# Koala / Firefox / REALITY compatibility investigation — 2026-11-08

Status: cause identified; production configuration changes are **not applied**.

## Verified evidence

- User-approved SSH fingerprints for all six supplied nodes were checked and
  pinned before password authentication. All six SSH logins succeeded.
- Installed Xray is **26.10.31** on REGXA-PL-3 (the original Poland host),
  ALEXHOST-UK-2 and the additional REGXA-PL2, REGXA-PL3 and REGXA-PL4 nodes.
- AEZA-VENA-4 has Xray **26.7.28**. It recovered independently and passes both
  gstatic and Cloudflare HTTPS URL tests in isolated mihomo 1.19.24.
- The original Poland host's actual running configuration was retrieved through
  its existing local Unix control socket without printing its token or config.
  Its client-facing inbound already has `minClientVer: "0.0.0"`; missing version
  compatibility is therefore not the explanation for that node's failure.
- Fresh subscription public keys, short IDs and SNI match the panel profiles.
  Isolated mihomo 1.19.24 and 1.19.33 reproduce REALITY authentication failures
  with `client-fingerprint: firefox`; working control hosts pass HTTPS requests.
- No active desktop configuration, installed client binary, node image, routing,
  user account or production profile was changed during this investigation.

## Upstream constraint

Xray 26.10.31 uses REALITY revision `83f621788ca8`. Its server rejects a
ClientHello without an X25519MLKEM768 key share before an optional X25519 share.
This check precedes client-version authentication. Changing `minClientVer`
alone does not bypass it.

Mihomo 1.19.33 uses metacubex/utls v1.8.8, where `firefox` selects
`HelloFirefox_120`. That preset contains X25519/P256 key shares, not the
hybrid share required by this REALITY server. Merely upgrading to this mihomo
release does not resolve the Firefox mismatch.

Primary sources:

- <https://github.com/XTLS/Xray-core/blob/v26.10.31/go.mod>
- <https://github.com/XTLS/REALITY/blob/83f621788ca8/tls.go#L203-L264>
- <https://github.com/MetaCubeX/mihomo/blob/v1.19.33/go.mod>
- <https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/tls/utls.go>
- <https://github.com/MetaCubeX/utls/blob/v1.8.8/u_common.go>
- <https://github.com/MetaCubeX/utls/blob/v1.8.8/u_parrots.go>

Do not silently switch to Chrome, downgrade Xray, disable REALITY authentication
or replace working endpoints. A parallel VLESS+TLS canary preserving Firefox
and existing REALITY endpoints requires the owner's explicit scope decision.
Availability from one test network is not proof of reachability from all ISPs.
