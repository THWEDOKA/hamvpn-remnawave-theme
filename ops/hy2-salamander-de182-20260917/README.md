# Germany 3: Hysteria2 + Salamander pilot on UDP/8443

One additive owner-requested alternative on existing `217.60.68.182` /
`de182.torcalc.ru`. Keep VLESS/TLS TCP443, plain HY2 UDP443, XHTTP and all
existing hosts/auto candidates unchanged. Reuse the certificate and renewal
process. This is not a reinstall, certificate migration or fleet-wide change.

The operator generates a random 32-byte Salamander secret only on the panel.
It remains in root-only state and the panel config/host. The host's `finalMask`
exports the identical `finalmask.udp` setting into the authenticated subscriber's
client config. This masking key is shared by authorized subscribers; it is not
the per-user VPN credential. Do not put either kind of credential in Git/logs.

New visible entry: `🇩🇪 Германия — 3 · HY2 Salamander`. No auto-pool tag or
hidden counterpart. UDP8443 is distinct from nginx's loopback TCP8443.
QUIC/TLS and certificate verification remain active beneath the masking layer.

Publish a tested commit to GitHub main before deployment. LF-preserved archive
must include this folder, `ops/selfsteal-us3/panel_api.py`,
`ops/selfsteal-ru214/panel.py`, `ops/xhttp-de182-20260917/common.py` and
`ops/selfsteal-eu-20260917/de182/tls-hy2-config.json` (last used only by tests).
Verify archive hashes on both hosts. Run:

1. Panel snapshot; privately pipe candidate JSON over verified SSH into node-test.
2. Return only the sanitized node-test proof to panel accept-test.
3. Panel create-test / before-probes / apply / after-probes / verify.
4. Publish / subscription / negative-test / subscription; node-verify.
5. Panel cleanup / finish; verify the 25-minute rollback timer is inactive.

No password is printed by these commands. Never print the candidate, host or
subscription JSON: they contain the live masking or user credentials. A node
config-test failure stores its diagnostic output root-only and does not deploy.
An API failure retains the rollback timer. If verification fails, run rollback
to remove only the new inbound/entitlement and disable the new host. Compare
guards refuse unrelated concurrent changes. Protected state and backups stay
under `/root/hamvpn-hy2-salamander-de182-20260917`, mode 0700/files 0600.

Verify positive authenticated traffic and correct exit IP, then rejection of
the same valid account when the mask is removed. Verify actual Happ subscription
settings, old protocols, website and unchanged firewall/renewal configs.
External success does not establish access through a Russian operator; owner
testing on the affected connection remains necessary.

Sources: [Hysteria obfuscation](https://v2.hysteria.network/docs/advanced/Full-Client-Config/#obfuscation),
[Xray FinalMask](https://xtls.github.io/en/config/transports/finalmask.html#salamander).
