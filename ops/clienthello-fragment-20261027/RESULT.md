# Verified deployment — 2026-10-27

Panel: goszapravki.com. Created three independent variants:

- 🇩🇪 Тест фрагментации — DE (Germany Powerful source).
- 🇵🇱 Тест фрагментации — PL (Poland Powerful source).
- 🇸🇪 Тест фрагментации — SE (Sweden source).

Original Hosts were compared byte-for-byte through the API and remained unchanged.
No profile, DNS, port, server process or route was changed for this experiment.
FinalMask is emitted in each actual Xray JSON outbound, with Firefox and 10–20
byte TLSHello fragments / 10–20 ms delay. The three variants are absent from the
actual mihomo export. AUTO_BASE_POOL/AUTO_WHITE_POOL membership was removed from
clones only; the actual automatic-selection JSON contains no experimental masks.

Official Xray v26.3.27 archive was verified against its published SHA-256 digest.
Each exported VLESS outbound passed config validation and three HTTPS 204
requests. Probe-only routing forced the IP-check request through VLESS because
the production template intentionally sends IP-check domains directly. Measured
egress: DE 143.20.148.183, PL 143.20.148.184, SE 143.246.193.45.

The temporary one-hour test account was deleted. Timed rollback was cancelled
after API/export/client checks. Private snapshots and probe evidence remain on
the bot server under the operation-owned root-only release directory; no user
links, tokens or private keys are published here.

This verifies protocol connectivity from the probe, not bypass of every Russian
operator's DPI. An affected-network check in an Xray JSON-capable app remains
necessary. Koala/mihomo continues using the original unmodified Hosts.
