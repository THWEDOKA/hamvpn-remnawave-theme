# HAMVPN: three ClientHello test variants

Scope: goszapravki.com only. Never use dom.gigaruss.com (a different owner).
Create independent clones of Germany Powerful, Poland Powerful and Sweden;
preserve original Hosts, profiles, routes, keys and users. Do not add the variants
to the automatic selection pool. Keep Firefox. Existing source REALITY profiles
already allow old clients (`minClientVer: 0.0.0`); this Host-only experiment does
not rewrite shared profiles to enforce a new minimum or alter existing clients.

Source supplied by the user: https://pastebin.com/tuv9BiG7. Its `interval` key is
not the FinalMask fragment key in Xray v26.3.27. That implementation uses `delay`:
https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go
Preserve 10–20 byte length, `tlshello` and 10–20 ms delay with the correct key.
Newer versions can have another schema: validate with the actual client core.

Only Xray JSON carries this experiment. Exclude MIHOMO/CLASH/STASH/SINGBOX and
XRAY_BASE64 to avoid fake fragmentation tests in clients/formats that omit it.
Koala retains its original hosts unchanged. Snapshot all Hosts privately before
creation; compare originals afterwards and keep the created UUIDs for rollback.
Rollback deletes only the three operation-owned clones, after checking their
identity/content, and restores only this operation's subscription-page card.

Verify the actual JSON export with a temporary restricted test account and the
official pinned client core, three HTTPS requests and output IP per variant.
Delete that account afterwards. TCP reachability alone is not an acceptance
test. Success outside an affected Russian network does not prove DPI bypass;
the operator-specific user test remains necessary. Tiny fragments may add
handshake latency, and do not bypass a full IP/port block.
