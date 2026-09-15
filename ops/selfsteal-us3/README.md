# Self-steal pilot: USA - 3

Requested scope: the visible host `🇺🇸 США - 3` only, plus its existing hidden
auto-selection counterpart if needed to preserve service on the same node.

- Target node: `GASAN US 2`, address `162.141.185.216`.
- Visible host UUID: `a2302256-68a3-4e3e-8213-5817b0177712`.
- Node UUID: `22ac9320-4762-461d-b877-a9f33b58d492`.
- Intended hostname: `us3.torcalc.ru`; A record, DNS only, TTL 300.
- The current REALITY/raw/443 profile is shared by 15 nodes. Do not modify
  that shared profile in place. The eventual pilot requires an isolated copy
  while preserving existing credentials and checking cached-client compatibility.

## DNS change safety

`dns-record.json` is the desired record. Publish this verified file to GitHub
main before applying it. The preflight lookup found no record at this exact
name. Re-read before creation; never overwrite a different A/AAAA/CNAME record
or a concurrent change. No changes to the apex or other subdomains are allowed.
After creation, re-read the record through the authenticated API and check
public resolvers. Keep the created record ID for an exact rollback. A rollback
would remove only this newly created record after verifying that it still
matches this manifest; no automatic deletion is performed by this change.

The Cloudflare token must stay outside this repository and command output.
An account-scoped token may authorize zone operations while the user-token
verification endpoint rejects it; judge zone access using the actual zone API.

API reference:
https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/

## Current state

DNS declaration prepared; creation is not yet confirmed in this commit.
SSH access remains unavailable: the checked local admin keys were rejected.
No certificate, website, new REALITY profile, host-address or SNI change has
been deployed. A DNS record alone does not make self-steal operational.
