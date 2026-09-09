# HAMVPN UK bypass firewall repair — 2026-09-09

## Confirmed fault

The HAMVPN host «🇬🇧 Обход все операторы» uses the existing route:

`client → 188.225.62.121:9443 → 51.194.229.165:7443 → Internet`.

The UK node `util-gb-2` was connected to the panel and Xray was listening on
TCP/7443. UFW denied incoming traffic by default and allowed only TCP/22,
TCP/443, and the panel's TCP/2222. There was no rule for TCP/7443.

Packet capture on the UK server confirmed arriving SYN packets from the
existing Russian bridge, `188.225.62.121`, destined to TCP/7443, without a
response. This located the confirmed failure on the UK firewall. The
Russian server is administered separately and was not modified.

## Applied change

```sh
ufw allow proto tcp from 188.225.62.121 to any port 7443 comment 'HAMVPN GB existing RU bridge'
```

Only this existing bridge can reach the UK client listener. Port 7443 was
not opened globally. The obsolete but pre-existing port 443 rule was left
untouched to keep the change narrowly scoped.

The exact netfilter comparison showed one added IPv4 rule and zero removed
rules. `/etc/ufw/user6.rules` was byte-identical to its backup. The change is
stored in `/etc/ufw/user.rules`; UFW remains enabled for boot.

## Verified results

- Five automated tests passed locally and on the server.
- TLS through the unchanged Russian endpoint `188.225.62.121:9443` succeeded
  with TLS 1.3, certificate verification enabled, and verified peername
  `google.com`. Before the fix, the same endpoint timed out.
- The panel kept the UK node connected, with no status error and the same
  profile `polandbs` (`447f780a-3a46-4f7e-ba55-74e80f4f2dfb`).
- The final observation found 615 established bridge connections, about
  398 MB acknowledged toward the bridge and 22 MB received on those open
  connections.
- Authenticated per-user traffic records for this node were updated for
  78 users in the preceding ten minutes; the latest update was
  `2026-09-09T11:45:45.044`. This is actual user traffic, not just TLS fallback.
- The node container remained `remnawave/node:2.7.0`, with its original
  `StartedAt=2026-08-27T21:50:05.111604792Z`, restart count zero. Neither the
  node container nor its Xray process was restarted for the repair.
- No panel profiles, hosts, subscriptions, user entitlements, or remote
  bridge settings were changed.

A separate synthetic HTTP-over-VLESS check was not completed: the existing
diagnostic account has no internal squads and is not loaded on this inbound.
An earlier runtime-user attempt was rejected by the internal mTLS API before
any user could be created. That protection was not weakened. No test account
was added, no existing account was changed, and no temporary test directories
remained. The unused experimental probe was removed from the final code state.

These checks verify the server-side route. They do not establish availability
under every Russian operator's current mobile filtering conditions.

## Canonical release and backup

The tested repair was published to GitHub before applying it, at revision
`d6c34d3871e8a29f1fc08a01b3e6434c10162b17`.

Root-only backup on the UK server:
`/root/hamvpn-uk-bypass-backups/firewall-20260909-57e5x40d`.

It contains the prior UFW configuration, IPv4/IPv6 firewall snapshots and
status, with a verified SHA-256 manifest. No SSH credentials or internal node
TLS material are included in this repository or the public update journal.

## Reapply safely

```sh
python3 test_repair_firewall.py
python3 repair_firewall.py          # Read-only preflight and planned command
python3 repair_firewall.py --apply  # Verified backup, then scoped UFW rule
```

Preflight refuses a different server, inactive UFW, or missing TCP/7443
listener. UFW skips an already existing identical rule.

Rollback only this task's rule, without restoring a whole live firewall dump:

```sh
ufw delete allow proto tcp from 188.225.62.121 to any port 7443 comment 'HAMVPN GB existing RU bridge'
```

This restores the prior restriction and therefore also restores the known
outage for new bridge connections. No broad firewall reset is required.
