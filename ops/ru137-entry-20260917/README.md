# Rejected entry preflight — no deployment

On 2026-09-17 the proposed entry 193.233.90.137 failed direct HTTPS checks to
the four selected exits. A read-only SSH relay trial through DE94 transferred
256 KiB intact and completed verified TLS requests to each exit. This was a
transport test, not a user VPN or egress-IP test. The owner rejected the extra
shared DE94 transit and supplied a replacement entry. No DNS, node, panel,
service or persistent tunnel was deployed on 193.233.90.137.

The diagnostic script uses an interactive password prompt and local SSH keys;
no private key is copied to either remote server. It is retained as evidence,
not as an installer or authorization to retry the rejected topology.
