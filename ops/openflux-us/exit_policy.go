// SPDX-License-Identifier: GPL-3.0-or-later
// HAMVPN pilot overlay: only public IPv4 destinations may leave the tunnel.
package tunnel

import (
	"net/netip"
	"os"
	"strings"
)

var blockedExitRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func allowedExitAddress(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedExitRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	for _, value := range strings.Fields(os.Getenv("OPENFLUX_DENY_IPS")) {
		denied, err := netip.ParseAddr(value)
		if err != nil || denied.Unmap() == ip {
			return false
		}
	}
	return true
}
