// SPDX-License-Identifier: GPL-3.0-or-later
package tunnel

import "testing"

func TestPilotExitDeniesInternalAndSpecialAddresses(t *testing.T) {
	t.Setenv("OPENFLUX_DENY_IPS", "162.141.185.219 62.144.56.247")
	for _, ip := range []string{
		"127.0.0.1", "10.1.2.3", "172.17.0.1", "192.168.0.1", "169.254.169.254",
		"0.0.0.0", "0.1.2.3", "100.64.0.1", "224.0.0.1", "240.0.0.1",
		"192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
		"255.255.255.255", "::1", "::ffff:127.0.0.1", "not-an-ip",
		"162.141.185.219", "62.144.56.247",
	} {
		if allowedExitAddress(ip) {
			t.Errorf("allowed protected address %s", ip)
		}
	}
}

func TestPilotExitAllowsPublicAddresses(t *testing.T) {
	t.Setenv("OPENFLUX_DENY_IPS", "162.141.185.219")
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "77.88.55.242", "::ffff:1.1.1.1"} {
		if !allowedExitAddress(ip) {
			t.Errorf("blocked public address %s", ip)
		}
	}
}

func TestPilotExitFailsClosedOnInvalidConfiguration(t *testing.T) {
	t.Setenv("OPENFLUX_DENY_IPS", "invalid")
	if allowedExitAddress("1.1.1.1") {
		t.Fatal("invalid policy did not fail closed")
	}
}
