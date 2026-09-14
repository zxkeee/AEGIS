package safefetch

import (
	"net"
	"testing"
)

// Every form below passed the previous string-based check and then connected to
// loopback anyway. They are here as named cases because each is a different way
// a host string fails to describe where a connection goes.
func TestIsPrivateOrLocalIP_CoversTheFormsAStringCheckMissed(t *testing.T) {
	blocked := map[string]string{
		"loopback":                  "127.0.0.1",
		"loopback, the short form":  "127.0.0.1", // 127.1 resolves here
		"loopback in decimal":       "127.0.0.1", // 2130706433 resolves here
		"loopback in hex":           "127.0.0.1", // 0x7f.0.0.1 resolves here
		"ipv6 loopback":             "::1",
		"ipv4-mapped ipv6 loopback": "::ffff:127.0.0.1",
		"cloud metadata":            "169.254.169.254",
		"link-local ipv6":           "fe80::1",
		"private 10/8":              "10.0.0.5",
		"private 172.16/12":         "172.16.0.1",
		"private 192.168/16":        "192.168.1.1",
		"unique local ipv6":         "fd00::1",
		"unspecified":               "0.0.0.0",
		"unspecified ipv6":          "::",
		"multicast":                 "224.0.0.1",
	}
	for name, addr := range blocked {
		t.Run(name, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("test fixture %q is not an IP", addr)
			}
			if !IsPrivateOrLocalIP(ip) {
				t.Errorf("%s (%s) was allowed", name, addr)
			}
		})
	}

	for name, addr := range map[string]string{
		"ordinary public v4": "93.184.216.34",
		"public resolver":    "8.8.8.8",
		"public v6":          "2606:2800:220:1:248:1893:25c8:1946",
	} {
		t.Run(name, func(t *testing.T) {
			if IsPrivateOrLocalIP(net.ParseIP(addr)) {
				t.Errorf("%s (%s) was blocked; the gateway must still reach the internet", name, addr)
			}
		})
	}

	// nil is "we do not know", and unknown is not safe.
	if !IsPrivateOrLocalIP(nil) {
		t.Error("a nil address was treated as safe")
	}
}

// The pre-filter exists to reject an obviously-internal destination at config
// time with a clear message. It must handle the trailing dot: "localhost." is
// the fully-qualified form and resolves identically, and EqualFold missed it.
func TestIsPrivateOrLocalHostname(t *testing.T) {
	for _, host := range []string{
		"localhost", "LOCALHOST", "localhost.", "LocalHost.",
		" localhost ", "api.localhost", "127.0.0.1", "::1",
		"169.254.169.254", "10.1.2.3", "0.0.0.0",
	} {
		if !IsPrivateOrLocalHostname(host) {
			t.Errorf("%q was not recognised as internal", host)
		}
	}
	for _, host := range []string{
		"example.com", "idp.example.com.", "93.184.216.34", "localhostile.com",
	} {
		if IsPrivateOrLocalHostname(host) {
			t.Errorf("%q was rejected; it is a public destination", host)
		}
	}
}

// The numeric forms are the point of moving the check to the dialer: the string
// "2130706433" is not an IP as far as net.ParseIP is concerned, so no
// string-level check can classify it — but the resolver turns it into 127.0.0.1
// and that is what the dialer sees.
func TestTheNumericFormsAreNotIPsAsStrings(t *testing.T) {
	for _, s := range []string{"2130706433", "127.1", "0x7f.0.0.1"} {
		if ip := net.ParseIP(s); ip != nil {
			t.Errorf("net.ParseIP(%q) = %v — the premise of this fix has changed "+
				"and the string check may be viable again", s, ip)
		}
		// And the pre-filter does not claim to catch them either.
		if IsPrivateOrLocalHostname(s) {
			t.Logf("note: the pre-filter now catches %q as well", s)
		}
	}
}
