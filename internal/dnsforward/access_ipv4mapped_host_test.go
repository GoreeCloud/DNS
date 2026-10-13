package dnsforward

import (
	"net/netip"
	"testing"
)

func TestGoreeCloudExactMappedHostRule(t *testing.T) {
	host := netip.MustParseAddr("192.0.2.45")
	mapped := netip.MustParseAddr("::ffff:192.0.2.45")
	neighbor := netip.MustParseAddr("192.0.2.46")
	for _, rule := range []string{"::ffff:192.0.2.45", "::ffff:192.0.2.45/128"} {
		t.Run(rule, func(t *testing.T) {
			denied, err := newAccessCtx(nil, []string{rule}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, ip := range []netip.Addr{host, mapped} {
				if blocked, _ := denied.isBlockedIP(ip); !blocked {
					t.Errorf("%s failed to deny %s", rule, ip)
				}
			}
			if blocked, _ := denied.isBlockedIP(neighbor); blocked {
				t.Fatal("adjacent host denied")
			}
			allowed, err := newAccessCtx([]string{rule}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, ip := range []netip.Addr{host, mapped} {
				if blocked, _ := allowed.isBlockedIP(ip); blocked {
					t.Errorf("%s failed to allow %s", rule, ip)
				}
			}
			if blocked, _ := allowed.isBlockedIP(neighbor); !blocked {
				t.Fatal("adjacent host allowed")
			}
		})
	}
}
