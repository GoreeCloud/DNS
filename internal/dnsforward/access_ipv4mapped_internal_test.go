package dnsforward

import (
	"net/netip"
	"testing"
)

func TestGoreeCloudMappedIPv4IdentityRegression(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:192.0.2.45")
	deniedExact, err := newAccessCtx(nil, []string{"192.0.2.45"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := deniedExact.isBlockedIP(mapped); !blocked {
		t.Error("native IPv4 deny rule did not match mapped IPv4 alias")
	}
	deniedPrefix, err := newAccessCtx(nil, []string{"192.0.2.0/24"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := deniedPrefix.isBlockedIP(mapped); !blocked {
		t.Error("native IPv4 CIDR deny rule did not match mapped IPv4 alias")
	}
	allowed, err := newAccessCtx([]string{"192.0.2.45"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := allowed.isBlockedIP(mapped); blocked {
		t.Error("native IPv4 allow rule did not recognize mapped IPv4 alias")
	}
}

func TestGoreeCloudMappedIPv4CrossListConflictRegression(t *testing.T) {
	list := &accessListJSON{
		AllowedClients:    []string{"192.0.2.45"},
		DisallowedClients: []string{"::ffff:192.0.2.45"},
	}
	if err := validateAccessSet(list); err == nil {
		t.Fatal("native/mapped IPv4 alias conflict was not rejected")
	}
}

func TestGoreeCloudMappedIPv4NetworkRule(t *testing.T) {
	denied, err := newAccessCtx(nil, []string{"::ffff:192.0.2.0/120"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.45", "::ffff:192.0.2.45"} {
		if blocked, _ := denied.isBlockedIP(netip.MustParseAddr(ip)); !blocked {
			t.Errorf("mapped rule did not match %s", ip)
		}
	}
	conflicting := &accessListJSON{AllowedClients: []string{"192.0.2.0/24"}, DisallowedClients: []string{"::ffff:192.0.2.0/120"}}
	if err := validateAccessSet(conflicting); err == nil {
		t.Fatal("mapped and native CIDR conflict accepted")
	}
}

func TestGoreeCloudLegacyBroadMappedNetwork(t *testing.T) {
	denied, err := newAccessCtx(nil, []string{"::ffff:192.0.2.0/95"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if blocked, _ := denied.isBlockedIP(netip.MustParseAddr("::ffff:192.0.2.45")); !blocked {
		t.Fatal("legacy broad IPv6 prefix no longer matches mapped peer")
	}
}
