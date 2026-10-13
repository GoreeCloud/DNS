package dnsforward

import (
	"net/netip"
	"testing"
)

func TestGoreeCloudBroadMappedNetworkMatchesNativeIPv4(t *testing.T) {
	const prefix = "::ffff:0.0.0.0/95"
	native := netip.MustParseAddr("192.0.2.45")
	mapped := netip.MustParseAddr("::ffff:192.0.2.45")
	denied, err := newAccessCtx(nil, []string{prefix}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{native, mapped} {
		if blocked, _ := denied.isBlockedIP(ip); !blocked {
			t.Errorf("broad mapped denial missed %s", ip)
		}
	}
	allowed, err := newAccessCtx([]string{prefix}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []netip.Addr{native, mapped} {
		if blocked, _ := allowed.isBlockedIP(ip); blocked {
			t.Errorf("broad mapped allow rule missed %s", ip)
		}
	}
}

func TestGoreeCloudBroadMappedNetworkConflictsWithNativeIPv4(t *testing.T) {
	for _, tc := range []struct{ allow, deny string }{
		{"192.0.2.0/24", "::ffff:0.0.0.0/95"},
		{"::ffff:0.0.0.0/95", "192.0.2.0/24"},
	} {
		if _, err := newAccessCtx([]string{tc.allow}, []string{tc.deny}, nil); err == nil {
			t.Errorf("overlapping allowed and denied networks accepted: %s, %s", tc.allow, tc.deny)
		}
	}
}

func TestGoreeCloudBroadMappedOverlapOrdering(t *testing.T) {
	for _, tc := range []struct{ allow, deny []string }{
		{[]string{"::1", "::ffff:0.0.0.0/95"}, []string{"192.0.2.45"}},
		{[]string{"192.0.2.45"}, []string{"::1", "::ffff:0.0.0.0/95"}},
	} {
		if _, err := newAccessCtx(tc.allow, tc.deny, nil); err == nil {
			t.Errorf("cross-family overlap not rejected")
		}
	}
}
