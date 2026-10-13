package dnsforward

import (
	"net/netip"
	"testing"
)

func TestGoreeCloudMappedAccessPrefixBoundaries(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"::ffff:0.0.0.0/96", "0.0.0.0/0"},
		{"::ffff:192.0.2.45/120", "192.0.2.0/24"},
		{"::ffff:192.0.2.45/128", "192.0.2.45/32"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range cases {
		if got := normalizeAccessPrefix(netip.MustParsePrefix(tc.raw)).Masked().String(); got != tc.want {
			t.Errorf("%q normalized to %q, want %q", tc.raw, got, tc.want)
		}
	}
}
