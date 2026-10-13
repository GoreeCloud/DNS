package dnsforward

import "testing"

// A mapped IPv4 alias must not let overlapping allow and deny CIDRs coexist.
func TestGoreeCloudMappedIPv4SubnetConflicts(t *testing.T) {
	cases := []struct{ allow, deny string }{
		{"192.0.2.0/24", "::ffff:192.0.2.45/128"},
		{"::ffff:192.0.2.0/120", "192.0.2.45"},
		{"192.0.2.45/32", "::ffff:192.0.2.0/120"},
	}
	for _, tc := range cases {
		t.Run(tc.allow+"_"+tc.deny, func(t *testing.T) {
			if _, err := newAccessCtx([]string{tc.allow}, []string{tc.deny}, nil); err == nil {
				t.Fatalf("accepted overlapping access ranges %q and %q", tc.allow, tc.deny)
			}
		})
	}
}

func TestGoreeCloudAdjacentMappedIPv4SubnetsDoNotConflict(t *testing.T) {
	if _, err := newAccessCtx(
		[]string{"192.0.2.0/25"}, []string{"::ffff:192.0.2.128/121"}, nil,
	); err != nil {
		t.Fatalf("disjoint adjacent subnets rejected: %v", err)
	}
}
