package dnsforward

import "testing"

func TestAccessNetworkKeysCanonicalizeWithoutChangingStoredRules(t *testing.T) {
	raw := []string{"192.0.2.47/24", "2001:db8:1234::aa/64", "fe80::7%eth0", "device-123"}
	got := normalizeAccessClientKeys(raw)
	want := []string{"192.0.2.0/24", "2001:db8:1234::/64", "fe80::7", "device-123"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("normalized value at %d = %q, want %q", i, got[i], want[i])
		}
	}
	if raw[0] != "192.0.2.47/24" || raw[1] != "2001:db8:1234::aa/64" || raw[2] != "fe80::7%eth0" {
		t.Fatal("access policy normalization changed configured source entries")
	}
}

func TestAccessNetworkKeysValidateCIDRConflicts(t *testing.T) {
	tests := []struct {
		name string
		allowed, denied []string
		reject bool
	}{
		{"equivalent allowed network", []string{"192.0.2.0/24", "192.0.2.50/24"}, nil, true},
		{"equivalent denied IPv6 network", nil, []string{"2001:db8:12::/64", "2001:db8:12::5/64"}, true},
		{"conflicting canonical subnet", []string{"192.0.2.100/24"}, []string{"192.0.2.0/24"}, true},
		{"distinct subnet", []string{"192.0.2.0/25"}, []string{"192.0.2.128/25"}, false},
		{"client ID distinction", []string{"device-A"}, []string{"device-B"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessSet(&accessListJSON{AllowedClients: tc.allowed, DisallowedClients: tc.denied})
			if (err != nil) != tc.reject {
				t.Errorf("validation error=%v, want rejected=%v", err, tc.reject)
			}
		})
	}
}
