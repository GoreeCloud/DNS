package dnsforward

import "testing"

func TestAccessSetRejectsZoneAliases(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		denied  []string
		reject  bool
	}{
		{"duplicate allowed aliases", []string{"fe80::1%eth0", "fe80::1%eth1"}, nil, true},
		{"duplicate denied aliases", nil, []string{"fe80::2", "fe80::2%eth0"}, true},
		{"conflicting aliases", []string{"fe80::3%eth0"}, []string{"fe80::3%eth1"}, true},
		{"distinct IPs", []string{"fe80::4%eth0"}, []string{"fe80::5%eth1"}, false},
		{"distinct IDs", []string{"client-one"}, []string{"client-two"}, false},
		{"duplicate allowed v4 CIDRs", []string{"10.2.0.0/16", "10.2.3.4/16"}, nil, true},
		{"duplicate denied v6 CIDRs", nil, []string{"fd42::/64", "fd42::123/64"}, true},
		{"conflicting v4 CIDR aliases", []string{"192.0.2.1/24"}, []string{"192.0.2.0/24"}, true},
		{"conflicting v6 CIDR aliases", []string{"2001:db8:100::1/64"}, []string{"2001:db8:100::/64"}, true},
		{"separate v4 ranges", []string{"10.2.0.0/16"}, []string{"10.3.0.0/16"}, false},
		{"different mask lengths", []string{"10.2.0.0/16"}, []string{"10.2.0.0/24"}, false},
		{"distinct client IDs remain unchanged", []string{"client-123"}, []string{"client-456"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessSet(&accessListJSON{
				AllowedClients:    tc.allowed,
				DisallowedClients: tc.denied,
			})
			if (err != nil) != tc.reject {
				t.Fatalf("validation error=%v, expected rejection=%v", err, tc.reject)
			}
		})
	}
}
