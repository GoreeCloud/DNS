package dnsforward

import "testing"

func TestAccessSetRejectsZoneAliases(t *testing.T) {
	cases := []struct {
		name string
		allowed []string
		denied []string
		reject bool
	}{
		{"duplicate allowed aliases", []string{"fe80::1%eth0", "fe80::1%eth1"}, nil, true},
		{"duplicate denied aliases", nil, []string{"fe80::2", "fe80::2%eth0"}, true},
		{"conflicting aliases", []string{"fe80::3%eth0"}, []string{"fe80::3%eth1"}, true},
		{"distinct IPs", []string{"fe80::4%eth0"}, []string{"fe80::5%eth1"}, false},
		{"distinct IDs", []string{"client-one"}, []string{"client-two"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessSet(&accessListJSON{
				AllowedClients: tc.allowed,
				DisallowedClients: tc.denied,
			})
			if (err != nil) != tc.reject {
				t.Fatalf("validation error=%v, expected rejection=%v", err, tc.reject)
			}
		})
	}
}
