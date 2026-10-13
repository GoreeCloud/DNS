package dnsforward

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestAccessRangeOverlap(t *testing.T) {
	cases := []struct {
		name string
		allow, deny []string
		conflict bool
	}{
		{"IPv4 host inside denied subnet", []string{"192.0.2.17"}, []string{"192.0.2.0/24"}, true},
		{"IPv4 denied host inside allowed subnet", []string{"198.51.100.0/24"}, []string{"198.51.100.44"}, true},
		{"IPv6 nested subnets", []string{"2001:db8:1::/48"}, []string{"2001:db8:1::100/120"}, true},
		{"zoned IPv6 identity", []string{"fe80::3%eth0"}, []string{"fe80::3/128"}, true},
		{"distinct IPv4 subnets", []string{"192.0.2.0/25"}, []string{"192.0.2.128/25"}, false},
		{"different address families", []string{"192.0.2.1"}, []string{"2001:db8::/32"}, false},
		{"client IDs remain independent", []string{"device-alpha"}, []string{"device-beta"}, false},
		{"no deny entries", []string{"10.8.0.0/16"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessRangeOverlap(tc.allow, tc.deny)
			if (err != nil) != tc.conflict {
				t.Fatalf("overlap error=%v expected=%v", err, tc.conflict)
			}
		})
	}
}

func TestAccessRangeSortedSweepAgainstReference(t *testing.T) {
	random := rand.New(rand.NewSource(81))
	for iter := 0; iter < 300; iter++ {
		allowed := make([]string, 0, 12)
		denied := make([]string, 0, 12)
		for i := 0; i < 12; i++ {
			makeRange := func() string {
				if random.Intn(2) == 0 {
					return fmt.Sprintf("10.%d.%d.%d/%d", random.Intn(8), random.Intn(256), random.Intn(256), 16+random.Intn(17))
				}
				return fmt.Sprintf("2001:db8:%x:%x::/%d", random.Intn(16), random.Intn(16), 48+random.Intn(33))
			}
			allowed = append(allowed, makeRange())
			denied = append(denied, makeRange())
		}
		expected := false
		for _, rawAllowed := range allowed {
			a, _ := accessAddressRange(rawAllowed)
			for _, rawDenied := range denied {
				d, _ := accessAddressRange(rawDenied)
				if a.Contains(d.Addr()) || d.Contains(a.Addr()) {
					expected = true
				}
			}
		}
		if got := validateAccessRangeOverlap(allowed, denied) != nil; got != expected {
			t.Fatalf("case %d: overlap=%v expected=%v", iter, got, expected)
		}
	}
}

func TestAccessRangeThousandsOfEntries(t *testing.T) {
	allowed, denied := make([]string, 0, 4096), make([]string, 0, 4096)
	for i := 0; i < 4096; i++ {
		allowed = append(allowed, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		denied = append(denied, fmt.Sprintf("172.%d.%d.0/24", 16+i/256, i%256))
	}
	if err := validateAccessRangeOverlap(allowed, denied); err != nil {
		t.Fatal(err)
	}
	denied = append(denied, "10.15.255.10")
	if err := validateAccessRangeOverlap(allowed, denied); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("missed overlap at end of access rules: %v", err)
	}
}
