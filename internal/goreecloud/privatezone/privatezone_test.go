package privatezone

import "testing"

func TestMatcherHonorsWholeLabelsAndCase(t *testing.T) {
	m, err := NewMatcher([]string{"LAN.", "home.arpa", "mesh.internal", "lan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"router.lan", true},
		{"router.LAN.", true},
		{"lan", true},
		{"_http._tcp.printer.home.arpa.", true},
		{"node.mesh.internal", true},
		{"mesh.internal", true},
		{"public.example", false},
		{"evillan", false},
		{"lan.evil.test", false},
		{"examplelan", false},
		{"service.mesh.internal.evil.test", false},
		{"example.internal.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := m.IsPrivate(tc.name)
			if err != nil || got != tc.want {
				t.Fatalf("IsPrivate(%q) = %v, %v; want %v", tc.name, got, err, tc.want)
			}
		})
	}
}

func TestMatcherRejectsAmbiguousConfiguration(t *testing.T) {
	for _, zones := range [][]string{
		nil, {},
		{"com"}, {"example.com"},
		{"lan.evil.test"}, {"."}, {"lan.."}, {"*.lan"},
		{"home.arpa", "example.com"},
		{"-bad.lan"}, {"bad_.lan"},
	} {
		_, err := NewMatcher(zones)
		if err == nil {
			t.Fatalf("zone config %q unexpectedly accepted", zones)
		}
	}
}

func TestMatcherRejectsMalformedNamesAndUnconfiguredUse(t *testing.T) {
	m, err := NewMatcher([]string{"lan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"", ".", "foo..lan", "foo.lan..", "foo.lan\ninjected",
		" leading.lan", "foo bar.lan", "f\\oo.lan",
		"-router.lan", "router-.lan", "printer_.lan",
	} {
		if matched, err := m.IsPrivate(name); err == nil || matched {
			t.Fatalf("malformed name %q unexpectedly accepted", name)
		}
	}
	if matched, err := (Matcher{}).IsPrivate("host.lan"); err == nil || matched {
		t.Fatal("unconfigured matcher must fail closed")
	}
}
