package dnsforward

import "testing"

func TestGoreeCloudBlockedHostCaseAliases(t *testing.T) {
	for _, entries := range [][]string{
		{"Example.COM", "example.com"},
		{"Site.Example", "site.example"},
	} {
		if err := validateAccessSet(&accessListJSON{BlockedHosts: entries}); err == nil {
			t.Fatalf("duplicate blocked-host entries accepted: %q", entries)
		}
	}
	original := []string{"Example.COM", "Different.example"}
	if err := validateAccessSet(&accessListJSON{BlockedHosts: original}); err != nil {
		t.Fatalf("distinct entries rejected: %v", err)
	}
	if original[0] != "Example.COM" {
		t.Fatal("validation unexpectedly changed the original entry")
	}
}
