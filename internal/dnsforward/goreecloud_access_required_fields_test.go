package dnsforward

import (
	"strings"
	"testing"
)

// /control/access/set replaces all three lists, so missing members must not
// implicitly erase an existing allow/deny/block policy.
func TestGoreeCloudAccessSetRequiresAllPolicyFields(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"missing allowed", `{"disallowed_clients":[],"blocked_hosts":[]}`},
		{"missing disallowed", `{"allowed_clients":[],"blocked_hosts":[]}`},
		{"missing blocked", `{"allowed_clients":[],"disallowed_clients":[]}`},
		{"null allowed", `{"allowed_clients":null,"disallowed_clients":[],"blocked_hosts":[]}`},
		{"null disallowed", `{"allowed_clients":[],"disallowed_clients":null,"blocked_hosts":[]}`},
		{"null blocked", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeStrictAccessSet(strings.NewReader(tc.input)); err == nil {
				t.Fatal("incomplete access replacement was accepted")
			}
		})
	}
}

func TestGoreeCloudExplicitEmptyAccessListsAllowed(t *testing.T) {
	input := `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[]}`
	list, err := decodeStrictAccessSet(strings.NewReader(input))
	if err != nil {
		t.Fatalf("explicitly empty access policy rejected: %v", err)
	}
	if list.AllowedClients == nil || list.DisallowedClients == nil || list.BlockedHosts == nil {
		t.Fatal("explicitly present empty arrays were lost")
	}
}
