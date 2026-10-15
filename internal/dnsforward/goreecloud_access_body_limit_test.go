package dnsforward

import (
	"strings"
	"testing"
)

func TestGoreeCloudAccessSetBodySizeIsBounded(t *testing.T) {
	const oversizedPadding = 2 * 1024 * 1024
	body := strings.Repeat(" ", oversizedPadding) + `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[]}`
	if _, err := decodeStrictAccessSet(strings.NewReader(body)); err == nil {
		t.Fatal("oversized JSON access-list update was accepted")
	}
}

func TestGoreeCloudAccessSetSmallJSONStillAccepted(t *testing.T) {
	body := `{"allowed_clients":["192.0.2.1"],"disallowed_clients":[],"blocked_hosts":[]}`
	list, err := decodeStrictAccessSet(strings.NewReader(body))
	if err != nil {
		t.Fatalf("normal access list rejected: %v", err)
	}
	if len(list.AllowedClients) != 1 || list.AllowedClients[0] != "192.0.2.1" {
		t.Fatalf("valid access-list payload changed: %#v", list)
	}
}
