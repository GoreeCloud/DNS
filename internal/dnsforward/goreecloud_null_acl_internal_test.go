package dnsforward

import (
	"encoding/json"
	"strings"
	"testing"
)

// A JSON null access-list request must be rejected instead of causing a panic
// when the HTTP handler validates the decoded pointer.
func TestGoreeCloudNilAccessListRejected(t *testing.T) {
	list := &accessListJSON{}
	if err := json.NewDecoder(strings.NewReader("null")).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if list != nil {
		t.Fatal("expected JSON null to decode into a nil pointer")
	}
	if err := validateAccessSet(list); err == nil {
		t.Fatal("nil access list must not be accepted")
	}
}
