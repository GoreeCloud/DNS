package dnsforward

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestGoreeCloudInvalidAccessReplacementPreservesExistingPolicy(t *testing.T) {
	server := &Server{logger: slog.Default()}
	server.conf.AllowedClients = []string{"192.0.2.10"}
	server.conf.DisallowedClients = []string{"198.51.100.5"}
	server.conf.BlockedHosts = []string{"original-policy.example"}
	baseline := server.accessListJSON()

	tests := []struct{ name, payload string }{
		{"missing-blocked-hosts", `{"allowed_clients":[],"disallowed_clients":[]}`},
		{"null-blocked-hosts", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":null}`},
		{"missing-allowed-clients", `{"disallowed_clients":[],"blocked_hosts":[]}`},
		{"duplicate-host", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":["duplicate.example","duplicate.example"]}`},
		{"unknown-member", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[],"unexpected":["x"]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/control/access/set", strings.NewReader(tc.payload))
			w := httptest.NewRecorder()
			server.handleAccessSet(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid replacement status=%d, want 400", w.Code)
			}
			if got := server.accessListJSON(); !reflect.DeepEqual(got, baseline) {
				t.Fatalf("rejected access request changed policy: before=%+v after=%+v", baseline, got)
			}
		})
	}
}
