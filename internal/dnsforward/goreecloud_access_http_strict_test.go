package dnsforward

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGoreeCloudAccessSetRejectsAmbiguousHTTPPayload(t *testing.T) {
	server := &Server{logger: slog.Default()}
	tests := []struct{ name, body string }{
		{"unknown member", `{"allowed_clients":[],"disalowed_clients":["192.0.2.1"],"blocked_hosts":[]}`},
		{"trailing object", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[]} {"blocked_hosts":["example.com"]}`},
		{"null body", `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/control/access/set", strings.NewReader(tc.body))
			recorder := httptest.NewRecorder()
			server.handleAccessSet(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("invalid access payload returned HTTP %d, want 400", recorder.Code)
			}
		})
	}
}
