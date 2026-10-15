package dnsforward

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestGoreeCloudInvalidAccessHTTPPayloadPreservesPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "null", payload: "null"},
		{name: "second document", payload: `{"allowed_clients":["192.0.2.5"]} {}`},
		{name: "second null", payload: `{"allowed_clients":["192.0.2.5"]} null`},
		{name: "trailing junk", payload: `{"allowed_clients":["192.0.2.5"]} trailing`},
		{name: "bad JSON", payload: `{"allowed_clients":`},
		{name: "blocked host aliases", payload: `{"blocked_hosts":["Example.COM","example.com"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			s.conf.AllowedClients = []string{"192.0.2.42"}
			s.conf.BlockedHosts = []string{"existing.example"}
			req := httptest.NewRequest(http.MethodPost, "/control/access/set", strings.NewReader(tc.payload))
			w := httptest.NewRecorder()
			s.handleAccessSet(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("HTTP status %d; want 400", w.Code)
			}
			if !slices.Equal(s.conf.AllowedClients, []string{"192.0.2.42"}) ||
				!slices.Equal(s.conf.BlockedHosts, []string{"existing.example"}) {
				t.Fatalf("invalid request modified access configuration")
			}
			if s.access != nil {
				t.Fatal("invalid request installed a new access manager")
			}
		})
	}
}
