package dnsforward

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Invalid admin API requests can contain private client names and hosts.
// Avoid reflecting policy values back into HTTP error bodies.
func TestGoreeCloudAccessSetHTTPErrorDoesNotEchoClientPolicy(t *testing.T) {
	const marker = "confidential-private-policy-do-not-echo.example"
	server := &Server{logger: slog.Default()}
	body := `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":["` + marker + `","` + marker + `"]}`
	request := httptest.NewRequest(http.MethodPost, "/control/access/set", strings.NewReader(body))
	response := httptest.NewRecorder()

	server.handleAccessSet(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate policy accepted: status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), marker) {
		t.Fatal("private blocked-host policy value echoed in API error")
	}
}
