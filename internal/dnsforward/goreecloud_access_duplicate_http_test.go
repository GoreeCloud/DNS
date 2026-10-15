package dnsforward

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestGoreeCloudAccessSetRejectsDuplicateJSONFields(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"duplicate allowed", `{"allowed_clients":["192.0.2.10"],"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[]}`},
		{"case variant", `{"allowed_clients":["192.0.2.10"],"ALLOWED_CLIENTS":[],"disallowed_clients":[],"blocked_hosts":[]}`},
		{"duplicate blocked hosts", `{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":["example.com"],"blocked_hosts":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{logger: slog.Default()}
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/control/access/set", strings.NewReader(tc.body))
			s.handleAccessSet(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("duplicate access field returned %d; want 400", recorder.Code)
			}
		})
	}
}

func TestGoreeCloudStrictAccessSetPreservesValidPayload(t *testing.T) {
	input := `{"ALLOWED_CLIENTS":["192.0.2.10"],"disallowed_clients":["192.0.2.11"],"blocked_hosts":["example.com"]}`
	list, err := decodeStrictAccessSet(strings.NewReader(input))
	if err != nil {
		t.Fatalf("valid access policy rejected: %v", err)
	}
	if !reflect.DeepEqual(list.AllowedClients, []string{"192.0.2.10"}) ||
		!reflect.DeepEqual(list.DisallowedClients, []string{"192.0.2.11"}) ||
		!reflect.DeepEqual(list.BlockedHosts, []string{"example.com"}) {
		t.Fatalf("valid policy was not preserved: %#v", list)
	}
}
