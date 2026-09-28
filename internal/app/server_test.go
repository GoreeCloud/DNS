package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusEndpoints(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status string
	}{{"/healthz", "ok"}, {"/readyz", "ready"}} {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := strings.TrimSpace(rec.Body.String())
			if !strings.Contains(body, `"service":"goreecloud-dns"`) || !strings.Contains(body, `"status":"`+tc.status+`"`) {
				t.Fatalf("unexpected body %q", body)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing nosniff")
			}
		})
	}
}

func TestStatusEndpointsRejectMutationMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", strings.NewReader("ignored"))
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestHeadHasNoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodHead, "/readyz", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body length = %d, want 0", rec.Body.Len())
	}
}
