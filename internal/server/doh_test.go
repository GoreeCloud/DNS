package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoHConfigurationFailClosed(t *testing.T) {
	base, _ := testConfig(t)
	disabled, err := New(base)
	if err != nil || disabled.dohTLS != nil {
		t.Fatalf("DoH should be disabled with no configuration: %v", err)
	}
	cert, key, _ := testCertificate(t)
	cases := []struct {
		name  string
		apply func(*Config)
	}{
		{"key without address", func(c *Config) { c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"remote opt-in without address", func(c *Config) { c.DoHAllowRemote = true }},
		{"address without identity", func(c *Config) { c.DoHListen = "127.0.0.1:8443" }},
		{"missing private key", func(c *Config) { c.DoHListen = "127.0.0.1:8443"; c.DoHTLSCertFile = cert }},
		{"invalid port", func(c *Config) { c.DoHListen = "127.0.0.1:99999"; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"wildcard without opt-in", func(c *Config) { c.DoHListen = "0.0.0.0:8443"; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"no host without opt-in", func(c *Config) { c.DoHListen = ":8443"; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"DNS listener conflict", func(c *Config) { c.DoHListen = c.DNSListen; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"API listener conflict", func(c *Config) { c.DoHListen = c.APIListen; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = key }},
		{"missing key file", func(c *Config) { c.DoHListen = "127.0.0.1:8443"; c.DoHTLSCertFile = cert; c.DoHTLSKeyFile = "/missing" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.apply(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("unsafe DoH configuration accepted")
			}
		})
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := base
	cfg.DoHListen, cfg.DoHTLSCertFile, cfg.DoHTLSKeyFile = "127.0.0.1:8443", cert, key
	if _, err := New(cfg); err == nil {
		t.Fatal("world-readable DoH TLS private key accepted")
	}
}

func TestDoHStrictHTTPAndClientACL(t *testing.T) {
	s, _ := testServer(t)
	q := new(dns.Msg)
	q.SetQuestion("blocked.test.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	valid := func(method, uri string, body []byte, contentType string) *http.Request {
		req := httptest.NewRequest(method, uri, bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{}
		req.RemoteAddr = "127.0.0.1:54321"
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", dohMediaType)
		return req
	}
	handler := s.DoHHandler()
	normal := valid(http.MethodPost, "/dns-query", wire, dohMediaType)
	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, normal)
	if ok.Code != 200 || ok.Header().Get("Content-Type") != dohMediaType ||
		ok.Header().Get("Cache-Control") != "no-store" ||
		ok.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unexpected DoH response headers: %+v code=%d", ok.Header(), ok.Code)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(ok.Body.Bytes()); err != nil || answer.Rcode != dns.RcodeNameError {
		t.Fatalf("filtered DNS query returned bad wire: %v %+v", err, answer)
	}
	get := valid(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire), nil, "")
	getReply := httptest.NewRecorder()
	handler.ServeHTTP(getReply, get)
	if getReply.Code != 200 {
		t.Fatalf("valid wire GET returned %d", getReply.Code)
	}
	if err := answer.Unpack(getReply.Body.Bytes()); err != nil || answer.Rcode != dns.RcodeNameError {
		t.Fatalf("DNS GET filter bypassed: %v %+v", err, answer)
	}
	// A reverse-proxy-supplied header can never widen the real TCP peer ACL.
	remote := valid(http.MethodPost, "/dns-query", wire, dohMediaType)
	remote.RemoteAddr = "192.0.2.99:54321"
	remote.Header.Set("X-Forwarded-For", "127.0.0.1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, remote)
	if res.Code != 200 {
		t.Fatal(res.Code)
	}
	if err := answer.Unpack(res.Body.Bytes()); err != nil || answer.Rcode != dns.RcodeRefused {
		t.Fatalf("forwarded spoof unexpectedly accepted: %v %+v", err, answer)
	}
	for _, tc := range []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"plaintext prohibited", httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire)), 426},
		{"other path", valid(http.MethodPost, "/api/v1/status", wire, dohMediaType), 404},
		{"wrong method", valid(http.MethodPut, "/dns-query", wire, dohMediaType), 405},
		{"missing query", valid(http.MethodGet, "/dns-query", nil, ""), 400},
		{"duplicate dns parameter", valid(http.MethodGet, "/dns-query?dns=abc&dns=def", nil, ""), 400},
		{"unexpected query parameter", valid(http.MethodGet, "/dns-query?format=json", nil, ""), 400},
		{"POST query parameter", valid(http.MethodPost, "/dns-query?dns=a", wire, dohMediaType), 400},
		{"non-base64url", valid(http.MethodGet, "/dns-query?dns=**", nil, ""), 400},
		{"incorrect content type", valid(http.MethodPost, "/dns-query", wire, "application/json"), 415},
		{"missing content type", valid(http.MethodPost, "/dns-query", wire, ""), 415},
		{"oversize payload", valid(http.MethodPost, "/dns-query", bytes.Repeat([]byte{'x'}, dohMaxQueryBytes+1), dohMediaType), 413},
		{"malformed DNS", valid(http.MethodPost, "/dns-query", []byte{1, 2, 3}, dohMediaType), 400},
		{"empty payload", valid(http.MethodPost, "/dns-query", nil, dohMediaType), 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "plaintext prohibited" {
				tc.req.Header.Set("Content-Type", dohMediaType)
			}
			got := httptest.NewRecorder()
			handler.ServeHTTP(got, tc.req)
			if got.Code != tc.status {
				t.Fatalf("got %d wanted %d", got.Code, tc.status)
			}
		})
	}
	notAcceptable := valid(http.MethodPost, "/dns-query", wire, dohMediaType)
	notAcceptable.Header.Set("Accept", "application/json")
	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, notAcceptable)
	if bad.Code != 406 {
		t.Fatalf("JSON content negotiation accepted: %d", bad.Code)
	}
}

func TestDoHEndToEndTLSLoopback(t *testing.T) {
	cert, key, roots := testCertificate(t)
	cfg, _ := testConfig(t)
	cfg.DNSListen, cfg.APIListen, cfg.DoHListen = freeLoopbackPort(t), freeLoopbackPort(t), freeLoopbackPort(t)
	cfg.DoHTLSCertFile, cfg.DoHTLSKeyFile = cert, key
	cfg.LocalRecordsFile = filepath.Join(t.TempDir(), "records.txt")
	if err := os.WriteFile(cfg.LocalRecordsFile, []byte("A home.example 192.0.2.41\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.dohTLS == nil || s.dohTLS.MinVersion < tls.VersionTLS12 {
		t.Fatal("DoH TLS not enabled or too old")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-ended:
		case <-time.After(5 * time.Second):
			t.Error("DoH gateway shutdown did not complete")
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	baseURL := "https://" + cfg.DoHListen + "/dns-query"
	q := new(dns.Msg)
	q.SetQuestion("home.example.", dns.TypeA)
	raw, _ := q.Pack()
	var res *http.Response
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(raw))
		req.Header.Set("Content-Type", dohMediaType)
		res, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("DoH failed to accept trusted TLS: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("DoH HTTP returned %d", res.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		t.Fatal(err)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(content); err != nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("DoH wire reply failed: err=%v response=%+v", err, answer)
	}
	if a, ok := answer.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.41" {
		t.Fatal("wrong DoH local answer")
	}
	// A client without the synthetic CA must not silently accept its TLS identity.
	untrusted := &http.Client{Timeout: time.Second}
	r, _ := http.NewRequest(http.MethodPost, baseURL, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", dohMediaType)
	if untrustedRes, e := untrusted.Do(r); e == nil {
		untrustedRes.Body.Close()
		t.Fatal("untrusted HTTPS certificate unexpectedly accepted")
	}
}
