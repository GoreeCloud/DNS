package server

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoTDisabledAndConfigurationFailClosed(t *testing.T) {
	base, _ := testConfig(t)
	initial, err := New(base)
	if err != nil || initial.dotTLS != nil {
		t.Fatalf("inbound DoT should remain disabled without explicit config: %v", err)
	}
	cert, key, _ := testCertificate(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"certificate without listener", func(c *Config) { c.DoTTLSCertFile = cert; c.DoTTLSKeyFile = key }},
		{"listener without identity", func(c *Config) { c.DoTListen = "127.0.0.1:8853" }},
		{"remote listener without opt-in", func(c *Config) { c.DoTListen = "0.0.0.0:8853"; c.DoTTLSCertFile = cert; c.DoTTLSKeyFile = key }},
		{"certificate without key", func(c *Config) { c.DoTListen = "127.0.0.1:8853"; c.DoTTLSCertFile = cert }},
		{"invalid port", func(c *Config) { c.DoTListen = "127.0.0.1:99999"; c.DoTTLSCertFile = cert; c.DoTTLSKeyFile = key }},
		{"TCP conflict", func(c *Config) { c.DoTListen = c.DNSListen; c.DoTTLSCertFile = cert; c.DoTTLSKeyFile = key }},
		{"API port conflict", func(c *Config) { c.DoTListen = c.APIListen; c.DoTTLSCertFile = cert; c.DoTTLSKeyFile = key }},
		{"missing private key", func(c *Config) {
			c.DoTListen = "127.0.0.1:8853"
			c.DoTTLSCertFile = cert
			c.DoTTLSKeyFile = "/missing/key.pem"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("insecure DoT configuration accepted")
			}
		})
	}
	// Even an explicitly permitted remote TLS listener still uses the DNS
	// client CIDR ACL and never implicitly accepts all source addresses.
	remote := base
	remote.DoTListen = "0.0.0.0:8853"
	remote.DoTAllowRemote = true
	remote.DoTTLSCertFile = cert
	remote.DoTTLSKeyFile = key
	if _, err := New(remote); err != nil {
		t.Fatalf("explicit remote DoT opt-in rejected: %v", err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := base
	cfg.DoTListen = "127.0.0.1:8853"
	cfg.DoTTLSCertFile = cert
	cfg.DoTTLSKeyFile = key
	if _, err := New(cfg); err == nil {
		t.Fatal("world-readable DoT private key accepted")
	}
}

func TestInboundDoTSyntheticLoopback(t *testing.T) {
	cert, key, roots := testCertificate(t)
	cfg, _ := testConfig(t)
	cfg.DNSListen = freeLoopbackPort(t)
	cfg.APIListen = freeLoopbackPort(t)
	cfg.DoTListen = freeLoopbackPort(t)
	cfg.DoTTLSCertFile = cert
	cfg.DoTTLSKeyFile = key
	cfg.LocalRecordsFile = filepath.Join(t.TempDir(), "local-records.txt")
	if err := os.WriteFile(cfg.LocalRecordsFile, []byte("A home.example 192.0.2.47\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.dotTLS == nil || s.dotTLS.MinVersion < tls.VersionTLS12 {
		t.Fatal("DoT TLS listener is not configured")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("DoT gateway shutdown timed out")
		}
	}()
	tlsClient := &dns.Client{Net: "tcp-tls", Timeout: time.Second, TLSConfig: &tls.Config{
		RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	}}
	query := new(dns.Msg)
	query.SetQuestion("home.example.", dns.TypeA)
	var response *dns.Msg
	for i := 0; i < 30; i++ {
		response, _, err = tlsClient.Exchange(query, cfg.DoTListen)
		if err == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("DoT listener failed to start: %v", err)
	}
	if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 ||
		!response.Authoritative {
		t.Fatalf("DoT local record not served: %+v", response)
	}
	if a, ok := response.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.47" {
		t.Fatalf("wrong DoT answer: %+v", response.Answer)
	}
	blocked := new(dns.Msg)
	blocked.SetQuestion("blocked.test.", dns.TypeAAAA)
	negative, _, err := tlsClient.Exchange(blocked, cfg.DoTListen)
	if err != nil || negative == nil || negative.Rcode != dns.RcodeNameError {
		t.Fatalf("DoT filtering bypassed: %+v err=%v", negative, err)
	}
	// Reject a client that does not trust the self-signed synthetic identity.
	unknownCA := &dns.Client{Net: "tcp-tls", Timeout: time.Second, TLSConfig: &tls.Config{
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	}}
	if _, _, err := unknownCA.Exchange(query, cfg.DoTListen); err == nil {
		t.Fatal("untrusted server identity unexpectedly accepted")
	}
	if s.localAnswers.Load() != 1 || s.blocked.Load() != 1 {
		t.Fatalf("unexpected DNS counters after DoT: local=%d blocked=%d", s.localAnswers.Load(), s.blocked.Load())
	}
	// Ensure native DNS-over-TLS uses an actual TCP endpoint, never UDP.
	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.DoTListen)
	if err != nil || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		t.Fatalf("DoT test escaped loopback: %v", err)
	}
}
