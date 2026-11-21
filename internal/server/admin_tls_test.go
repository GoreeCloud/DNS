package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagementAPIBindGuard(t *testing.T) {
	base, _ := testConfig(t)
	for _, address := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.10:8080", "dns.example:8080"} {
		cfg := base
		cfg.APIListen = address
		if _, err := New(cfg); err == nil {
			t.Errorf("plaintext remote admin bind accepted for %s", address)
		}
		cfg.APIAllowInsecureRemote = true
		if _, err := New(cfg); err != nil {
			t.Errorf("explicit isolated-container opt-in not accepted for %s: %v", address, err)
		}
	}
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		cfg := base
		cfg.APIListen = address
		if _, err := New(cfg); err != nil {
			t.Errorf("loopback admin API rejected for %s: %v", address, err)
		}
	}
	base.APITLSCertFile = "/does/not/exist/cert.pem"
	if _, err := New(base); err == nil {
		t.Fatal("accepted certificate without key")
	}
}

func testCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	ephemeral := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := ephemeral.TLS.Certificates[0]
	ephemeral.Close()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	root := x509.NewCertPool()
	root.AddCert(ephemeral.Certificate())
	return certFile, keyFile, root
}

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	return address
}

func TestManagementHTTPSLoopbackAndAuth(t *testing.T) {
	certFile, keyFile, roots := testCertificate(t)
	config, _ := testConfig(t)
	config.DNSListen = freeLoopbackPort(t)
	config.APIListen = freeLoopbackPort(t)
	config.APITLSCertFile = certFile
	config.APITLSKeyFile = keyFile
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if server.adminTLS == nil || server.adminTLS.MinVersion < tls.VersionTLS12 {
		t.Fatal("management TLS not loaded or too old")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- server.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	url := "https://" + config.APIListen + "/api/v1/status"
	var response *http.Response
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+config.APIToken)
		response, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS listener did not start: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("authenticated HTTPS returned %d", response.StatusCode)
	}
	req, _ := http.NewRequest("GET", url, nil)
	unauth, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauth.Body.Close()
	if unauth.StatusCode != 401 {
		t.Fatalf("unauthenticated HTTPS returned %d", unauth.StatusCode)
	}
}

func TestManagementTLSKeyPermissions(t *testing.T) {
	certFile, keyFile, _ := testCertificate(t)
	cfg, _ := testConfig(t)
	cfg.APITLSCertFile = certFile
	cfg.APITLSKeyFile = keyFile
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("insecure private-key file accepted: %v", err)
	}
}
