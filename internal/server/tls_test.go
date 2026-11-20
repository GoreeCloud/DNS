package server

import (
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSOverTLSVerifiedUpstream(t *testing.T) {
	// Reuse the Go standard library's ephemeral test TLS identity and store
	// its public certificate as an isolated, explicitly trusted test CA.
	testTLS := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := testTLS.TLS.Certificates[0]
	publicCert := testTLS.Certificate()
	testTLS.Close()

	name := ""
	if len(publicCert.DNSNames) > 0 {
		name = publicCert.DNSNames[0]
	} else if len(publicCert.IPAddresses) > 0 {
		name = publicCert.IPAddresses[0].String()
	}
	if name == "" { t.Fatal("test certificate has no SAN") }

	pemFile := filepath.Join(t.TempDir(), "resolver-ca.pem")
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: publicCert.Raw,
	}), 0600); err != nil { t.Fatal(err) }

	conn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		_ = w.WriteMsg(reply)
	})
	listener := tls.NewListener(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS12,
	})
	backend := &dns.Server{Net: "tcp-tls", Listener: listener, Handler: handler}
	go func() { _ = backend.ActivateAndServe() }()
	t.Cleanup(func() { _ = backend.Shutdown() })

	config, _ := testConfig(t)
	config.Upstream = conn.Addr().String()
	config.UpstreamMode = "tls"
	config.UpstreamTLSName = name
	config.UpstreamTLSCAFile = pemFile
	resolver, err := New(config)
	if err != nil { t.Fatal(err) }
	query := new(dns.Msg)
	query.SetQuestion("safe.example.", dns.TypeA)
	w := new(writer)
	resolver.ServeDNS(w,query)
	if w.answer == nil || w.answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("valid authenticated TLS upstream rejected: %+v",w.answer)
	}

	// Wrong certificate identity must fail closed and not return upstream data.
	config.UpstreamTLSName = "wrong.invalid"
	rejecting, err := New(config)
	if err != nil { t.Fatal(err) }
	failed := new(writer)
	rejecting.ServeDNS(failed,query)
	if failed.answer == nil || failed.answer.Rcode != dns.RcodeServerFailure {
		t.Fatalf("incorrect TLS identity was accepted: %+v",failed.answer)
	}
	if rejecting.upstreamErrors.Load() != 1 {
		t.Fatal("TLS failure was not recorded")
	}
}

func TestUpstreamTimeout(t *testing.T) {
	// Prove errors return SERVFAIL instead of silently modifying DNS replies.
	cfg,_:=testConfig(t)
	// Reserve a local port then close it so no upstream is available.
	listener,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	cfg.Upstream=listener.Addr().String()
	_ = listener.Close()
	cfg.UpstreamMode="tcp"
	s,err:=New(cfg)
	if err!=nil{t.Fatal(err)}
	request:=new(dns.Msg);request.SetQuestion("safe.example.",dns.TypeA)
	w:=new(writer)
	begin:=time.Now()
	s.ServeDNS(w,request)
	if w.answer==nil || w.answer.Rcode!=dns.RcodeServerFailure {t.Fatalf("unexpected upstream failure: %+v",w.answer)}
	if time.Since(begin)>5*time.Second {t.Fatal("upstream budget exceeded")}
}
