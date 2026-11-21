package server

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// This is a DNSSEC *wire preservation* test, not cryptographic signature
// verification. The independent Unbound resolver owns DNSSEC validation.
func TestDNSSECWireFlagsAndClientMetadataMinimization(t *testing.T) {
	udpSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var observed atomic.Bool
	backend := &dns.Server{
		PacketConn: udpSocket,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			opt := q.IsEdns0()
			if opt == nil || !opt.Do() || opt.UDPSize() > 1232 || len(opt.Option) != 0 ||
				len(q.Extra) != 1 || len(q.Answer) != 0 || len(q.Ns) != 0 {
				// Fail closed rather than accepting client-subnet/cookie leaks.
				bad := new(dns.Msg)
				bad.SetRcode(q, dns.RcodeServerFailure)
				_ = w.WriteMsg(bad)
				return
			}
			observed.Store(true)
			response := new(dns.Msg)
			response.SetReply(q)
			response.AuthenticatedData = true // fabricated in test: NOT signature validation
			response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{
				Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30,
			}, Txt: []string{"synthetic-dnssec-pass-through"}}}
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = backend.ActivateAndServe() }()
	defer backend.Shutdown()

	cfg, _ := testConfig(t)
	cfg.Upstream = udpSocket.LocalAddr().String()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("wire.example.test.", dns.TypeTXT)
	query.SetEdns0(4096, true)
	query.IsEdns0().Option = append(query.IsEdns0().Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("192.0.2.0").To4()},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	client := new(writer)
	s.ServeDNS(client, query)
	if !observed.Load() || client.answer == nil || client.answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("DNSSEC flag passthrough or privacy minimized request failed: %v", client.answer)
	}
	if !client.answer.AuthenticatedData || len(client.answer.Answer) != 1 {
		t.Fatalf("upstream DNSSEC AD marker was not preserved: %+v", client.answer)
	}
	if s.upstreamErrors.Load() != 0 {
		t.Fatal("unexpected upstream error")
	}
	// The gateway did not verify any signature. Do not advertise this
	// test as cryptographically validated DNSSEC or upstream trust.
}
