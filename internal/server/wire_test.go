package server

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestWireTransport is a synthetic, loopback-only DNS protocol smoke test.
// It exercises the real UDP and TCP listeners and upstream round trip.
func TestWireTransport(t *testing.T) {
	upUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upTCP, err := net.Listen("tcp", upUDP.LocalAddr().String())
	if err != nil {
		_ = upUDP.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.RecursionAvailable = true
		if len(request.Question) == 1 && request.Question[0].Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   request.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("192.0.2.42").To4(),
			})
		}
		_ = w.WriteMsg(reply)
	})
	upUDPServer := &dns.Server{PacketConn: upUDP, Handler: handler}
	upTCPServer := &dns.Server{Listener: upTCP, Handler: handler}
	go func() { _ = upUDPServer.ActivateAndServe() }()
	go func() { _ = upTCPServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = upUDPServer.Shutdown()
		_ = upTCPServer.Shutdown()
	})

	file := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(file, []byte("blocked.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		DNSListen: "127.0.0.1:1053",
		APIListen: "127.0.0.1:8080",
		Upstream:  upUDP.LocalAddr().String(),
		APIToken:  "synthetic-token-for-wire-test",
		RulesFile: file,
	})
	if err != nil {
		t.Fatal(err)
	}

	inUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inTCP, err := net.Listen("tcp", inUDP.LocalAddr().String())
	if err != nil {
		_ = inUDP.Close()
		t.Fatal(err)
	}
	dnsUDPServer := &dns.Server{PacketConn: inUDP, Handler: s}
	dnsTCPServer := &dns.Server{Listener: inTCP, Handler: s}
	go func() { _ = dnsUDPServer.ActivateAndServe() }()
	go func() { _ = dnsTCPServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = dnsUDPServer.Shutdown()
		_ = dnsTCPServer.Shutdown()
	})

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			client := &dns.Client{Net: network, Timeout: 2 * time.Second}
			query := new(dns.Msg)
			query.SetQuestion("allowed.test.", dns.TypeA)
			answer, _, err := client.Exchange(query, inUDP.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
				t.Fatalf("unexpected upstream response: rcode %d answers %d", answer.Rcode, len(answer.Answer))
			}

			blocked := new(dns.Msg)
			blocked.SetQuestion("sub.blocked.test.", dns.TypeA)
			blockedAnswer, _, err := client.Exchange(blocked, inUDP.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			if blockedAnswer.Rcode != dns.RcodeNameError {
				t.Fatalf("blocked query returned rcode %d", blockedAnswer.Rcode)
			}
		})
	}
	if s.queries.Load() != 4 || s.blocked.Load() != 2 {
		t.Fatalf("counters: queries=%d blocked=%d", s.queries.Load(), s.blocked.Load())
	}
}
