package server

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestLocalRecordWire verifies full client -> gateway -> local policy /
// upstream routing over both UDP and TCP, entirely on loopback.
func TestLocalRecordWire(t *testing.T) {
	var forwarded atomic.Uint64
	var sawDO atomic.Bool
	upPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upStream, err := net.Listen("tcp", upPacket.LocalAddr().String())
	if err != nil {
		_ = upPacket.Close()
		t.Fatal(err)
	}
	upHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		forwarded.Add(1)
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			sawDO.Store(true)
		}
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.RecursionAvailable = true
		if req.Question[0].Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP("192.0.2.110").To4(),
			})
		}
		if opt := req.IsEdns0(); opt != nil {
			msg.SetEdns0(opt.UDPSize(), opt.Do())
		}
		_ = w.WriteMsg(msg)
	})
	upUDP := &dns.Server{PacketConn: upPacket, Handler: upHandler}
	upTCP := &dns.Server{Listener: upStream, Handler: upHandler}
	go func() { _ = upUDP.ActivateAndServe() }()
	go func() { _ = upTCP.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = upUDP.Shutdown()
		_ = upTCP.Shutdown()
	})

	cfg, _ := testConfig(t)
	cfg.Upstream = upPacket.LocalAddr().String()
	cfg.LocalRecordsFile = filepath.Join(t.TempDir(), "local-records.txt")
	local := "A host.example 192.0.2.42\nAAAA host.example 2001:db8::42\nCNAME alias.example host.example\n"
	if err := os.WriteFile(cfg.LocalRecordsFile, []byte(local), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	dnsPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsStream, err := net.Listen("tcp", dnsPacket.LocalAddr().String())
	if err != nil {
		_ = dnsPacket.Close()
		t.Fatal(err)
	}
	localUDP := &dns.Server{PacketConn: dnsPacket, Handler: s}
	localTCP := &dns.Server{Listener: dnsStream, Handler: s}
	go func() { _ = localUDP.ActivateAndServe() }()
	go func() { _ = localTCP.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = localUDP.Shutdown()
		_ = localTCP.Shutdown()
	})

	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			client := &dns.Client{Net: transport, Timeout: 2 * time.Second}
			for _, tc := range []struct {
				name          string
				qtype         uint16
				rcode         int
				answers       int
				authoritative bool
			}{
				{"host.example.", dns.TypeA, dns.RcodeSuccess, 1, true},
				{"host.example.", dns.TypeAAAA, dns.RcodeSuccess, 1, true},
				{"alias.example.", dns.TypeA, dns.RcodeSuccess, 1, true},
				{"host.example.", dns.TypeMX, dns.RcodeSuccess, 0, true},
				{"blocked.test.", dns.TypeA, dns.RcodeNameError, 0, false},
				{"unknown.example.", dns.TypeA, dns.RcodeSuccess, 1, false},
			} {
				req := new(dns.Msg)
				req.SetQuestion(tc.name, tc.qtype)
				if tc.name == "unknown.example." {
					req.SetEdns0(1232, true)
				}
				reply, _, err := client.Exchange(req, dnsPacket.LocalAddr().String())
				if err != nil {
					t.Fatalf("%s %d: %v", tc.name, tc.qtype, err)
				}
				if reply.Rcode != tc.rcode || len(reply.Answer) != tc.answers {
					t.Fatalf("%s %d: rcode=%d answers=%d", tc.name, tc.qtype, reply.Rcode, len(reply.Answer))
				}
				if reply.Authoritative != tc.authoritative {
					t.Fatalf("%s %d: unexpected authoritative=%t", tc.name, tc.qtype, reply.Authoritative)
				}
				if tc.name == "alias.example." {
					if _, ok := reply.Answer[0].(*dns.CNAME); !ok {
						t.Fatalf("alias did not return a CNAME: %T", reply.Answer[0])
					}
				}
			}
		})
	}
	if forwarded.Load() != 2 || s.localAnswers.Load() != 8 || s.blocked.Load() != 2 {
		t.Fatalf("forwarded=%d local=%d blocked=%d", forwarded.Load(), s.localAnswers.Load(), s.blocked.Load())
	}
	if !sawDO.Load() {
		t.Fatal("DNSSEC DO bit was not passed to the upstream resolver")
	}
}
