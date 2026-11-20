package server

import (
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestPrivacyMinimizedRequest(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("safe.example.", dns.TypeA)
	req.SetEdns0(1232, true)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code: dns.EDNS0COOKIE, Cookie: "0102030405060708",
	})
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1,
		SourceNetmask: 24, Address: net.ParseIP("192.0.2.0").To4(),
	})
	req.Extra = append(req.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: "private.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"synthetic-extra"},
	})
	clean := privacyMinimizedRequest(req)
	if len(clean.Answer) != 0 || len(clean.Ns) != 0 || len(clean.Extra) != 1 {
		t.Fatalf("unexpected copied additional sections: %+v", clean)
	}
	cleanOpt := clean.IsEdns0()
	if cleanOpt == nil || !cleanOpt.Do() || cleanOpt.UDPSize() != 1232 || len(cleanOpt.Option) != 0 {
		t.Fatalf("client metadata forwarded: %+v", cleanOpt)
	}
	if len(req.Extra) != 2 || len(req.IsEdns0().Option) != 2 {
		t.Fatal("privacy normalization unexpectedly modified the original client request")
	}
	req.IsEdns0().SetUDPSize(4096)
	capped := privacyMinimizedRequest(req)
	if capped.IsEdns0() == nil || capped.IsEdns0().UDPSize() != 1232 {
		t.Fatal("upstream UDP payload was not capped at 1232 bytes")
	}
}

func TestUpstreamQuestionValidation(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("Safe.Example.", dns.TypeA)
	good := new(dns.Msg)
	good.SetReply(req)
	if !validUpstreamAnswer(req, good) {
		t.Fatal("valid upstream answer rejected")
	}
	copyReply := func() *dns.Msg { return good.Copy() }
	cases := []struct {
		name   string
		change func(*dns.Msg)
	}{
		{"different id", func(r *dns.Msg) { r.Id++ }},
		{"different name", func(r *dns.Msg) { r.Question[0].Name = "other.example." }},
		{"different type", func(r *dns.Msg) { r.Question[0].Qtype = dns.TypeAAAA }},
		{"different class", func(r *dns.Msg) { r.Question[0].Qclass = dns.ClassCHAOS }},
		{"no question", func(r *dns.Msg) { r.Question = nil }},
		{"wrong opcode", func(r *dns.Msg) { r.Opcode = dns.OpcodeStatus }},
		{"not response", func(r *dns.Msg) { r.Response = false }},
		{"truncated", func(r *dns.Msg) { r.Truncated = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := copyReply()
			tc.change(bad)
			if validUpstreamAnswer(req, bad) {
				t.Fatal("malformed or unrelated upstream answer accepted")
			}
		})
	}
}

func TestUnsupportedDNSOpcodeAndClassRejected(t *testing.T) {
	s, _ := testServer(t)
	q := new(dns.Msg)
	q.SetQuestion("safe.example.", dns.TypeA)
	q.Opcode = dns.OpcodeUpdate
	w := new(writer)
	s.ServeDNS(w, q)
	if w.answer == nil || w.answer.Rcode != dns.RcodeNotImplemented ||
		s.upstreamErrors.Load() != 0 {
		t.Fatal("unexpected forwarding of DNS UPDATE opcode")
	}
	q.Opcode = dns.OpcodeQuery
	q.Question[0].Qclass = dns.ClassCHAOS
	w = new(writer)
	s.ServeDNS(w, q)
	if w.answer == nil || w.answer.Rcode != dns.RcodeNotImplemented {
		t.Fatal("non-IN class was forwarded upstream")
	}
}

// All names, upstreams and transport endpoints are synthetic and loopback.
func TestUDPTruncationRetriesOverTCP(t *testing.T) {
	udpSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpSocket, err := net.Listen("tcp", udpSocket.LocalAddr().String())
	if err != nil {
		_ = udpSocket.Close()
		t.Fatal(err)
	}
	var receivedUDP atomic.Uint64
	var receivedTCP atomic.Uint64
	udpBackend := &dns.Server{PacketConn: udpSocket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		receivedUDP.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Truncated = true
		_ = w.WriteMsg(reply)
	})}
	tcpBackend := &dns.Server{Listener: tcpSocket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		receivedTCP.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.25").To4(),
		}}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = udpBackend.ActivateAndServe() }()
	go func() { _ = tcpBackend.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpBackend.Shutdown(); _ = tcpBackend.Shutdown() })
	cfg, _ := testConfig(t)
	cfg.Upstream = udpSocket.LocalAddr().String()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("safe.example.", dns.TypeA)
	w := new(writer)
	s.ServeDNS(w, q)
	if w.answer == nil || w.answer.Rcode != dns.RcodeSuccess ||
		len(w.answer.Answer) != 1 || receivedUDP.Load() != 1 || receivedTCP.Load() != 1 {
		t.Fatalf("UDP truncation fallback failed: %+v UDP=%d TCP=%d", w.answer, receivedUDP.Load(), receivedTCP.Load())
	}
}

func TestUpstreamQuestionMismatchFailsClosed(t *testing.T) {
	udpSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &dns.Server{PacketConn: udpSocket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Question[0].Name = "wrong.example."
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = backend.ActivateAndServe() }()
	t.Cleanup(func() { _ = backend.Shutdown() })
	cfg, _ := testConfig(t)
	cfg.Upstream = udpSocket.LocalAddr().String()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg)
	q.SetQuestion("safe.example.", dns.TypeA)
	w := new(writer)
	s.ServeDNS(w, q)
	if w.answer == nil || w.answer.Rcode != dns.RcodeServerFailure ||
		s.upstreamErrors.Load() != 1 {
		t.Fatalf("mismatched response not rejected: %+v", w.answer)
	}
}

func TestForwardedEDNSClientMetadataRemoved(t *testing.T) {
	udpSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var minimized atomic.Bool
	backend := &dns.Server{PacketConn: udpSocket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		opt := q.IsEdns0()
		if opt != nil && opt.Do() && opt.UDPSize() == 1232 && len(opt.Option) == 0 && len(q.Extra) == 1 {
			minimized.Store(true)
		}
		reply := new(dns.Msg)
		reply.SetReply(q)
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = backend.ActivateAndServe() }()
	t.Cleanup(func() { _ = backend.Shutdown() })
	cfg, _ := testConfig(t)
	cfg.Upstream = udpSocket.LocalAddr().String()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("safe.example.", dns.TypeA)
	query.SetEdns0(1232, true)
	query.IsEdns0().Option = append(query.IsEdns0().Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	w := new(writer)
	s.ServeDNS(w, query)
	if w.answer == nil || w.answer.Rcode != dns.RcodeSuccess || !minimized.Load() {
		t.Fatalf("ECS/Cookie privacy not enforced: %+v", w.answer)
	}
	if len(query.IsEdns0().Option) != 1 {
		t.Fatal("original client metadata was mutated")
	}
}
