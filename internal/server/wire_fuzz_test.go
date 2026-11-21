package server

import (
	"bytes"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// FuzzDNSWirePrivacy exercises both the wire parser and the privacy boundary.
// The fuzzer never opens a socket, uses an external DNS server or stores queries.
func FuzzDNSWirePrivacy(f *testing.F) {
	a := new(dns.Msg)
	a.SetQuestion("www.example.test.", dns.TypeA)
	a.SetEdns0(4096, true)
	a.IsEdns0().Option = append(a.IsEdns0().Option,
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1,
			SourceNetmask: 24, Address: net.ParseIP("192.0.2.0").To4()},
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	good, _ := a.Pack()
	f.Add(good)
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 12))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		var message dns.Msg
		if err := message.Unpack(wire); err != nil {
			return
		}
		if len(message.Question) > 4 {
			return
		}
		// A DNS struct Copy can normalize nil versus empty slices. Compare
		// full wire serialization to detect actual request mutations.
		beforeWire, beforeErr := message.Pack()
		clean := privacyMinimizedRequest(&message)
		if clean == nil || len(clean.Answer) != 0 || len(clean.Ns) != 0 || len(clean.Extra) > 1 {
			t.Fatal("DNS wire privacy boundary preserved forbidden records")
		}
		if len(clean.Extra) == 1 {
			opt, ok := clean.Extra[0].(*dns.OPT)
			if !ok || len(opt.Option) != 0 || opt.UDPSize() > 1232 || opt.UDPSize() < 512 {
				t.Fatal("DNS client EDNS options leaked upstream")
			}
		}
		afterWire, afterErr := message.Pack()
		if (beforeErr == nil) != (afterErr == nil) ||
			(beforeErr == nil && !bytes.Equal(beforeWire, afterWire)) {
			t.Fatal("privacy minimization changed the client DNS wire")
		}
	})
}

// FuzzUpstreamResponseIdentity ensures that independently untrusted upstream
// messages never satisfy the query binding without matching wire identity.
func FuzzUpstreamResponseIdentity(f *testing.F) {
	q := new(dns.Msg)
	q.SetQuestion("unique.example.test.", dns.TypeA)
	q.Id = 0x1234
	reply := new(dns.Msg)
	reply.SetReply(q)
	wire, _ := reply.Pack()
	f.Add(wire)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			t.Skip()
		}
		var answer dns.Msg
		if err := answer.Unpack(wire); err != nil {
			return
		}
		ok := validUpstreamAnswer(q, &answer)
		if ok && (!answer.Response || answer.Truncated || answer.Id != q.Id ||
			answer.Opcode != q.Opcode || len(answer.Question) != 1 ||
			!bytes.EqualFold([]byte(answer.Question[0].Name), []byte(q.Question[0].Name)) ||
			answer.Question[0].Qtype != q.Question[0].Qtype ||
			answer.Question[0].Qclass != q.Question[0].Qclass) {
			t.Fatal("upstream mismatched response was accepted")
		}
	})
}
