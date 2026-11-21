package records

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func FuzzLocalRecordFileParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("A home.example 192.0.2.12\nAAAA home.example 2001:db8::12\n"),
		[]byte("CNAME alias.example home.example\n"),
		[]byte("CNAME loop.example loop.example\n"),
		[]byte("A wrong.example invalid\n"),
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		store, err := Parse(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeANY} {
			_, _ = store.Lookup(dns.Question{Name: "home.example.", Qtype: qt, Qclass: dns.ClassINET})
		}
	})
}
