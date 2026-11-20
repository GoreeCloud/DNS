package records

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestLocalRecords(t *testing.T) {
	records,err:=Parse(strings.NewReader(
		"# local-only synthetic fixture\n" +
		"A home.example 192.0.2.42\n" +
		"AAAA home.example 2001:db8::42\n" +
		"CNAME alias.example home.example\n" +
		"A home.example 192.0.2.42 # duplicate\n"))
	if err!=nil{t.Fatal(err)}
	if records.Count()!=3 {t.Fatalf("count=%d",records.Count())}
	for _,tt:=range []struct{name string;typ uint16;count int;matched bool}{
		{"home.example.",dns.TypeA,1,true},
		{"home.example.",dns.TypeAAAA,1,true},
		{"home.example.",dns.TypeMX,0,true},
		{"home.example.",dns.TypeANY,0,true},
		{"alias.example.",dns.TypeA,1,true},
		{"other.example.",dns.TypeA,0,false},
	}{
		answer,found:=records.Lookup(dns.Question{Name:tt.name,Qtype:tt.typ,Qclass:dns.ClassINET})
		if found!=tt.matched || len(answer)!=tt.count {
			t.Fatalf("lookup %s type %d: found=%v count=%d",tt.name,tt.typ,found,len(answer))
		}
	}
	if _,found:=records.Lookup(dns.Question{Name:"home.example.",Qtype:dns.TypeA,Qclass:dns.ClassCHAOS});found {
		t.Fatal("non-IN question incorrectly intercepted")
	}
}

func TestRejectUnsafeLocalRecords(t *testing.T) {
	for _,entry:=range []string{
		"TXT home.example hello",
		"A home.example 2001:db8::1",
		"AAAA home.example 192.0.2.42",
		"A home.example not-an-ip",
		"A https://example.org 192.0.2.1",
		"CNAME alias.example invalid",
		"A home.example 192.0.2.1\nCNAME home.example other.example",
		"CNAME alias.example other.example\nCNAME alias.example another.example",
		"A home.example",
	}{
		if _,err:=Parse(strings.NewReader(entry));err==nil{
			t.Fatalf("accepted invalid local records %q",entry)
		}
	}
	if _,err:=Parse(bytes.NewReader(bytes.Repeat([]byte('#'),MaxFileBytes+1)));err==nil {
		t.Fatal("oversized override file accepted")
	}
}

func FuzzLocalRecords(f *testing.F){
	f.Add([]byte("A home.example 192.0.2.1\n"))
	f.Add([]byte("CNAME alias.example home.example\n"))
	f.Add([]byte("bad input"))
	f.Fuzz(func(t *testing.T, data []byte){
		if len(data)>128<<10{t.Skip()}
		r,err:=Parse(bytes.NewReader(data))
		if err==nil && r.Count()>maxEntries{t.Fatal("record count exceeded")}
	})
}
