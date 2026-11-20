package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type writer struct { answer *dns.Msg; remote net.Addr }
func (w *writer) LocalAddr() net.Addr { return &net.UDPAddr{IP:net.ParseIP("127.0.0.1")} }
func (w *writer) RemoteAddr() net.Addr { if w.remote != nil { return w.remote }; return &net.UDPAddr{IP:net.ParseIP("127.0.0.1"),Port:12345} }
func (w *writer) WriteMsg(m *dns.Msg) error { w.answer = m; return nil }
func (w *writer) Write(_ []byte) (int,error) { return 0,nil }
func (w *writer) Close() error { return nil }
func (w *writer) TsigStatus() error { return nil }
func (w *writer) TsigTimersOnly(bool) {}
func (w *writer) Hijack() {}

func testConfig(t *testing.T) (Config,string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(file, []byte("blocked.test\n"), 0600); err != nil { t.Fatal(err) }
	return Config{DNSListen:"127.0.0.1:1053",APIListen:"127.0.0.1:8080",
		Upstream:"127.0.0.1:5335",APIToken:"test-token-123456",RulesFile:file},file
}

func testServer(t *testing.T) (*Server,string) {
	t.Helper()
	cfg,file:=testConfig(t)
	s,err:=New(cfg)
	if err != nil { t.Fatal(err) }
	return s,file
}

func TestBlockAndCounters(t *testing.T) {
	s,_ := testServer(t)
	q:=new(dns.Msg); q.SetQuestion("a.blocked.test.",dns.TypeAAAA)
	w:=new(writer); s.ServeDNS(w,q)
	if w.answer == nil || w.answer.Rcode != dns.RcodeNameError { t.Fatalf("bad reply: %+v",w.answer) }
	if s.queries.Load()!=1 || s.blocked.Load()!=1 { t.Fatal("incorrect counters") }
}

func TestAPIAuthenticationAndReloadRollback(t *testing.T) {
	s,path:=testServer(t)
	h:=s.APIHandler()
	req:=httptest.NewRequest(http.MethodGet,"/api/v1/status",nil)
	unauth:=httptest.NewRecorder(); h.ServeHTTP(unauth,req)
	if unauth.Code!=http.StatusUnauthorized { t.Fatal(unauth.Code) }
	req.Header.Set("Authorization","Bearer test-token-123456")
	success:=httptest.NewRecorder(); h.ServeHTTP(success,req)
	if success.Code!=http.StatusOK || !strings.Contains(success.Body.String(), "\"rules\":1") { t.Fatal(success.Body.String()) }
	if err:=os.WriteFile(path,[]byte("bad syntax here\n"),0600);err!=nil { t.Fatal(err) }
	reload:=httptest.NewRequest(http.MethodPost,"/api/v1/rules/reload",nil)
	reload.Header.Set("Authorization","Bearer test-token-123456")
	response:=httptest.NewRecorder(); h.ServeHTTP(response,reload)
	if response.Code!=http.StatusUnprocessableEntity || s.rules.Load().Count()!=1 { t.Fatal("bad reload changed policy") }
}

func TestPolicyCheckAuthenticatedAndBounded(t *testing.T) {
	s,_:=testServer(t)
	h:=s.APIHandler()
	for _,tc:=range []struct {
		body string
		want int
		decision string
	}{
		{`{"name":"sub.blocked.test"}`,200,"blocked"},
		{`{"name":"safe.example"}`,200,"unmatched"},
		{`{"name":"http://blocked.test"}`,400,""},
		{`{"name":"blocked.test","unknown":true}`,400,""},
		{`{"name":"blocked.test"} {"name":"safe.example"}`,400,""},
		{strings.Repeat("x",2048),400,""},
	} {
		request:=httptest.NewRequest(http.MethodPost,"/api/v1/policy/check",strings.NewReader(tc.body))
		request.Header.Set("Authorization","Bearer test-token-123456")
		response:=httptest.NewRecorder()
		h.ServeHTTP(response,request)
		if response.Code!=tc.want { t.Fatalf("body %q => %d, want %d",tc.body[:min(len(tc.body),90)],response.Code,tc.want) }
		if tc.decision!="" {
			var result struct { Decision string `json:"decision"` }
			if err:=json.Unmarshal(response.Body.Bytes(),&result);err!=nil{t.Fatal(err)}
			if result.Decision!=tc.decision{t.Fatalf("decision=%q wanted %q",result.Decision,tc.decision)}
		}
	}
	if s.queries.Load()!=0 {t.Fatal("policy preview must not count as a DNS request")}
}

func TestReloadRejectsBodyAndRetainsRules(t *testing.T) {
	s,path:=testServer(t)
	h:=s.APIHandler()
	req:=httptest.NewRequest(http.MethodPost,"/api/v1/rules/reload",bytes.NewBufferString("unexpected"))
	req.Header.Set("Authorization","Bearer test-token-123456")
	response:=httptest.NewRecorder()
	h.ServeHTTP(response,req)
	if response.Code!=400 || s.rules.Load().Count()!=1 { t.Fatalf("status=%d count=%d",response.Code,s.rules.Load().Count()) }
	if err:=os.WriteFile(path,[]byte("blocked.test" + string(byte(10)) + "@@||safe.blocked.test^" + string(byte(10))),0600);err!=nil{t.Fatal(err)}
	reload:=httptest.NewRequest(http.MethodPost,"/api/v1/rules/reload",nil)
	reload.Header.Set("Authorization","Bearer test-token-123456")
	w:=httptest.NewRecorder();h.ServeHTTP(w,reload)
	if w.Code!=200 || s.rules.Load().Count()!=2 || s.rules.Load().Matches("sub.safe.blocked.test.") {
		t.Fatalf("reload failed: %d %s",w.Code,w.Body.String())
	}
}

func TestConcurrencyBudget(t *testing.T) {
	s,_:=testServer(t)
	s.permits<-struct{}{}
	for i:=1;i<cap(s.permits);i++ { s.permits<-struct{}{} }
	q:=new(dns.Msg);q.SetQuestion("notblocked.test.",dns.TypeA)
	w:=new(writer);s.ServeDNS(w,q)
	if w.answer==nil || w.answer.Rcode!=dns.RcodeServerFailure || s.overloaded.Load()!=1 {
		t.Fatalf("unbounded upstream work or bad reply: %+v",w.answer)
	}
}

func TestConfigurationValidation(t *testing.T) {
	base,_:=testConfig(t)
	tests:=[]struct{name string;mutate func(*Config)}{
		{"blank token",func(c *Config){c.APIToken=""}},
		{"short token",func(c *Config){c.APIToken="short"}},
		{"bad mode",func(c *Config){c.UpstreamMode="https"}},
		{"tls without identity",func(c *Config){c.UpstreamMode="tls"}},
		{"tls name used without tls",func(c *Config){c.UpstreamTLSName="example.com"}},
		{"missing custom root",func(c *Config){c.UpstreamMode="tls";c.UpstreamTLSName="example.com";c.UpstreamTLSCAFile="/nonexistent/goreecloud-ca.pem"}},
		{"concurrency negative",func(c *Config){c.MaxConcurrent=-1}},
		{"concurrency excessive",func(c *Config){c.MaxConcurrent=4097}},
		{"port out of range",func(c *Config){c.DNSListen="127.0.0.1:99999"}},
	}
	for _,tt:=range tests {
		t.Run(tt.name,func(t *testing.T){
			cfg:=base
			tt.mutate(&cfg)
			if _,err:=New(cfg);err==nil {t.Fatal("invalid configuration accepted")}
		})
	}
}


func TestDNSClientAllowlist(t *testing.T) {
	cfg,_:=testConfig(t)
	cfg.AllowedCIDRs="127.0.0.0/8,192.168.50.0/24"
	s,err:=New(cfg)
	if err!=nil{t.Fatal(err)}
	q:=new(dns.Msg)
	q.SetQuestion("blocked.test.",dns.TypeA)
	for _,tc:=range []struct{address string; allowed bool}{
		{"127.0.0.1",true},
		{"192.168.50.9",true},
		{"192.168.51.9",false},
		{"203.0.113.9",false},
	} {
		w:=&writer{remote:&net.UDPAddr{IP:net.ParseIP(tc.address),Port:55444}}
		s.ServeDNS(w,q)
		if w.answer==nil {t.Fatalf("no response for %s",tc.address)}
		expected:=dns.RcodeRefused
		if tc.allowed {expected=dns.RcodeNameError}
		if w.answer.Rcode!=expected {t.Fatalf("client %s returned %s",tc.address,dns.RcodeToString[w.answer.Rcode])}
	}
	if s.blocked.Load()!=2 || s.refused.Load()!=2 {
		t.Fatalf("counters incorrect: blocked=%d refused=%d",s.blocked.Load(),s.refused.Load())
	}
}

func TestDNSAllowlistConfiguration(t *testing.T) {
	base,_:=testConfig(t)
	for _,value:=range []string{"0.0.0.0/0","::/0","bad-cidr","127.0.0.0/33",",127.0.0.0/8","::ffff:127.0.0.1/128"} {
		cfg:=base
		cfg.AllowedCIDRs=value
		if _,err:=New(cfg);err==nil{t.Fatalf("accepted invalid allowlist %q",value)}
	}
	for _,value:=range []string{"127.0.0.0/8","::1/128","10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"} {
		cfg:=base
		cfg.AllowedCIDRs=value
		if _,err:=New(cfg);err!=nil{t.Fatalf("rejected %q: %v",value,err)}
	}
}

func TestDefaultDNSAllowlistIsLoopback(t *testing.T) {
	s,_:=testServer(t)
	if !s.accepts(&net.UDPAddr{IP:net.ParseIP("127.0.0.1")}) ||
		!s.accepts(&net.TCPAddr{IP:net.ParseIP("::1")}) ||
		s.accepts(&net.UDPAddr{IP:net.ParseIP("192.168.0.2")}) {
		t.Fatal("DNS listener did not default to loopback-only allowlist")
	}
}
