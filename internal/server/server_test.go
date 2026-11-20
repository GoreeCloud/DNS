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

type writer struct { answer *dns.Msg }
func (w *writer) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (w *writer) RemoteAddr() net.Addr { return &net.UDPAddr{} }
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
