package server

import (
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

func testServer(t *testing.T) (*Server,string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(file, []byte("blocked.test\n"), 0600); err != nil { t.Fatal(err) }
	s, err := New(Config{DNSListen:"127.0.0.1:1053",APIListen:"127.0.0.1:8080",Upstream:"127.0.0.1:5335",APIToken:"test-token-123456",RulesFile:file})
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

func TestMissingTokenRejected(t *testing.T) {
	_,err:=New(Config{APIToken:""})
	if err==nil { t.Fatal("must reject empty token") }
}
