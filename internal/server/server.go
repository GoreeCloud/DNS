package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GoreeCloud/DNS/internal/policy"
	"github.com/miekg/dns"
)

type Config struct {
	DNSListen string
	APIListen string
	Upstream string
	APIToken string
	RulesFile string
}

type Server struct {
	config Config
	rules atomic.Pointer[policy.Rules]
	queries atomic.Uint64
	blocked atomic.Uint64
	upstreamErrors atomic.Uint64
}

func New(config Config) (*Server, error) {
	if config.APIToken == "" || len(config.APIToken) < 16 {
		return nil, errors.New("DNS_API_TOKEN must contain at least 16 characters")
	}
	for _, value := range []string{config.DNSListen, config.APIListen, config.Upstream} {
		if _, _, err := net.SplitHostPort(value); err != nil {
			return nil, fmt.Errorf("invalid endpoint: %w", err)
		}
	}
	if config.RulesFile == "" {
		return nil, errors.New("rules file is required")
	}
	rules, err := policy.Load(config.RulesFile)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	s := &Server{config: config}
	s.rules.Store(rules)
	return s, nil
}

func (s *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	s.queries.Add(1)
	if len(request.Question) != 1 {
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}
	query := request.Question[0]
	if s.rules.Load().Matches(query.Name) {
		s.blocked.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeNameError)
		reply.RecursionAvailable = true
		_ = w.WriteMsg(reply)
		return
	}

	network := "udp"
	if remote := w.RemoteAddr(); remote != nil && strings.HasPrefix(remote.Network(), "tcp") {
		network = "tcp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	client := &dns.Client{Net: network, Timeout: 3 * time.Second}
	answer, _, err := client.ExchangeContext(ctx, request, s.config.Upstream)
	if err == nil && answer != nil && answer.Truncated && network == "udp" {
		client.Net = "tcp"
		answer, _, err = client.ExchangeContext(ctx, request, s.config.Upstream)
	}
	if err != nil || answer == nil || answer.Id != request.Id {
		s.upstreamErrors.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeServerFailure)
		reply.RecursionAvailable = true
		_ = w.WriteMsg(reply)
		return
	}
	_ = w.WriteMsg(answer)
}

func (s *Server) apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		expected := "Bearer " + s.config.APIToken
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("running\n"))
	})
	mux.HandleFunc("GET /api/v1/status", s.apiAuth(func(w http.ResponseWriter, _ *http.Request) {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"product": "GoreeCloud DNS",
			"state": "running",
			"queries": s.queries.Load(),
			"blocked": s.blocked.Load(),
			"upstream_errors": s.upstreamErrors.Load(),
			"rules": s.rules.Load().Count(),
		})
	}))
	mux.HandleFunc("POST /api/v1/rules/reload", s.apiAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			http.Error(w, "request body not accepted", http.StatusBadRequest)
			return
		}
		rules, err := policy.Load(s.config.RulesFile)
		if err != nil {
			http.Error(w, "invalid rules file; old rules retained", http.StatusUnprocessableEntity)
			return
		}
		s.rules.Store(rules)
		s.writeJSON(w, http.StatusOK, map[string]any{"rules": rules.Count(), "reloaded": true})
	}))
	return mux
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// Run starts separate UDP, TCP and HTTP services and shuts them down together.
func (s *Server) Run(ctx context.Context) error {
	dnsHandler := dns.Handler(s)
	udp := &dns.Server{Addr: s.config.DNSListen, Net: "udp", Handler: dnsHandler}
	tcp := &dns.Server{Addr: s.config.DNSListen, Net: "tcp", Handler: dnsHandler}
	httpServer := &http.Server{
		Addr: s.config.APIListen, Handler: s.APIHandler(),
		ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 1 << 16,
	}
	failures := make(chan error, 3)
	go func() { failures <- udp.ListenAndServe() }()
	go func() { failures <- tcp.ListenAndServe() }()
	go func() { failures <- httpServer.ListenAndServe() }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-failures:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	_ = httpServer.Shutdown(shutdownCtx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
