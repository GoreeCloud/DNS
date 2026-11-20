package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/GoreeCloud/DNS/internal/policy"
	"github.com/GoreeCloud/DNS/internal/records"
	"github.com/miekg/dns"
)

type Config struct {
	DNSListen         string
	APIListen         string
	Upstream          string
	UpstreamMode      string // auto (client transport), tcp, or tls
	UpstreamTLSName   string // TLS certificate identity; required for tls mode
	UpstreamTLSCAFile string // optional custom PEM CA file for tls mode
	APIToken          string
	RulesFile         string
	LocalRecordsFile  string // optional, strictly validated static overrides
	MaxConcurrent     int    // defaults to 128, bounds simultaneous upstream queries
	AllowedCIDRs      string // explicit DNS client CIDRs; loopback-only by default
}

type Server struct {
	config         Config
	tlsConfig      *tls.Config
	rules          atomic.Pointer[policy.Rules]
	local          atomic.Pointer[records.Store]
	localAnswers   atomic.Uint64
	queries        atomic.Uint64
	blocked        atomic.Uint64
	upstreamErrors atomic.Uint64
	overloaded     atomic.Uint64
	refused        atomic.Uint64
	permits        chan struct{}
	allowed        []netip.Prefix
}

func New(config Config) (*Server, error) {
	if len(config.APIToken) < 16 {
		return nil, errors.New("DNS_API_TOKEN must contain at least 16 characters")
	}
	for name, value := range map[string]string{
		"DNS_LISTEN_ADDR":   config.DNSListen,
		"DNS_API_ADDR":      config.APIListen,
		"DNS_UPSTREAM_ADDR": config.Upstream,
	} {
		_, port, err := net.SplitHostPort(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%s: port must be between 1 and 65535", name)
		}
	}
	if config.RulesFile == "" {
		return nil, errors.New("rules file is required")
	}
	if config.UpstreamMode == "" {
		config.UpstreamMode = "auto"
	}
	if config.UpstreamMode != "auto" && config.UpstreamMode != "tcp" && config.UpstreamMode != "tls" {
		return nil, errors.New("DNS_UPSTREAM_MODE must be auto, tcp or tls")
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 128
	}
	if config.MaxConcurrent < 1 || config.MaxConcurrent > 4096 {
		return nil, errors.New("DNS_MAX_CONCURRENT must be between 1 and 4096")
	}
	allowed, err := parseAllowedCIDRs(config.AllowedCIDRs)
	if err != nil {
		return nil, fmt.Errorf("DNS_ALLOWED_CIDRS: %w", err)
	}
	var upstreamTLS *tls.Config
	if config.UpstreamMode == "tls" {
		name := strings.TrimSpace(config.UpstreamTLSName)
		if name == "" || strings.ContainsAny(name, " \t\r\n:/") {
			return nil, errors.New("DNS_UPSTREAM_TLS_NAME must be a certificate identity in tls mode")
		}
		upstreamTLS = &tls.Config{
			ServerName: name,
			MinVersion: tls.VersionTLS12,
		}
		if config.UpstreamTLSCAFile != "" {
			pemData, err := os.ReadFile(config.UpstreamTLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read TLS CA file: %w", err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(pemData) {
				return nil, errors.New("DNS_UPSTREAM_TLS_CA_FILE has no valid CA certificates")
			}
			upstreamTLS.RootCAs = roots
		}
	} else if config.UpstreamTLSName != "" || config.UpstreamTLSCAFile != "" {
		return nil, errors.New("upstream TLS settings require DNS_UPSTREAM_MODE=tls")
	}
	rules, err := policy.Load(config.RulesFile)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	var local *records.Store
	if config.LocalRecordsFile == "" {
		local = records.Empty()
	} else {
		local, err = records.Load(config.LocalRecordsFile)
		if err != nil {
			return nil, fmt.Errorf("load local records: %w", err)
		}
	}
	s := &Server{config: config, tlsConfig: upstreamTLS, permits: make(chan struct{}, config.MaxConcurrent), allowed: allowed}
	s.rules.Store(rules)
	s.local.Store(local)
	return s, nil
}

// parseAllowedCIDRs accepts a bounded list of explicit prefixes. Empty input
// intentionally means localhost only. An unrestricted /0 prefix is rejected
// so a public recursive resolver cannot be enabled by an accidental wildcard.
func parseAllowedCIDRs(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		value = "127.0.0.0/8,::1/128"
	}
	if len(value) > 2048 {
		return nil, errors.New("CIDR configuration is too long")
	}
	inputs := strings.Split(value, ",")
	if len(inputs) > 32 {
		return nil, errors.New("too many CIDR entries")
	}
	result := make([]netip.Prefix, 0, len(inputs))
	for _, input := range inputs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(input))
		if err != nil || !prefix.IsValid() || prefix.Bits() == 0 ||
			prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid or overly broad CIDR %q", strings.TrimSpace(input))
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func (s *Server) accepts(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	var raw net.IP
	switch addr := remote.(type) {
	case *net.TCPAddr:
		raw = addr.IP
	case *net.UDPAddr:
		raw = addr.IP
	default:
		host, _, err := net.SplitHostPort(remote.String())
		if err != nil {
			return false
		}
		raw = net.ParseIP(host)
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, cidr := range s.allowed {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	s.queries.Add(1)
	if !s.accepts(w.RemoteAddr()) {
		s.refused.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeRefused)
		_ = w.WriteMsg(reply)
		return
	}
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
	// Local records are exact-name overrides; they never reach the upstream.
	// Filter blocks take precedence over local overrides.
	if answers, found := s.local.Load().Lookup(query); found {
		s.localAnswers.Add(1)
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Authoritative = true
		reply.RecursionAvailable = true
		reply.Answer = answers
		_ = w.WriteMsg(reply)
		return
	}
	// Bound concurrent upstream work; policy-blocked replies are still served.
	select {
	case s.permits <- struct{}{}:
		defer func() { <-s.permits }()
	default:
		s.overloaded.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeServerFailure)
		reply.RecursionAvailable = true
		_ = w.WriteMsg(reply)
		return
	}

	network := "udp"
	switch s.config.UpstreamMode {
	case "tls":
		network = "tcp-tls"
	case "tcp":
		network = "tcp"
	default:
		if remote := w.RemoteAddr(); remote != nil && strings.HasPrefix(remote.Network(), "tcp") {
			network = "tcp"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	client := &dns.Client{Net: network, Timeout: 3 * time.Second, TLSConfig: s.tlsConfig}
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
		rules := s.rules.Load()
		s.writeJSON(w, http.StatusOK, map[string]any{
			"product":         "GoreeCloud DNS",
			"state":           "running",
			"queries":         s.queries.Load(),
			"blocked":         s.blocked.Load(),
			"upstream_errors": s.upstreamErrors.Load(),
			"overloaded":      s.overloaded.Load(),
			"refused":         s.refused.Load(),
			"rules":           rules.Count(),
			"local_records":   s.local.Load().Count(),
			"local_answers":   s.localAnswers.Load(),
			"exceptions":      rules.AllowCount(),
			"upstream_mode":   s.config.UpstreamMode,
		})
	}))
	mux.HandleFunc("POST /api/v1/rules/reload", s.apiAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			received, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(received) != 0 {
				http.Error(w, "request body not accepted", http.StatusBadRequest)
				return
			}
		}
		rules, err := policy.Load(s.config.RulesFile)
		if err != nil {
			http.Error(w, "invalid rules file; old rules retained", http.StatusUnprocessableEntity)
			return
		}
		s.rules.Store(rules)
		s.writeJSON(w, http.StatusOK, map[string]any{
			"rules": rules.Count(), "exceptions": rules.AllowCount(), "reloaded": true,
		})
	}))
	// POST keeps private domain names out of URLs, browser history and
	// ordinary reverse-proxy request-path logs. This endpoint logs nothing.

	mux.HandleFunc("POST /api/v1/local/reload", s.apiAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.config.LocalRecordsFile == "" {
			http.Error(w, "local records file not configured", http.StatusConflict)
			return
		}
		if r.Body != nil {
			received, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(received) != 0 {
				http.Error(w, "request body not accepted", http.StatusBadRequest)
				return
			}
		}
		next, err := records.Load(s.config.LocalRecordsFile)
		if err != nil {
			http.Error(w, "invalid local records; old records retained", http.StatusUnprocessableEntity)
			return
		}
		s.local.Store(next)
		s.writeJSON(w, http.StatusOK, map[string]any{
			"reloaded": true, "records": next.Count(),
		})
	}))
	mux.HandleFunc("POST /api/v1/policy/check", s.apiAuth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name string `json:"name"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid policy check", http.StatusBadRequest)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid policy check", http.StatusBadRequest)
			return
		}
		name, err := policy.ValidateDomain(input.Name)
		if err != nil {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"name": name, "decision": s.rules.Load().Decide(name),
		})
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
