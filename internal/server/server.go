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
	"log"
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
	DNSListen              string
	DoTListen              string // optional inbound TLS DNS listener; default disabled
	DoHListen              string // optional inbound HTTPS DNS listener; default disabled
	DoHAllowRemote         bool   // explicit remote binding opt-in, never public by default
	DoHTLSCertFile         string // inbound HTTPS certificate
	DoHTLSKeyFile          string // owner-only matching key
	DoTAllowRemote         bool   // additional explicit opt-in for non-loopback DoT listeners
	DoTTLSCertFile         string // inbound DoT certificate (operator-managed)
	DoTTLSKeyFile          string // matching owner-only private key
	APIListen              string
	APITLSCertFile         string // optional authenticated HTTPS management certificate
	APITLSKeyFile          string // optional private key (owner-only permissions)
	APIAllowInsecureRemote bool   // explicit container/proxy HTTP development exception
	Upstream               string
	UpstreamMode           string // auto (client transport), tcp, or tls
	UpstreamTLSName        string // TLS certificate identity; required for tls mode
	UpstreamTLSCAFile      string // optional custom PEM CA file for tls mode
	APIToken               string
	RulesFile              string
	LocalRecordsFile       string // optional, strictly validated static overrides
	MaxConcurrent          int    // defaults to 128, bounds simultaneous upstream queries
	AllowedCIDRs           string // explicit DNS client CIDRs; loopback-only by default
	RateQPS                int    // process-wide query rate; 500/sec by default
	RateBurst              int    // process-wide request burst; 1000 by default
}

type Server struct {
	config         Config
	tlsConfig      *tls.Config
	adminTLS       *tls.Config
	dotTLS         *tls.Config
	dohTLS         *tls.Config
	rules          atomic.Pointer[policy.Rules]
	local          atomic.Pointer[records.Store]
	localAnswers   atomic.Uint64
	queries        atomic.Uint64
	blocked        atomic.Uint64
	upstreamErrors atomic.Uint64
	overloaded     atomic.Uint64
	refused        atomic.Uint64
	rateLimited    atomic.Uint64
	queryBudget    *queryBudget
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
	// Inbound DNS-over-TLS is disabled by default and must be configured
	// with an explicit listener and matching owner-only TLS identity.
	if config.DoTListen == "" && (config.DoTTLSCertFile != "" || config.DoTTLSKeyFile != "") {
		return nil, errors.New("DNS_DOT_LISTEN_ADDR required with DoT certificate settings")
	}
	var dotTLS *tls.Config
	if config.DoTListen != "" {
		_, port, err := net.SplitHostPort(config.DoTListen)
		if err != nil {
			return nil, fmt.Errorf("DNS_DOT_LISTEN_ADDR: %w", err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("DNS_DOT_LISTEN_ADDR port must be between 1 and 65535")
		}
		host, _, _ := net.SplitHostPort(config.DoTListen)
		ip := net.ParseIP(host)
		isLoopback := host == "localhost" || (ip != nil && ip.IsLoopback())
		if !isLoopback && !config.DoTAllowRemote {
			return nil, errors.New("non-loopback inbound DoT requires DNS_DOT_ALLOW_REMOTE=true and a scoped DNS_ALLOWED_CIDRS")
		}
		if config.DoTListen == config.DNSListen || config.DoTListen == config.APIListen {
			return nil, errors.New("DNS_DOT_LISTEN_ADDR conflicts with another service listener")
		}
		if config.DoTTLSCertFile == "" || config.DoTTLSKeyFile == "" {
			return nil, errors.New("DNS_DOT_TLS_CERT_FILE and DNS_DOT_TLS_KEY_FILE required together")
		}
		info, err := os.Stat(config.DoTTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("DoT private key: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("DoT private key must be a regular owner-only file")
		}
		pair, err := tls.LoadX509KeyPair(config.DoTTLSCertFile, config.DoTTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load DoT certificate: %w", err)
		}
		dotTLS = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
			NextProtos:   []string{"dot"},
		}
	}
	// Independent inbound RFC 8484 listener. There is deliberately no
	// path where a partial HTTPS configuration silently falls back to HTTP.
	if config.DoHListen == "" && (config.DoHTLSCertFile != "" ||
		config.DoHTLSKeyFile != "" || config.DoHAllowRemote) {
		return nil, errors.New("DNS_DOH_LISTEN_ADDR is required when DoH options are set")
	}
	var dohTLS *tls.Config
	if config.DoHListen != "" {
		host, port, err := net.SplitHostPort(config.DoHListen)
		if err != nil {
			return nil, fmt.Errorf("DNS_DOH_LISTEN_ADDR: %w", err)
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("DNS_DOH_LISTEN_ADDR must have a valid TCP port")
		}
		ip := net.ParseIP(host)
		loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
		if !loopback && !config.DoHAllowRemote {
			return nil, errors.New("non-loopback inbound DoH requires DNS_DOH_ALLOW_REMOTE=true and scoped DNS_ALLOWED_CIDRS")
		}
		for _, occupied := range []string{config.DNSListen, config.DoTListen, config.APIListen} {
			if occupied == "" {
				continue
			}
			_, usedPort, _ := net.SplitHostPort(occupied)
			if usedPort == port {
				return nil, errors.New("DNS_DOH_LISTEN_ADDR conflicts with a configured DNS or API port")
			}
		}
		if config.DoHTLSCertFile == "" || config.DoHTLSKeyFile == "" {
			return nil, errors.New("DNS_DOH_TLS_CERT_FILE and DNS_DOH_TLS_KEY_FILE must be set together")
		}
		info, err := os.Stat(config.DoHTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("DoH private key: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("DoH private key must be a regular owner-only file")
		}
		pair, err := tls.LoadX509KeyPair(config.DoHTLSCertFile, config.DoHTLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load DoH TLS certificate: %w", err)
		}
		dohTLS = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}
	// HTTP administration must remain on loopback unless the operator
	// explicitly supplies TLS or authorizes a separately isolated reverse-
	// proxy/container bridge. A wildcard listener must never be accidental.
	apiHost, _, _ := net.SplitHostPort(config.APIListen)
	apiIP := net.ParseIP(apiHost)
	loopbackAPI := apiHost == "localhost" || (apiIP != nil && apiIP.IsLoopback())
	if (config.APITLSCertFile == "") != (config.APITLSKeyFile == "") {
		return nil, errors.New("DNS_API_TLS_CERT_FILE and DNS_API_TLS_KEY_FILE must be configured together")
	}
	var adminTLS *tls.Config
	if config.APITLSKeyFile != "" {
		info, err := os.Stat(config.APITLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("admin TLS private key: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("admin TLS private key must be a regular owner-only file")
		}
		pair, err := tls.LoadX509KeyPair(config.APITLSCertFile, config.APITLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load admin TLS certificate: %w", err)
		}
		adminTLS = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		}
	}
	if !loopbackAPI && adminTLS == nil && !config.APIAllowInsecureRemote {
		return nil, errors.New("non-loopback management API requires HTTPS; for isolated development use DNS_API_ALLOW_INSECURE_REMOTE=true")
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
	if config.RateQPS == 0 {
		config.RateQPS = 500
	}
	if config.RateBurst == 0 {
		config.RateBurst = 1000
	}
	if config.RateQPS < 1 || config.RateQPS > 20000 || config.RateBurst < 1 || config.RateBurst > 50000 {
		return nil, errors.New("DNS_RATE_QPS and DNS_RATE_BURST are outside permitted ranges")
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
	s := &Server{config: config, tlsConfig: upstreamTLS, adminTLS: adminTLS, dotTLS: dotTLS, dohTLS: dohTLS, permits: make(chan struct{}, config.MaxConcurrent), allowed: allowed, queryBudget: newQueryBudget(config.RateQPS, config.RateBurst, time.Now())}
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
	if !s.queryBudget.allow(time.Now()) {
		s.rateLimited.Add(1)
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
	if request.Opcode != dns.OpcodeQuery || query.Qclass != dns.ClassINET {
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeNotImplemented)
		_ = w.WriteMsg(reply)
		return
	}
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
	// Preserve the question and DNSSEC DO bit, but never pass opaque client
	// additionals, TSIG material or EDNS options (including ECS and Cookie)
	// to an upstream resolver. No client/subnet history is retained.
	upstreamRequest := privacyMinimizedRequest(request)
	answer, _, err := client.ExchangeContext(ctx, upstreamRequest, s.config.Upstream)
	if err == nil && answer != nil && answer.Truncated && network == "udp" {
		client.Net = "tcp"
		answer, _, err = client.ExchangeContext(ctx, upstreamRequest, s.config.Upstream)
	}
	if err != nil || !validUpstreamAnswer(request, answer) {
		s.upstreamErrors.Add(1)
		reply := new(dns.Msg)
		reply.SetRcode(request, dns.RcodeServerFailure)
		reply.RecursionAvailable = true
		_ = w.WriteMsg(reply)
		return
	}
	_ = w.WriteMsg(answer)
}

// privacyMinimizedRequest creates a fresh wire question without client-side
// EDNS metadata, subnet data, cookies, unsigned arbitrary additions, or TSIG.
// Only UDP size and DNSSEC DO preference survive when EDNS0 is present.
func privacyMinimizedRequest(request *dns.Msg) *dns.Msg {
	clean := request.Copy()
	clean.Answer = nil
	clean.Ns = nil
	clean.Extra = nil
	if opt := request.IsEdns0(); opt != nil {
		size := opt.UDPSize()
		if size < 512 {
			size = 512
		}
		if size > 1232 {
			size = 1232 // favor fragmentation-resistant UDP; retry over TCP
		}
		clean.SetEdns0(size, opt.Do())
	}
	return clean
}

// validUpstreamAnswer rejects forged, malformed or unrelated replies even
// when they happen to reuse the query's 16-bit transaction identifier.
func validUpstreamAnswer(request, answer *dns.Msg) bool {
	if answer == nil || !answer.Response || answer.Truncated ||
		answer.Id != request.Id || answer.Opcode != request.Opcode ||
		len(answer.Question) != 1 || len(request.Question) != 1 {
		return false
	}
	question := request.Question[0]
	returned := answer.Question[0]
	return returned.Qtype == question.Qtype &&
		returned.Qclass == question.Qclass &&
		strings.EqualFold(dns.Fqdn(returned.Name), dns.Fqdn(question.Name))
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
			"product":             "GoreeCloud DNS",
			"state":               "running",
			"queries":             s.queries.Load(),
			"blocked":             s.blocked.Load(),
			"upstream_errors":     s.upstreamErrors.Load(),
			"overloaded":          s.overloaded.Load(),
			"refused":             s.refused.Load(),
			"rate_limited":        s.rateLimited.Load(),
			"rate_qps":            s.config.RateQPS,
			"rate_burst":          s.config.RateBurst,
			"rules":               rules.Count(),
			"local_records":       s.local.Load().Count(),
			"local_answers":       s.localAnswers.Load(),
			"exceptions":          rules.AllowCount(),
			"upstream_mode":       s.config.UpstreamMode,
			"inbound_dot_enabled": s.dotTLS != nil,
			"inbound_doh_enabled": s.dohTLS != nil,
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

// Run starts UDP, TCP, optional encrypted DoT and DoH, and the management API.
func (s *Server) Run(ctx context.Context) error {
	dnsHandler := dns.Handler(s)
	udp := &dns.Server{Addr: s.config.DNSListen, Net: "udp", Handler: dnsHandler}
	tcp := &dns.Server{Addr: s.config.DNSListen, Net: "tcp", Handler: dnsHandler}
	httpServer := &http.Server{
		Addr: s.config.APIListen, Handler: s.APIHandler(),
		TLSConfig:         s.adminTLS,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	failures := make(chan error, 5)
	go func() { failures <- udp.ListenAndServe() }()
	go func() { failures <- tcp.ListenAndServe() }()
	var dot *dns.Server
	if s.dotTLS != nil {
		dot = &dns.Server{
			Addr: s.config.DoTListen, Net: "tcp-tls", TLSConfig: s.dotTLS,
			Handler: dnsHandler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		}
		go func() { failures <- dot.ListenAndServe() }()
	}
	var doh *http.Server
	if s.dohTLS != nil {
		doh = &http.Server{
			Addr: s.config.DoHListen, Handler: s.DoHHandler(), TLSConfig: s.dohTLS,
			ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 6 * time.Second,
			WriteTimeout: 6 * time.Second, IdleTimeout: 15 * time.Second,
			MaxHeaderBytes: 8 << 10,
			ErrorLog:       log.New(io.Discard, "", 0), // no client-IP TLS handshake logs
		}
		go func() { failures <- doh.ListenAndServeTLS("", "") }()
	}
	go func() {
		if s.adminTLS != nil {
			failures <- httpServer.ListenAndServeTLS("", "")
		} else {
			failures <- httpServer.ListenAndServe()
		}
	}()
	var err error
	select {
	case <-ctx.Done():
	case err = <-failures:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	if dot != nil {
		_ = dot.Shutdown()
	}
	if doh != nil {
		_ = doh.Shutdown(shutdownCtx)
	}
	_ = httpServer.Shutdown(shutdownCtx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
