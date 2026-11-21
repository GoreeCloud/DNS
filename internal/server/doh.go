package server

import (
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

const (
	dohMediaType     = "application/dns-message"
	dohMaxQueryBytes = 4096
	dohMaxReplyBytes = 65535
)

// DoHHandler implements a deliberately narrow RFC 8484 GET/POST wire-format
// endpoint. Only the independently configured HTTPS listener serves this
// handler. It is NOT multiplexed with the authenticated administration API.
func (s *Server) DoHHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
			return
		}
		if r.URL.Path != "/dns-query" || r.URL.EscapedPath() != "/dns-query" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
			return
		}
		accept := strings.TrimSpace(r.Header.Get("Accept"))
		if accept != "" && accept != "*/*" && !strings.EqualFold(accept, dohMediaType) {
			http.Error(w, "unsupported response format", http.StatusNotAcceptable)
			return
		}
		var wire []byte
		switch r.Method {
		case http.MethodGet:
			if r.URL.RawQuery == "" {
				http.Error(w, "missing dns query", http.StatusBadRequest)
				return
			}
			params, err := parseDoHParameters(r.URL.RawQuery)
			if err != nil {
				http.Error(w, "invalid dns query parameters", http.StatusBadRequest)
				return
			}
			if len(params) > 5470 {
				http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
				return
			}
			wire, err = base64.RawURLEncoding.DecodeString(params)
			if err != nil {
				http.Error(w, "invalid dns query encoding", http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if r.URL.RawQuery != "" {
				http.Error(w, "unexpected query parameters", http.StatusBadRequest)
				return
			}
			if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Type")), dohMediaType) {
				http.Error(w, "unsupported request format", http.StatusUnsupportedMediaType)
				return
			}
			content, err := io.ReadAll(io.LimitReader(r.Body, dohMaxQueryBytes+1))
			if err != nil {
				http.Error(w, "could not read dns message", http.StatusBadRequest)
				return
			}
			wire = content
		}
		if len(wire) == 0 {
			http.Error(w, "missing dns message", http.StatusBadRequest)
			return
		}
		if len(wire) > dohMaxQueryBytes {
			http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil || query.Response || len(query.Question) != 1 {
			http.Error(w, "malformed dns message", http.StatusBadRequest)
			return
		}
		// RemoteAddr comes from net/http's accepted TCP connection. Deliberately
		// ignore X-Forwarded-For and all proxy-supplied client identities.
		host, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid peer", http.StatusBadRequest)
			return
		}
		peer := net.ParseIP(host)
		parsedPort, err := net.LookupPort("tcp", port)
		if err != nil || peer == nil {
			http.Error(w, "invalid peer", http.StatusBadRequest)
			return
		}
		bridge := &dohDNSWriter{
			peer:  &net.TCPAddr{IP: peer, Port: parsedPort},
			local: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
		}
		s.ServeDNS(bridge, query)
		if bridge.err != nil || len(bridge.response) == 0 {
			http.Error(w, "resolver response unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", dohMediaType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bridge.response)
	})
}

// parseDoHParameters deliberately permits only one unpadded base64url "dns"
// field, preventing accidental caching or routing on arbitrary parameters.
func parseDoHParameters(raw string) (string, error) {
	if strings.Contains(raw, ";") {
		return "", errors.New("query parameter separator unsupported")
	}
	fields := strings.Split(raw, "&")
	if len(fields) != 1 || !strings.HasPrefix(fields[0], "dns=") {
		return "", errors.New("expected exactly one dns parameter")
	}
	encoded := strings.TrimPrefix(fields[0], "dns=")
	if encoded == "" || strings.ContainsAny(encoded, "=%+") {
		return "", errors.New("invalid base64url parameter")
	}
	return encoded, nil
}

// dohDNSWriter adapts one synchronous DoH request to the existing policy,
// client-CIDR, rate-limit and resolver pipeline. It never reads HTTP headers.
type dohDNSWriter struct {
	peer     net.Addr
	local    net.Addr
	response []byte
	err      error
}

func (w *dohDNSWriter) RemoteAddr() net.Addr { return w.peer }
func (w *dohDNSWriter) LocalAddr() net.Addr  { return w.local }
func (w *dohDNSWriter) Close() error         { return nil }
func (w *dohDNSWriter) TsigStatus() error    { return nil }
func (w *dohDNSWriter) TsigTimersOnly(bool)  {}
func (w *dohDNSWriter) Hijack()              {}

func (w *dohDNSWriter) WriteMsg(m *dns.Msg) error {
	if m == nil {
		w.err = errors.New("missing dns reply")
		return w.err
	}
	wire, err := m.Pack()
	if err == nil && len(wire) > dohMaxReplyBytes {
		err = errors.New("dns reply too large")
	}
	if err == nil {
		w.response = wire
	} else {
		w.err = err
	}
	return err
}
func (w *dohDNSWriter) Write(p []byte) (int, error) {
	if len(p) > dohMaxReplyBytes {
		w.err = errors.New("dns reply too large")
		return 0, w.err
	}
	w.response = append([]byte(nil), p...)
	return len(p), nil
}
