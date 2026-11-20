package records

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/GoreeCloud/DNS/internal/policy"
	"github.com/miekg/dns"
)

const MaxFileBytes = 2 << 20
const maxEntries = 10000
const localTTL = 60

// Store is an immutable set of explicitly configured, exact-name local
// overrides. It is not a general-purpose authoritative DNS zone database.
type Store struct {
	byName map[string]map[uint16][]dns.RR
	count int
}

func Empty() *Store { return &Store{byName: make(map[string]map[uint16][]dns.RR)} }

func (s *Store) Count() int { return s.count }

// Lookup distinguishes an unknown name (forward upstream) from a known local
// name with no RR of the requested type (NOERROR/NODATA). CNAME aliases are
// returned for other query types and never followed automatically.
func (s *Store) Lookup(question dns.Question) ([]dns.RR, bool) {
	if question.Qclass != dns.ClassINET {
		return nil, false
	}
	name := strings.ToLower(dns.Fqdn(question.Name))
	types, found := s.byName[name]
	if !found {
		return nil, false
	}
	var source []dns.RR
	if aliases := types[dns.TypeCNAME]; len(aliases) != 0 {
		source = aliases
	} else if question.Qtype != dns.TypeANY {
		source = types[question.Qtype]
	}
	result := make([]dns.RR, 0, len(source))
	for _, rr := range source {
		result = append(result, dns.Copy(rr))
	}
	return result, true
}

// Parse supports only the bounded, local-only record forms:
//   A     host.example    192.0.2.42
//   AAAA  host.example    2001:db8::42
//   CNAME alias.example   host.example
//
// Source names are exact matches, unlike suffix-based filter policy.
func Parse(reader io.Reader) (*Store, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read local overrides: %w", err)
	}
	if len(data) > MaxFileBytes {
		return nil, errors.New("local overrides file exceeds 2 MiB limit")
	}
	s := Empty()
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("local record line %d: expected TYPE NAME VALUE", lineNumber)
		}
		recordType := strings.ToUpper(fields[0])
		owner, err := policy.ValidateDomain(fields[1])
		if err != nil {
			return nil, fmt.Errorf("local record line %d: invalid owner domain", lineNumber)
		}
		owner = dns.Fqdn(owner)
		var rr dns.RR
		kind := uint16(0)
		var value string
		header := dns.RR_Header{Name: owner, Class: dns.ClassINET, Ttl: localTTL}
		switch recordType {
		case "A":
			ip, err := netip.ParseAddr(fields[2])
			if err != nil || !ip.Is4() {
				return nil, fmt.Errorf("local record line %d: invalid IPv4 address", lineNumber)
			}
			kind = dns.TypeA
			value = ip.String()
			header.Rrtype = kind
			rr = &dns.A{Hdr: header, A: net.IP(ip.AsSlice())}
		case "AAAA":
			ip, err := netip.ParseAddr(fields[2])
			if err != nil || !ip.Is6() || ip.Is4In6() {
				return nil, fmt.Errorf("local record line %d: invalid IPv6 address", lineNumber)
			}
			kind = dns.TypeAAAA
			value = ip.String()
			header.Rrtype = kind
			rr = &dns.AAAA{Hdr: header, AAAA: net.IP(ip.AsSlice())}
		case "CNAME":
			target, err := policy.ValidateDomain(fields[2])
			if err != nil {
				return nil, fmt.Errorf("local record line %d: invalid alias target", lineNumber)
			}
			kind = dns.TypeCNAME
			value = target
			header.Rrtype = kind
			rr = &dns.CNAME{Hdr: header, Target: dns.Fqdn(target)}
		default:
			return nil, fmt.Errorf("local record line %d: unsupported type", lineNumber)
		}
		if s.byName[owner] == nil {
			s.byName[owner] = make(map[uint16][]dns.RR)
		}
		types := s.byName[owner]
		if (kind == dns.TypeCNAME && len(types) != 0 && len(types[dns.TypeCNAME]) == 0) ||
			(kind != dns.TypeCNAME && len(types[dns.TypeCNAME]) > 0) {
			return nil, fmt.Errorf("local record line %d: CNAME cannot coexist with A/AAAA", lineNumber)
		}
		if kind == dns.TypeCNAME && len(types[kind]) > 0 {
			return nil, fmt.Errorf("local record line %d: multiple CNAME targets", lineNumber)
		}
		key := fmt.Sprintf("%d:%s:%s", kind, owner, value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		s.count++
		if s.count > maxEntries {
			return nil, fmt.Errorf("local override limit of %d exceeded", maxEntries)
		}
		types[kind] = append(types[kind], rr)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("local record line %d: %w", lineNumber+1, err)
	}
	return s, nil
}

func Load(path string) (*Store, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Parse(file)
}
