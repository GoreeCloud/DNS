// Package privatezone implements a pure DNS name-scoping boundary for
// future GoreeCloud DNS/VPN/Gateway private-service discovery integration.
// It neither resolves domains nor changes upstream AdGuard Home behavior.
package privatezone

import (
	"errors"
	"strings"
)

// Matcher is an immutable label-aware private-zone matcher.
type Matcher struct{ zones []string }

// NewMatcher validates explicitly provisioned private DNS suffixes.
// The bounded allowlist prevents accidental routing or claiming of public DNS
// suffixes as private. It does not confer authority to publish a service.
func NewMatcher(zones []string) (Matcher, error) {
	if len(zones) == 0 || len(zones) > 32 {
		return Matcher{}, errors.New("invalid_private_zone_count")
	}
	seen := make(map[string]bool, len(zones))
	normalized := make([]string, 0, len(zones))
	for _, raw := range zones {
		zone, err := normalizeDNSName(raw)
		if err != nil || !isPermittedPrivateSuffix(zone) {
			return Matcher{}, errors.New("invalid_private_dns_zone")
		}
		if !seen[zone] {
			seen[zone] = true
			normalized = append(normalized, zone)
		}
	}
	return Matcher{zones: normalized}, nil
}

// IsPrivate checks complete DNS-label suffix boundaries, not substrings.
// "publiclan" is not under "lan"; "lan.evil.test" is not under "lan".
func (m Matcher) IsPrivate(qname string) (bool, error) {
	name, err := normalizeDNSName(qname)
	if err != nil {
		return false, err
	}
	if len(m.zones) == 0 {
		return false, errors.New("private_zone_matcher_unconfigured")
	}
	for _, zone := range m.zones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true, nil
		}
	}
	return false, nil
}

func isPermittedPrivateSuffix(name string) bool {
	for _, suffix := range []string{"lan", "home.arpa", "internal"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeDNSName(raw string) (string, error) {
	if raw == "" || len(raw) > 254 || strings.TrimSpace(raw) != raw {
		return "", errors.New("invalid_dns_name")
	}
	s := strings.TrimSuffix(strings.ToLower(raw), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", errors.New("invalid_dns_name")
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid_dns_label")
		}
		for i, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			// DNS-SD owner names permit leading underscore labels such as _tcp.
			if c == '_' && i == 0 && len(label) > 1 {
				continue
			}
			return "", errors.New("invalid_dns_label")
		}
	}
	return s, nil
}
