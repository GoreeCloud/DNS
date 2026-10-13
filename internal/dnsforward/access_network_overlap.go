package dnsforward

import (
	"fmt"
	"net/netip"
	"sort"
)

type accessRangeEntry struct {
	prefix netip.Prefix
	source string
}

// validateAccessRangeOverlap rejects ambiguous allow/deny address ranges.
// The resolver uses allowlist precedence, so explicit denied addresses that
// intersect an allow rule would otherwise not apply as an administrator expects.
func validateAccessRangeOverlap(allowed, disallowed []string) error {
	parse := func(entries []string) []accessRangeEntry {
		ranges := make([]accessRangeEntry, 0, len(entries))
		for _, raw := range entries {
			prefix, ok := accessAddressRange(raw)
			if ok {
				ranges = append(ranges, accessRangeEntry{prefix: prefix, source: raw})
			}
		}
		sort.Slice(ranges, func(i, j int) bool {
			return ranges[i].prefix.Addr().Less(ranges[j].prefix.Addr())
		})
		return ranges
	}
	allowRanges, denyRanges := parse(allowed), parse(disallowed)
	for i, j := 0, 0; i < len(allowRanges) && j < len(denyRanges); {
		a, d := allowRanges[i], denyRanges[j]
		if a.prefix.Contains(d.prefix.Addr()) || d.prefix.Contains(a.prefix.Addr()) {
			return fmt.Errorf("allowed client range %q overlaps disallowed client range %q", a.source, d.source)
		}
		if a.prefix.Addr().Less(d.prefix.Addr()) {
			i++
		} else {
			j++
		}
	}
	return nil
}

// A single IP is represented as a host-length prefix. Interface zones are
// ignored for client identity, matching the runtime policy engine.
func accessAddressRange(value string) (netip.Prefix, bool) {
	if address, err := netip.ParseAddr(value); err == nil {
		address = normalizeAccessAddr(address)
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return normalizeAccessPrefix(prefix).Masked(), true
	}
	return netip.Prefix{}, false
}
