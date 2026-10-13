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
				if alias, ok := mappedIPv4Alias(prefix); ok {
					ranges = append(ranges, accessRangeEntry{prefix: alias, source: raw})
				}
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
		if accessRangesOverlap(a.prefix, d.prefix) {
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

// accessRangesOverlap considers the native IPv4 alias of IPv4-mapped IPv6
// ranges, including IPv6 prefixes wider than the mapped /96 boundary.
// Those broad IPv6 ranges remain IPv6 rules but also cover mapped clients.
func accessRangesOverlap(a, b netip.Prefix) bool {
	if a.Contains(b.Addr()) || b.Contains(a.Addr()) {
		return true
	}
	if a.Addr().Is4() && b.Addr().Is6() {
		return b.Contains(netip.AddrFrom16(a.Addr().As16()))
	}
	if b.Addr().Is4() && a.Addr().Is6() {
		return a.Contains(netip.AddrFrom16(b.Addr().As16()))
	}
	return false
}

// mappedIPv4Alias exposes the IPv4 identity of an IPv6 range that
// contains every mapped IPv4 address. It is used only for overlap sorting.
func mappedIPv4Alias(prefix netip.Prefix) (netip.Prefix, bool) {
	if prefix.Addr().Is6() && prefix.Bits() < 96 &&
		prefix.Contains(netip.MustParseAddr("::ffff:0.0.0.0")) {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	return netip.Prefix{}, false
}
