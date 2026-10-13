package dnsforward

import "net/netip"

// normalizeAccessAddr compares an IPv4-mapped IPv6 socket identity with its
// native IPv4 form. Interface zones are local routing hints, not client IDs.
func normalizeAccessAddr(ip netip.Addr) netip.Addr {
	return ip.WithZone("").Unmap()
}

// normalizeAccessPrefix canonicalizes only networks wholly within the mapped
// IPv4 address family. Broader IPv6 ranges retain their original meaning.
func normalizeAccessPrefix(prefix netip.Prefix) netip.Prefix {
	if !prefix.IsValid() {
		return prefix
	}
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		masked := prefix.Masked()
		return netip.PrefixFrom(masked.Addr().Unmap(), masked.Bits()-96)
	}
	return prefix
}
