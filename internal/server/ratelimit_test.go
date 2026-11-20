package server

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestGlobalQueryBudget(t *testing.T) {
	now := time.Unix(0, 0)
	b := newQueryBudget(2, 3, now)
	for i := 0; i < 3; i++ {
		if !b.allow(now) {
			t.Fatalf("initial request %d rejected", i)
		}
	}
	if b.allow(now) {
		t.Fatal("burst cap failed")
	}
	if !b.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("expected one replenished token")
	}
	if b.allow(now.Add(500 * time.Millisecond)) {
		t.Fatal("more than the replenished tokens were granted")
	}
	for i := 0; i < 3; i++ {
		if !b.allow(now.Add(10 * time.Second)) {
			t.Fatal("budget did not replenish to capacity")
		}
	}
	if b.allow(now.Add(10 * time.Second)) {
		t.Fatal("budget exceeded burst size")
	}
}

func TestConcurrentGlobalBudget(t *testing.T) {
	now := time.Unix(0, 0)
	b := newQueryBudget(1, 4, now)
	var accepted atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.allow(now) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 4 {
		t.Fatalf("accepted %d queries; expected exactly 4", accepted.Load())
	}
}

func TestDNSBudgetAndACLPrecedence(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.RateQPS = 1
	cfg.RateBurst = 1
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	msg.SetQuestion("blocked.test.", dns.TypeA)
	unauthorized := &writer{remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 2222}}
	s.ServeDNS(unauthorized, msg)
	if unauthorized.answer.Rcode != dns.RcodeRefused || s.refused.Load() != 1 ||
		s.rateLimited.Load() != 0 {
		t.Fatal("CIDR restriction did not precede budget accounting")
	}
	first := new(writer)
	s.ServeDNS(first, msg)
	second := new(writer)
	s.ServeDNS(second, msg)
	if first.answer.Rcode != dns.RcodeNameError || second.answer.Rcode != dns.RcodeRefused {
		t.Fatalf("unexpected budget response: first=%d second=%d", first.answer.Rcode, second.answer.Rcode)
	}
	if s.rateLimited.Load() != 1 || s.blocked.Load() != 1 {
		t.Fatal("expected separate blocked and rate-limited aggregates")
	}
}

func TestDNSRateConfiguration(t *testing.T) {
	base, _ := testConfig(t)
	for _, entry := range []struct {
		rate, burst int
	}{
		{-1, 10}, {20001, 10}, {100, -1}, {100, 50001},
	} {
		cfg := base
		cfg.RateQPS = entry.rate
		cfg.RateBurst = entry.burst
		if _, err := New(cfg); err == nil {
			t.Fatalf("invalid rate configuration accepted: %+v", entry)
		}
	}
	s, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if s.config.RateQPS != 500 || s.config.RateBurst != 1000 {
		t.Fatal("missing default global rate protection")
	}
}
