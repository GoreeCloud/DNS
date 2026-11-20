package server

import (
	"sync"
	"time"
)

// queryBudget is a process-wide token bucket, deliberately not keyed by
// client address or queried name. It stores no IPs, domain history, or
// persistent identifiers. It does not replace per-source firewall controls.
type queryBudget struct {
	mu       sync.Mutex
	tokens   float64
	rate     float64
	capacity float64
	last     time.Time
}

func newQueryBudget(qps, burst int, now time.Time) *queryBudget {
	return &queryBudget{
		tokens:   float64(burst),
		rate:     float64(qps),
		capacity: float64(burst),
		last:     now,
	}
}

// allow accepts one DNS request or fails closed without waiting for a
// resource budget. The caller chooses the time for deterministic testing.
func (b *queryBudget) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
