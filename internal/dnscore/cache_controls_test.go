package dnscore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewMemoryCacheWithConfigRejectsInvalidTTLRange(t *testing.T) {
	_, err := NewMemoryCacheWithConfig(CacheConfig{MinTTL: 60, MaxTTL: 30})
	if !errors.Is(err, ErrInvalidCacheTTLRange) {
		t.Fatalf("NewMemoryCacheWithConfig() error = %v, want ErrInvalidCacheTTLRange", err)
	}
}

func TestMemoryCacheAppliesTTLBoundsBeforeExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCacheWithConfig(CacheConfig{MaxEntries: 8, MinTTL: 10, MaxTTL: 30}, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := cache.Put(ctx, request, Result{
		Code: ResultSuccess,
		Records: []Record{
			{Name: request.Name, Type: 1, Class: 1, TTL: 5, Data: "192.0.2.30"},
			{Name: request.Name, Type: 1, Class: 1, TTL: 120, Data: "192.0.2.31"},
		},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	first, found, err := cache.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found {
		t.Fatal("Lookup() found = false, want true")
	}
	if first.Records[0].TTL != 10 || first.Records[1].TTL != 30 {
		t.Fatalf("bounded TTLs = [%d %d], want [10 30]", first.Records[0].TTL, first.Records[1].TTL)
	}

	clock.Advance(9 * time.Second)
	aged, found, err := cache.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("aged Lookup() error = %v", err)
	}
	if !found {
		t.Fatal("aged Lookup() found = false before minimum TTL expiry")
	}
	if aged.Records[0].TTL != 1 || aged.Records[1].TTL != 21 {
		t.Fatalf("aged TTLs = [%d %d], want [1 21]", aged.Records[0].TTL, aged.Records[1].TTL)
	}

	clock.Advance(time.Second)
	if _, found, err := cache.Lookup(ctx, request); err != nil {
		t.Fatalf("expired Lookup() error = %v", err)
	} else if found {
		t.Fatal("Lookup() found = true at minimum bounded TTL expiry")
	}
}

func TestMemoryCacheTTLBoundsDoNotMakeZeroTTLsCacheable(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCacheWithConfig(CacheConfig{MinTTL: 30}, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := cache.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 0}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", cache.Len())
	}
}

func TestMemoryCacheStatsAreAggregateOnly(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCacheWithConfig(CacheConfig{MaxEntries: 1}, clock.Time)
	ctx := context.Background()
	one := Request{Name: "one.test.", Type: 1, Class: 1, ClientID: "client-a"}
	two := Request{Name: "two.test.", Type: 1, Class: 1, ClientID: "client-b"}

	if _, found, err := cache.Lookup(ctx, one); err != nil || found {
		t.Fatalf("initial Lookup() = found %v, error %v", found, err)
	}
	if err := cache.Put(ctx, one, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: one.Name, Type: 1, Class: 1, TTL: 2}},
	}); err != nil {
		t.Fatalf("Put(one) error = %v", err)
	}
	if _, found, err := cache.Lookup(ctx, one); err != nil || !found {
		t.Fatalf("cached Lookup(one) = found %v, error %v", found, err)
	}
	if err := cache.Put(ctx, two, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: two.Name, Type: 1, Class: 1, TTL: 1}},
	}); err != nil {
		t.Fatalf("Put(two) error = %v", err)
	}
	clock.Advance(time.Second)
	if _, found, err := cache.Lookup(ctx, two); err != nil || found {
		t.Fatalf("expired Lookup(two) = found %v, error %v", found, err)
	}

	stats := cache.Stats()
	if stats.Entries != 0 {
		t.Fatalf("Entries = %d, want 0", stats.Entries)
	}
	if stats.Hits != 1 || stats.Misses != 2 || stats.Stores != 2 || stats.Evictions != 1 || stats.Expirations != 1 {
		t.Fatalf("Stats() = %#v, want hits=1 misses=2 stores=2 evictions=1 expirations=1", stats)
	}
}

func TestMemoryCacheOverwriteDoesNotCountAsEviction(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCacheWithConfig(CacheConfig{MaxEntries: 1}, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	for _, data := range []string{"192.0.2.40", "192.0.2.41"} {
		if err := cache.Put(ctx, request, Result{
			Code:    ResultSuccess,
			Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: data}},
		}); err != nil {
			t.Fatalf("Put(%q) error = %v", data, err)
		}
	}

	stats := cache.Stats()
	if stats.Stores != 2 || stats.Evictions != 0 || stats.Entries != 1 {
		t.Fatalf("Stats() = %#v, want stores=2 evictions=0 entries=1", stats)
	}
}
