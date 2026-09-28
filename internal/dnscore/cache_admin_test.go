package dnscore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryCacheInspectReturnsPrivacyMinimizedMetadata(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "Example.TEST", Type: 1, Class: 1, ClientID: "client-a"}

	if err := cache.Put(ctx, request, Result{
		Code: ResultSuccess,
		Records: []Record{
			{Name: "example.test.", Type: 1, Class: 1, TTL: 20, Data: "192.0.2.50"},
			{Name: "example.test.", Type: 1, Class: 1, TTL: 30, Data: "192.0.2.51"},
		},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	clock.Advance(4*time.Second + 100*time.Millisecond)
	info, err := cache.Inspect(ctx, Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !info.Present {
		t.Fatal("Inspect() Present = false, want true")
	}
	if info.RecordCount != 2 {
		t.Fatalf("Inspect() RecordCount = %d, want 2", info.RecordCount)
	}
	if info.RemainingTTL != 16 {
		t.Fatalf("Inspect() RemainingTTL = %d, want 16", info.RemainingTTL)
	}

	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Fatalf("Inspect() changed lookup counters: %#v", stats)
	}
}

func TestMemoryCacheInspectRespectsClientPartition(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()

	request := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"}
	if err := cache.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: "192.0.2.52"}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	info, err := cache.Inspect(ctx, Request{Name: request.Name, Type: 1, Class: 1, ClientID: "client-b"})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if info.Present {
		t.Fatal("Inspect() crossed client partition")
	}
}

func TestMemoryCacheInspectCleansExpiredWithoutHitOrMiss(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := cache.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 1}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	clock.Advance(time.Second)
	info, err := cache.Inspect(ctx, request)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if info.Present {
		t.Fatal("Inspect() Present = true after expiry")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", cache.Len())
	}

	stats := cache.Stats()
	if stats.Expirations != 1 || stats.Hits != 0 || stats.Misses != 0 {
		t.Fatalf("Stats() = %#v, want expirations=1 hits=0 misses=0", stats)
	}
}

func TestMemoryCacheInvalidateRemovesExactPartitionOnly(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	clientA := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"}
	clientB := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-b"}

	for _, request := range []Request{clientA, clientB} {
		if err := cache.Put(ctx, request, Result{
			Code:    ResultSuccess,
			Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}},
		}); err != nil {
			t.Fatalf("Put(%q) error = %v", request.ClientID, err)
		}
	}

	removed, err := cache.Invalidate(ctx, clientA)
	if err != nil {
		t.Fatalf("Invalidate() error = %v", err)
	}
	if !removed {
		t.Fatal("Invalidate() removed = false, want true")
	}

	infoA, err := cache.Inspect(ctx, clientA)
	if err != nil {
		t.Fatalf("Inspect(client-a) error = %v", err)
	}
	infoB, err := cache.Inspect(ctx, clientB)
	if err != nil {
		t.Fatalf("Inspect(client-b) error = %v", err)
	}
	if infoA.Present {
		t.Fatal("invalidated client-a entry is still present")
	}
	if !infoB.Present {
		t.Fatal("client-b entry was removed by client-a invalidation")
	}

	stats := cache.Stats()
	if stats.Invalidations != 1 || stats.Entries != 1 {
		t.Fatalf("Stats() = %#v, want invalidations=1 entries=1", stats)
	}
}

func TestMemoryCacheInvalidateMissingOrExpiredDoesNotCount(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	missing := Request{Name: "missing.test.", Type: 1, Class: 1}

	removed, err := cache.Invalidate(ctx, missing)
	if err != nil {
		t.Fatalf("Invalidate(missing) error = %v", err)
	}
	if removed {
		t.Fatal("Invalidate(missing) removed = true, want false")
	}

	expired := Request{Name: "expired.test.", Type: 1, Class: 1}
	if err := cache.Put(ctx, expired, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: expired.Name, Type: 1, Class: 1, TTL: 1}},
	}); err != nil {
		t.Fatalf("Put(expired) error = %v", err)
	}
	clock.Advance(time.Second)

	removed, err = cache.Invalidate(ctx, expired)
	if err != nil {
		t.Fatalf("Invalidate(expired) error = %v", err)
	}
	if removed {
		t.Fatal("Invalidate(expired) removed = true, want false")
	}

	stats := cache.Stats()
	if stats.Invalidations != 0 || stats.Expirations != 1 || stats.Entries != 0 {
		t.Fatalf("Stats() = %#v, want invalidations=0 expirations=1 entries=0", stats)
	}
}

func TestMemoryCacheAdministrationHonorsCancelledContextAndInvalidRequest(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := cache.Inspect(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Inspect() error = %v, want context.Canceled", err)
	}
	if _, err := cache.Invalidate(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Invalidate() error = %v, want context.Canceled", err)
	}

	bad := Request{Name: " ", Type: 1, Class: 1}
	if _, err := cache.Inspect(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Inspect(invalid) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := cache.Invalidate(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Invalidate(invalid) error = %v, want ErrInvalidRequest", err)
	}
}
