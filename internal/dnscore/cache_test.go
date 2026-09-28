package dnscore

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Time() time.Time {
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

func TestNewMemoryCacheRejectsNegativeCapacity(t *testing.T) {
	if _, err := NewMemoryCache(-1); !errors.Is(err, ErrInvalidCacheCapacity) {
		t.Fatalf("NewMemoryCache() error = %v, want ErrInvalidCacheCapacity", err)
	}
}

func TestMemoryCacheNormalizesQuestionName(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()

	stored := Request{Name: "Example.TEST", Type: 1, Class: 1, ClientID: "client-a"}
	result := Result{
		Code: ResultSuccess,
		Records: []Record{{
			Name:  "example.test.",
			Type:  1,
			Class: 1,
			TTL:   60,
			Data:  "192.0.2.10",
		}},
	}
	if err := cache.Put(ctx, stored, result); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, found, err := cache.Lookup(ctx, Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"})
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found {
		t.Fatal("Lookup() found = false, want true")
	}
	if got.Records[0].Data != "192.0.2.10" {
		t.Fatalf("Lookup() record = %#v", got.Records[0])
	}
}

func TestMemoryCachePartitionsByClientID(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()

	request := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"}
	if err := cache.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: "192.0.2.11"}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if _, found, err := cache.Lookup(ctx, Request{Name: request.Name, Type: 1, Class: 1, ClientID: "client-b"}); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	} else if found {
		t.Fatal("Lookup() crossed client partition")
	}
}

func TestMemoryCacheExpiresAtMinimumTTLAndAgesRecords(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	result := Result{
		Code: ResultSuccess,
		Records: []Record{
			{Name: request.Name, Type: 1, Class: 1, TTL: 10, Data: "192.0.2.12"},
			{Name: request.Name, Type: 1, Class: 1, TTL: 30, Data: "192.0.2.13"},
		},
	}
	if err := cache.Put(ctx, request, result); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	clock.Advance(4*time.Second + 100*time.Millisecond)
	got, found, err := cache.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found {
		t.Fatal("Lookup() found = false before expiry")
	}
	if got.Records[0].TTL != 6 || got.Records[1].TTL != 26 {
		t.Fatalf("aged TTLs = [%d %d], want [6 26]", got.Records[0].TTL, got.Records[1].TTL)
	}

	clock.Advance(6 * time.Second)
	if _, found, err := cache.Lookup(ctx, request); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	} else if found {
		t.Fatal("Lookup() found = true after minimum TTL expiry")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after expiry cleanup", cache.Len())
	}
}

func TestMemoryCacheDoesNotStoreZeroTTLOrNonSuccessResults(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	for _, result := range []Result{
		{Code: ResultBlocked, Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}}},
		{Code: ResultFailure, Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}}},
		{Code: ResultSuccess},
		{Code: ResultSuccess, Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 0}}},
	} {
		if err := cache.Put(ctx, request, result); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", cache.Len())
	}
}

func TestMemoryCacheEvictsOldestEntryAtCapacity(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(2, clock.Time)
	ctx := context.Background()

	requests := []Request{
		{Name: "one.test.", Type: 1, Class: 1},
		{Name: "two.test.", Type: 1, Class: 1},
		{Name: "three.test.", Type: 1, Class: 1},
	}
	for i, request := range requests {
		if err := cache.Put(ctx, request, Result{
			Code:    ResultSuccess,
			Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: string(rune('a' + i))}},
		}); err != nil {
			t.Fatalf("Put(%q) error = %v", request.Name, err)
		}
	}

	if cache.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", cache.Len())
	}
	if _, found, err := cache.Lookup(ctx, requests[0]); err != nil {
		t.Fatalf("Lookup() error = %v", err)
	} else if found {
		t.Fatal("oldest entry was not evicted")
	}
	for _, request := range requests[1:] {
		if _, found, err := cache.Lookup(ctx, request); err != nil {
			t.Fatalf("Lookup(%q) error = %v", request.Name, err)
		} else if !found {
			t.Fatalf("Lookup(%q) found = false, want true", request.Name)
		}
	}
}

func TestMemoryCacheCopiesCallerOwnedRecords(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}
	records := []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: "192.0.2.20"}}

	if err := cache.Put(ctx, request, Result{Code: ResultSuccess, Records: records}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	records[0].Data = "198.51.100.99"

	first, found, err := cache.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found || first.Records[0].Data != "192.0.2.20" {
		t.Fatalf("cached result = %#v", first)
	}

	first.Records[0].Data = "203.0.113.44"
	second, found, err := cache.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	if !found || second.Records[0].Data != "192.0.2.20" {
		t.Fatalf("cached storage aliased returned result: %#v", second)
	}
}

func TestMemoryCacheFlush(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := cache.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	cache.Flush()
	if cache.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after Flush()", cache.Len())
	}
}

func TestMemoryCacheHonorsCancelledContext(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newMemoryCache(8, clock.Time)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := cache.Put(ctx, request, Result{Code: ResultSuccess}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context.Canceled", err)
	}
	if _, _, err := cache.Lookup(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup() error = %v, want context.Canceled", err)
	}
}
