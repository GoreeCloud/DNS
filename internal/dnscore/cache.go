package dnscore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrInvalidCacheCapacity = errors.New("DNS cache capacity must be non-negative")
	ErrInvalidCacheTTLRange = errors.New("DNS cache minimum TTL must not exceed maximum TTL")
)

type CacheConfig struct {
	MaxEntries int
	MinTTL     uint32
	MaxTTL     uint32
}

type CacheStats struct {
	Entries     int
	Hits        uint64
	Misses      uint64
	Stores      uint64
	Evictions   uint64
	Expirations uint64
}

type cacheKey struct {
	name     string
	qtype    uint16
	qclass   uint16
	clientID string
}

type cacheEntry struct {
	result    Result
	storedAt  time.Time
	expiresAt time.Time
	sequence  uint64
}

type MemoryCache struct {
	mu          sync.RWMutex
	entries     map[cacheKey]cacheEntry
	config      CacheConfig
	now         func() time.Time
	sequence    uint64
	hits        atomic.Uint64
	misses      atomic.Uint64
	stores      atomic.Uint64
	evictions   atomic.Uint64
	expirations atomic.Uint64
}

func NewMemoryCache(maxEntries int) (*MemoryCache, error) {
	return NewMemoryCacheWithConfig(CacheConfig{MaxEntries: maxEntries})
}

func NewMemoryCacheWithConfig(config CacheConfig) (*MemoryCache, error) {
	if err := validateCacheConfig(config); err != nil {
		return nil, err
	}
	return newMemoryCacheWithConfig(config, time.Now), nil
}

func newMemoryCache(maxEntries int, now func() time.Time) *MemoryCache {
	return newMemoryCacheWithConfig(CacheConfig{MaxEntries: maxEntries}, now)
}

func newMemoryCacheWithConfig(config CacheConfig, now func() time.Time) *MemoryCache {
	return &MemoryCache{
		entries: make(map[cacheKey]cacheEntry),
		config:  config,
		now:     now,
	}
}

func validateCacheConfig(config CacheConfig) error {
	if config.MaxEntries < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidCacheCapacity, config.MaxEntries)
	}
	if config.MaxTTL > 0 && config.MinTTL > config.MaxTTL {
		return fmt.Errorf("%w: min=%d max=%d", ErrInvalidCacheTTLRange, config.MinTTL, config.MaxTTL)
	}
	return nil
}

func (c *MemoryCache) Lookup(ctx context.Context, request Request) (Result, bool, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, false, err
	}
	if err := request.Validate(); err != nil {
		return Result{}, false, err
	}

	key := makeCacheKey(request)
	now := c.now()

	c.mu.RLock()
	entry, found := c.entries[key]
	c.mu.RUnlock()
	if !found {
		c.misses.Add(1)
		return Result{}, false, nil
	}
	if !now.Before(entry.expiresAt) {
		c.mu.Lock()
		current, currentFound := c.entries[key]
		if !currentFound {
			c.mu.Unlock()
			c.misses.Add(1)
			return Result{}, false, nil
		}
		if !now.Before(current.expiresAt) {
			delete(c.entries, key)
			c.mu.Unlock()
			c.expirations.Add(1)
			c.misses.Add(1)
			return Result{}, false, nil
		}
		entry = current
		c.mu.Unlock()
	}

	c.hits.Add(1)
	return ageResult(entry.result, now.Sub(entry.storedAt)), true, nil
}

func (c *MemoryCache) Put(ctx context.Context, request Request, result Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if result.Code != ResultSuccess || len(result.Records) == 0 {
		return nil
	}

	for _, record := range result.Records {
		if record.TTL == 0 {
			return nil
		}
	}

	storedResult := copyResult(result)
	applyTTLBounds(storedResult.Records, c.config.MinTTL, c.config.MaxTTL)
	ttl, ok := minimumTTL(storedResult.Records)
	if !ok {
		return nil
	}

	now := c.now()
	key := makeCacheKey(request)
	entry := cacheEntry{
		result:    storedResult,
		storedAt:  now,
		expiresAt: now.Add(time.Duration(ttl) * time.Second),
	}

	c.mu.Lock()
	c.sequence++
	entry.sequence = c.sequence

	if c.config.MaxEntries > 0 {
		if _, exists := c.entries[key]; !exists && len(c.entries) >= c.config.MaxEntries {
			c.evictOldestLocked()
			c.evictions.Add(1)
		}
	}
	c.entries[key] = entry
	c.mu.Unlock()

	c.stores.Add(1)
	return nil
}

func (c *MemoryCache) Flush() {
	c.mu.Lock()
	clear(c.entries)
	c.mu.Unlock()
}

func (c *MemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *MemoryCache) Stats() CacheStats {
	return CacheStats{
		Entries:     c.Len(),
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Stores:      c.stores.Load(),
		Evictions:   c.evictions.Load(),
		Expirations: c.expirations.Load(),
	}
}

func (c *MemoryCache) evictOldestLocked() {
	var oldestKey cacheKey
	var oldestSequence uint64
	first := true

	for key, entry := range c.entries {
		if first || entry.sequence < oldestSequence {
			oldestKey = key
			oldestSequence = entry.sequence
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}

func makeCacheKey(request Request) cacheKey {
	name := strings.ToLower(strings.TrimSpace(request.Name))
	name = strings.TrimSuffix(name, ".") + "."
	return cacheKey{
		name:     name,
		qtype:    request.Type,
		qclass:   request.Class,
		clientID: strings.TrimSpace(request.ClientID),
	}
}

func minimumTTL(records []Record) (uint32, bool) {
	var minimum uint32
	for i, record := range records {
		if record.TTL == 0 {
			return 0, false
		}
		if i == 0 || record.TTL < minimum {
			minimum = record.TTL
		}
	}
	return minimum, len(records) > 0
}

func applyTTLBounds(records []Record, minTTL, maxTTL uint32) {
	for i := range records {
		ttl := records[i].TTL
		if minTTL > 0 && ttl < minTTL {
			ttl = minTTL
		}
		if maxTTL > 0 && ttl > maxTTL {
			ttl = maxTTL
		}
		records[i].TTL = ttl
	}
}

func ageResult(result Result, elapsed time.Duration) Result {
	aged := copyResult(result)
	for i := range aged.Records {
		remaining := time.Duration(aged.Records[i].TTL)*time.Second - elapsed
		if remaining <= 0 {
			aged.Records[i].TTL = 0
			continue
		}
		aged.Records[i].TTL = uint32(math.Ceil(remaining.Seconds()))
	}
	return aged
}

func copyResult(result Result) Result {
	result.Records = append([]Record(nil), result.Records...)
	return result
}
