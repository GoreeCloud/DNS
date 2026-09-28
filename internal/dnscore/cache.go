package dnscore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

var ErrInvalidCacheCapacity = errors.New("DNS cache capacity must be non-negative")

type cacheKey struct {
	name     string
	qtype    uint16
	qclass   uint16
	clientID string
}

type cacheEntry struct {
	result     Result
	storedAt   time.Time
	expiresAt  time.Time
	sequence   uint64
}

type MemoryCache struct {
	mu         sync.RWMutex
	entries    map[cacheKey]cacheEntry
	maxEntries int
	now        func() time.Time
	sequence   uint64
}

func NewMemoryCache(maxEntries int) (*MemoryCache, error) {
	if maxEntries < 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidCacheCapacity, maxEntries)
	}
	return newMemoryCache(maxEntries, time.Now), nil
}

func newMemoryCache(maxEntries int, now func() time.Time) *MemoryCache {
	return &MemoryCache{
		entries:    make(map[cacheKey]cacheEntry),
		maxEntries: maxEntries,
		now:        now,
	}
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
		return Result{}, false, nil
	}
	if !now.Before(entry.expiresAt) {
		c.mu.Lock()
		if current, ok := c.entries[key]; ok && !now.Before(current.expiresAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return Result{}, false, nil
	}

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

	ttl, ok := minimumTTL(result.Records)
	if !ok {
		return nil
	}

	now := c.now()
	key := makeCacheKey(request)
	entry := cacheEntry{
		result:    copyResult(result),
		storedAt:  now,
		expiresAt: now.Add(time.Duration(ttl) * time.Second),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.sequence++
	entry.sequence = c.sequence

	if c.maxEntries > 0 {
		if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
			c.evictOldestLocked()
		}
	}
	c.entries[key] = entry
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
