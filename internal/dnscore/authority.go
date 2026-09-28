package dnscore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var ErrInvalidAuthorityResult = errors.New("invalid DNS authority result")

type authorityKey struct {
	name     string
	qtype    uint16
	qclass   uint16
	clientID string
}

type MemoryAuthority struct {
	mu      sync.RWMutex
	entries map[authorityKey]Result
}

func NewMemoryAuthority() *MemoryAuthority {
	return &MemoryAuthority{
		entries: make(map[authorityKey]Result),
	}
}

func (a *MemoryAuthority) Lookup(ctx context.Context, request Request) (Result, bool, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, false, err
	}
	if err := request.Validate(); err != nil {
		return Result{}, false, err
	}

	key := makeAuthorityKey(request)

	a.mu.RLock()
	result, found := a.entries[key]
	if !found && key.clientID != "" {
		key.clientID = ""
		result, found = a.entries[key]
	}
	a.mu.RUnlock()

	if !found {
		return Result{}, false, nil
	}
	return copyAuthorityResult(result), true, nil
}

func (a *MemoryAuthority) Put(ctx context.Context, request Request, result Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if err := validateAuthorityResult(result); err != nil {
		return err
	}

	result = copyAuthorityResult(result)
	result.Source = ""

	a.mu.Lock()
	a.entries[makeAuthorityKey(request)] = result
	a.mu.Unlock()
	return nil
}

func (a *MemoryAuthority) Delete(ctx context.Context, request Request) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := request.Validate(); err != nil {
		return false, err
	}

	key := makeAuthorityKey(request)

	a.mu.Lock()
	_, found := a.entries[key]
	if found {
		delete(a.entries, key)
	}
	a.mu.Unlock()
	return found, nil
}

func (a *MemoryAuthority) Flush() {
	a.mu.Lock()
	clear(a.entries)
	a.mu.Unlock()
}

func (a *MemoryAuthority) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

func validateAuthorityResult(result Result) error {
	if result.Code != ResultSuccess {
		return fmt.Errorf("%w: result code must be %q", ErrInvalidAuthorityResult, ResultSuccess)
	}
	if len(result.Records) == 0 {
		return fmt.Errorf("%w: at least one record is required", ErrInvalidAuthorityResult)
	}
	for i, record := range result.Records {
		if strings.TrimSpace(record.Name) == "" {
			return fmt.Errorf("%w: record %d name is required", ErrInvalidAuthorityResult, i)
		}
		if record.Type == 0 {
			return fmt.Errorf("%w: record %d type must be non-zero", ErrInvalidAuthorityResult, i)
		}
		if record.Class == 0 {
			return fmt.Errorf("%w: record %d class must be non-zero", ErrInvalidAuthorityResult, i)
		}
	}
	return nil
}

func makeAuthorityKey(request Request) authorityKey {
	name := strings.ToLower(strings.TrimSpace(request.Name))
	name = strings.TrimSuffix(name, ".") + "."
	return authorityKey{
		name:     name,
		qtype:    request.Type,
		qclass:   request.Class,
		clientID: strings.TrimSpace(request.ClientID),
	}
}

func copyAuthorityResult(result Result) Result {
	result.Records = append([]Record(nil), result.Records...)
	return result
}
