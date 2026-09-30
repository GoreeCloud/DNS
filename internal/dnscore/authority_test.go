package dnscore

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryAuthorityGlobalAndClientOverridePrecedence(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	global := Request{Name: "Example.TEST", Type: 1, Class: 1}
	clientA := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"}
	clientB := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-b"}

	if err := authority.Put(ctx, global, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: "example.test.", Type: 1, Class: 1, TTL: 300, Data: "192.0.2.60"}},
	}); err != nil {
		t.Fatalf("Put(global) error = %v", err)
	}

	got, found, err := authority.Lookup(ctx, clientA)
	if err != nil {
		t.Fatalf("Lookup(client-a global fallback) error = %v", err)
	}
	if !found || got.Records[0].Data != "192.0.2.60" {
		t.Fatalf("Lookup(client-a global fallback) = %#v, found %v", got, found)
	}

	if err := authority.Put(ctx, clientA, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: "example.test.", Type: 1, Class: 1, TTL: 60, Data: "192.0.2.61"}},
	}); err != nil {
		t.Fatalf("Put(client-a) error = %v", err)
	}

	got, found, err = authority.Lookup(ctx, clientA)
	if err != nil {
		t.Fatalf("Lookup(client-a override) error = %v", err)
	}
	if !found || got.Records[0].Data != "192.0.2.61" {
		t.Fatalf("Lookup(client-a override) = %#v, found %v", got, found)
	}

	got, found, err = authority.Lookup(ctx, clientB)
	if err != nil {
		t.Fatalf("Lookup(client-b global fallback) error = %v", err)
	}
	if !found || got.Records[0].Data != "192.0.2.60" {
		t.Fatalf("Lookup(client-b global fallback) = %#v, found %v", got, found)
	}
}

func TestMemoryAuthorityDeleteIsExactPartitionOnly(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	global := Request{Name: "example.test.", Type: 1, Class: 1}
	client := Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "client-a"}

	for _, item := range []struct {
		request Request
		data    string
	}{
		{request: global, data: "192.0.2.70"},
		{request: client, data: "192.0.2.71"},
	} {
		if err := authority.Put(ctx, item.request, Result{
			Code:    ResultSuccess,
			Records: []Record{{Name: item.request.Name, Type: 1, Class: 1, TTL: 60, Data: item.data}},
		}); err != nil {
			t.Fatalf("Put(%q) error = %v", item.request.ClientID, err)
		}
	}

	deleted, err := authority.Delete(ctx, client)
	if err != nil {
		t.Fatalf("Delete(client) error = %v", err)
	}
	if !deleted {
		t.Fatal("Delete(client) deleted = false, want true")
	}

	got, found, err := authority.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup(client after override delete) error = %v", err)
	}
	if !found || got.Records[0].Data != "192.0.2.70" {
		t.Fatalf("Lookup(client after override delete) = %#v, found %v", got, found)
	}

	deleted, err = authority.Delete(ctx, client)
	if err != nil {
		t.Fatalf("second Delete(client) error = %v", err)
	}
	if deleted {
		t.Fatal("second Delete(client) removed global fallback")
	}
	if authority.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", authority.Len())
	}
}

func TestMemoryAuthorityCopiesCallerOwnedRecordsAndClearsSource(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}
	records := []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60, Data: "192.0.2.80"}}

	if err := authority.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: records,
		Source:  SourceResolver,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	records[0].Data = "198.51.100.80"

	first, found, err := authority.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found {
		t.Fatal("Lookup() found = false, want true")
	}
	if first.Source != "" {
		t.Fatalf("Lookup() source = %q, want empty source before pipeline attribution", first.Source)
	}
	if first.Records[0].Data != "192.0.2.80" {
		t.Fatalf("Lookup() record = %#v", first.Records[0])
	}

	first.Records[0].Data = "203.0.113.80"
	second, found, err := authority.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	if !found || second.Records[0].Data != "192.0.2.80" {
		t.Fatalf("stored result was aliased: %#v", second)
	}
}

func TestMemoryAuthorityRejectsInvalidResults(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	tests := []struct {
		name   string
		result Result
	}{
		{name: "non-success", result: Result{Code: ResultFailure, Records: []Record{{Name: request.Name, Type: 1, Class: 1}}}},
		{name: "empty", result: Result{Code: ResultSuccess}},
		{name: "blank-record-name", result: Result{Code: ResultSuccess, Records: []Record{{Name: " ", Type: 1, Class: 1}}}},
		{name: "zero-record-type", result: Result{Code: ResultSuccess, Records: []Record{{Name: request.Name, Type: 0, Class: 1}}}},
		{name: "zero-record-class", result: Result{Code: ResultSuccess, Records: []Record{{Name: request.Name, Type: 1, Class: 0}}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := authority.Put(ctx, request, tc.result); !errors.Is(err, ErrInvalidAuthorityResult) {
				t.Fatalf("Put() error = %v, want ErrInvalidAuthorityResult", err)
			}
		})
	}
	if authority.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after rejected results", authority.Len())
	}
}

func TestMemoryAuthorityAllowsZeroTTLRecords(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := authority.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 0, Data: "192.0.2.90"}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, found, err := authority.Lookup(ctx, request)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !found || got.Records[0].TTL != 0 {
		t.Fatalf("Lookup() = %#v, found %v, want zero-TTL authoritative record", got, found)
	}
}

func TestMemoryAuthorityFlush(t *testing.T) {
	authority := NewMemoryAuthority()
	ctx := context.Background()
	request := Request{Name: "example.test.", Type: 1, Class: 1}

	if err := authority.Put(ctx, request, Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}},
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	authority.Flush()
	if authority.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after Flush()", authority.Len())
	}
}

func TestMemoryAuthorityHonorsCancelledContextAndInvalidRequest(t *testing.T) {
	authority := NewMemoryAuthority()
	request := Request{Name: "example.test.", Type: 1, Class: 1}
	result := Result{
		Code:    ResultSuccess,
		Records: []Record{{Name: request.Name, Type: 1, Class: 1, TTL: 60}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := authority.Lookup(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup() error = %v, want context.Canceled", err)
	}
	if err := authority.Put(ctx, request, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put() error = %v, want context.Canceled", err)
	}
	if _, err := authority.Delete(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v, want context.Canceled", err)
	}

	bad := Request{Name: " ", Type: 1, Class: 1}
	if _, _, err := authority.Lookup(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Lookup(invalid) error = %v, want ErrInvalidRequest", err)
	}
	if err := authority.Put(context.Background(), bad, result); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Put(invalid) error = %v, want ErrInvalidRequest", err)
	}
	if _, err := authority.Delete(context.Background(), bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Delete(invalid) error = %v, want ErrInvalidRequest", err)
	}
}
