package dnscore

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type policyFunc func(context.Context, Request) (PolicyDecision, error)

func (f policyFunc) Evaluate(ctx context.Context, request Request) (PolicyDecision, error) {
	return f(ctx, request)
}

type lookupFunc func(context.Context, Request) (Result, bool, error)

func (f lookupFunc) Lookup(ctx context.Context, request Request) (Result, bool, error) {
	return f(ctx, request)
}

type resolverFunc func(context.Context, Request) (Result, error)

func (f resolverFunc) Resolve(ctx context.Context, request Request) (Result, error) {
	return f(ctx, request)
}

func validRequest() Request {
	return Request{Name: "example.test.", Type: 1, Class: 1, ClientID: "synthetic-client"}
}

func allowPolicy(calls *[]string) Policy {
	return policyFunc(func(context.Context, Request) (PolicyDecision, error) {
		*calls = append(*calls, "policy")
		return PolicyDecision{Action: PolicyAllow}, nil
	})
}

func missLookup(name string, calls *[]string) lookupFunc {
	return func(context.Context, Request) (Result, bool, error) {
		*calls = append(*calls, name)
		return Result{}, false, nil
	}
}

func TestNewPipelineRequiresEveryStage(t *testing.T) {
	calls := []string{}
	policy := allowPolicy(&calls)
	lookup := missLookup("lookup", &calls)
	resolver := resolverFunc(func(context.Context, Request) (Result, error) {
		return Result{Code: ResultSuccess}, nil
	})

	tests := []struct {
		name      string
		policy    Policy
		authority Authority
		cache     Cache
		resolver  Resolver
	}{
		{name: "policy", authority: lookup, cache: lookup, resolver: resolver},
		{name: "authority", policy: policy, cache: lookup, resolver: resolver},
		{name: "cache", policy: policy, authority: lookup, resolver: resolver},
		{name: "resolver", policy: policy, authority: lookup, cache: lookup},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPipeline(tc.policy, tc.authority, tc.cache, tc.resolver); !errors.Is(err, ErrMissingStage) {
				t.Fatalf("NewPipeline() error = %v, want ErrMissingStage", err)
			}
		})
	}
}

func TestResolveRejectsInvalidRequestBeforeStages(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		missLookup("authority", &calls),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{Code: ResultSuccess}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	_, err = pipeline.Resolve(context.Background(), Request{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Resolve() error = %v, want ErrInvalidRequest", err)
	}
	if len(calls) != 0 {
		t.Fatalf("stages called for invalid request: %v", calls)
	}
}

func TestResolvePolicyBlockShortCircuits(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		policyFunc(func(context.Context, Request) (PolicyDecision, error) {
			calls = append(calls, "policy")
			return PolicyDecision{Action: PolicyBlock}, nil
		}),
		missLookup("authority", &calls),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	result, err := pipeline.Resolve(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if result.Code != ResultBlocked || result.Source != SourcePolicy {
		t.Fatalf("Resolve() result = %#v, want blocked policy result", result)
	}
	if !reflect.DeepEqual(calls, []string{"policy"}) {
		t.Fatalf("call order = %v, want [policy]", calls)
	}
}

func TestResolveRejectsUnknownPolicyAction(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		policyFunc(func(context.Context, Request) (PolicyDecision, error) {
			calls = append(calls, "policy")
			return PolicyDecision{Action: PolicyAction("unknown")}, nil
		}),
		missLookup("authority", &calls),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	_, err = pipeline.Resolve(context.Background(), validRequest())
	if !errors.Is(err, ErrPolicyAction) {
		t.Fatalf("Resolve() error = %v, want ErrPolicyAction", err)
	}
	if !reflect.DeepEqual(calls, []string{"policy"}) {
		t.Fatalf("call order = %v, want [policy]", calls)
	}
}

func TestResolveUsesAuthorityBeforeCacheAndResolver(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		lookupFunc(func(context.Context, Request) (Result, bool, error) {
			calls = append(calls, "authority")
			return Result{Code: ResultSuccess, Records: []Record{{Name: "example.test.", Type: 1, Class: 1, TTL: 60, Data: "192.0.2.10"}}}, true, nil
		}),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	result, err := pipeline.Resolve(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if result.Source != SourceAuthority {
		t.Fatalf("Source = %q, want %q", result.Source, SourceAuthority)
	}
	if !reflect.DeepEqual(calls, []string{"policy", "authority"}) {
		t.Fatalf("call order = %v", calls)
	}
}

func TestResolveUsesCacheAfterAuthorityMiss(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		missLookup("authority", &calls),
		lookupFunc(func(context.Context, Request) (Result, bool, error) {
			calls = append(calls, "cache")
			return Result{Code: ResultSuccess, Source: SourceResolver}, true, nil
		}),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	result, err := pipeline.Resolve(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if result.Source != SourceCache {
		t.Fatalf("Source = %q, want %q", result.Source, SourceCache)
	}
	if !reflect.DeepEqual(calls, []string{"policy", "authority", "cache"}) {
		t.Fatalf("call order = %v", calls)
	}
}

func TestResolveFallsBackToResolver(t *testing.T) {
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		missLookup("authority", &calls),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{Code: ResultSuccess}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	result, err := pipeline.Resolve(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if result.Source != SourceResolver {
		t.Fatalf("Source = %q, want %q", result.Source, SourceResolver)
	}
	want := []string{"policy", "authority", "cache", "resolver"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestResolveStopsOnStageError(t *testing.T) {
	sentinel := errors.New("synthetic authority failure")
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		lookupFunc(func(context.Context, Request) (Result, bool, error) {
			calls = append(calls, "authority")
			return Result{}, false, sentinel
		}),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			calls = append(calls, "resolver")
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	_, err = pipeline.Resolve(context.Background(), validRequest())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Resolve() error = %v, want sentinel", err)
	}
	if !reflect.DeepEqual(calls, []string{"policy", "authority"}) {
		t.Fatalf("call order = %v, want stop after authority", calls)
	}
}

func TestResolveCopiesReturnedRecords(t *testing.T) {
	records := []Record{{Name: "example.test.", Type: 1, Class: 1, TTL: 60, Data: "192.0.2.20"}}
	calls := []string{}
	pipeline, err := NewPipeline(
		allowPolicy(&calls),
		lookupFunc(func(context.Context, Request) (Result, bool, error) {
			return Result{Code: ResultSuccess, Records: records}, true, nil
		}),
		missLookup("cache", &calls),
		resolverFunc(func(context.Context, Request) (Result, error) {
			return Result{}, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}

	result, err := pipeline.Resolve(context.Background(), validRequest())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	records[0].Data = "198.51.100.99"
	if result.Records[0].Data != "192.0.2.20" {
		t.Fatalf("returned records alias stage-owned storage: %#v", result.Records)
	}
}
