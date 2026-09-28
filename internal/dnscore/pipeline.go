package dnscore

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidRequest = errors.New("invalid DNS core request")
	ErrMissingStage   = errors.New("DNS core pipeline stage is required")
	ErrPolicyAction   = errors.New("unsupported DNS policy action")
)

type Source string

const (
	SourcePolicy    Source = "policy"
	SourceAuthority Source = "authority"
	SourceCache     Source = "cache"
	SourceResolver  Source = "resolver"
)

type ResultCode string

const (
	ResultSuccess ResultCode = "success"
	ResultBlocked ResultCode = "blocked"
	ResultFailure ResultCode = "failure"
)

type Request struct {
	Name     string
	Type     uint16
	Class    uint16
	ClientID string
}

func (r Request) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}
	if r.Type == 0 {
		return fmt.Errorf("%w: type must be non-zero", ErrInvalidRequest)
	}
	if r.Class == 0 {
		return fmt.Errorf("%w: class must be non-zero", ErrInvalidRequest)
	}
	return nil
}

type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

type Result struct {
	Code    ResultCode
	Records []Record
	Source  Source
}

type PolicyAction string

const (
	PolicyAllow PolicyAction = "allow"
	PolicyBlock PolicyAction = "block"
)

type PolicyDecision struct {
	Action PolicyAction
	Result Result
}

type Policy interface {
	Evaluate(context.Context, Request) (PolicyDecision, error)
}

type Authority interface {
	Lookup(context.Context, Request) (Result, bool, error)
}

type Cache interface {
	Lookup(context.Context, Request) (Result, bool, error)
}

type Resolver interface {
	Resolve(context.Context, Request) (Result, error)
}

type Pipeline struct {
	policy    Policy
	authority Authority
	cache     Cache
	resolver  Resolver
}

func NewPipeline(policy Policy, authority Authority, cache Cache, resolver Resolver) (*Pipeline, error) {
	if policy == nil {
		return nil, fmt.Errorf("%w: policy", ErrMissingStage)
	}
	if authority == nil {
		return nil, fmt.Errorf("%w: authority", ErrMissingStage)
	}
	if cache == nil {
		return nil, fmt.Errorf("%w: cache", ErrMissingStage)
	}
	if resolver == nil {
		return nil, fmt.Errorf("%w: resolver", ErrMissingStage)
	}
	return &Pipeline{
		policy:    policy,
		authority: authority,
		cache:     cache,
		resolver:  resolver,
	}, nil
}

func (p *Pipeline) Resolve(ctx context.Context, request Request) (Result, error) {
	if err := request.Validate(); err != nil {
		return Result{}, err
	}

	decision, err := p.policy.Evaluate(ctx, request)
	if err != nil {
		return Result{}, fmt.Errorf("policy stage: %w", err)
	}
	switch decision.Action {
	case PolicyBlock:
		result := decision.Result
		if result.Code == "" {
			result.Code = ResultBlocked
		}
		return withSource(result, SourcePolicy), nil
	case PolicyAllow:
		// Continue through authoritative, cache, and resolver stages.
	default:
		return Result{}, fmt.Errorf("%w: %q", ErrPolicyAction, decision.Action)
	}

	if result, found, err := p.authority.Lookup(ctx, request); err != nil {
		return Result{}, fmt.Errorf("authority stage: %w", err)
	} else if found {
		return withSource(result, SourceAuthority), nil
	}

	if result, found, err := p.cache.Lookup(ctx, request); err != nil {
		return Result{}, fmt.Errorf("cache stage: %w", err)
	} else if found {
		return withSource(result, SourceCache), nil
	}

	result, err := p.resolver.Resolve(ctx, request)
	if err != nil {
		return Result{}, fmt.Errorf("resolver stage: %w", err)
	}
	return withSource(result, SourceResolver), nil
}

func withSource(result Result, source Source) Result {
	result.Source = source
	if result.Records != nil {
		result.Records = append([]Record(nil), result.Records...)
	}
	return result
}
