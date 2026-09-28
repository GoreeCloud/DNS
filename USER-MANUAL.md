# GoreeCloud DNS — User Manual

## Current Development use

GoreeCloud DNS is not yet a production DNS server. The current executable exposes only loopback operational health/readiness endpoints.

Run source checks with:

```bash
go test ./...
go vet ./...
go build ./cmd/goreecloud-dns
```

Running `go run ./cmd/goreecloud-dns` starts the Development control plane on `127.0.0.1:8853` by default. It does not open DNS port 53 or answer DNS queries.

## Native core

The repository includes an in-process request pipeline under `internal/dnscore` plus a process-local `MemoryCache` implementation. They are exercised only through source/tests at this stage and are not wired to network traffic. The cache is ephemeral and is cleared when the process exits. Source callers may configure entry capacity and minimum/maximum TTL clamps, and may read aggregate hit/miss/store/eviction/expiration counters; there is no administrative cache endpoint yet.

No production DNS listener, client configuration, filtering policy, resolver cutover, or Stable operation is available from this Development milestone.
