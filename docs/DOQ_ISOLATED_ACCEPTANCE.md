# Isolated DoQ source probe — development acceptance

**Status:** A bounded, independently compiled **source-side test client**, not a successful real DNS-over-QUIC service acceptance, deployed service, release, or substitute for [issue #11](https://github.com/GoreeCloud/DNS/issues/11).

## Protocol and security contract

`tests/DoQProbe/Program.cs` uses .NET 10's built-in `System.Net.Quic` API and RFC 9250's `doq` ALPN, TLS 1.3, DNS message ID 0, one bidirectional QUIC stream per query, a 2-byte big-endian length prefix, explicit stream FIN and bounded 12–4096-byte responses. It requires the exact echoed test question, an authoritative response, and the synthetic `host.smoke.invalid` A address `192.0.2.42`. The probe performs **two queries over one QUIC connection** to test sequential stream reuse and refuses malformed or extra trailing frames.

The `--self-test` mode uses only synthetic in-memory test wires and needs neither MsQuic nor sockets. The pinned .NET SDK CI job compiles and executes this self-test on every PR. A pass establishes **parser/source acceptance only**.

## Explicit optional live acceptance — isolated lab ONLY

The `--loopback` mode is refused unless `GC_DNS_DOQ_ISOLATED_TEST=1`, a disposable container marker is present, and **no active network interface other than loopback** is visible. It uses only UDP `127.0.0.1:1854` and expects the generated public certificate `/work/doh-cert.pem` and binary A question `/work/doh-query.bin` from the existing isolated DoH fixture. The trusted certificate is loaded only into an in-memory custom root store for this test; **TLS hostname mismatches and non-chain errors are rejected**, not ignored. No process writes the certificate to the system trust store.

For a **manually approved, disposable, rootless, `--network=none` candidate-image test**, first build the probe using `dotnet build tests/DoQProbe/DoQProbe.csproj -c Release` in the pinned SDK. Use the established authenticated test-only DNS configuration workflow to create the local temporary PFX, publish the synthetic authoritative zone, set `enableDnsOverQuic=true`, `dnsOverQuicPort=1854` and the disposable certificate settings, and mount only the bounded test workdir plus compiled probe into the sandbox. Run:

```sh
GC_DNS_DOQ_ISOLATED_TEST=1 dotnet /work/doq-probe/DoQProbe.dll --loopback
```

The candidate image **must** have a verified MsQuic runtime, local 127.0.0.1 QUIC listener, and isolated credentials/test data already installed. This run is **not automated in CI**: the SDK builder image may not have the runtime MsQuic library. Do not weaken the test to accept untrusted certificates, host networking, arbitrary endpoints, or public service addresses.

## Remaining release gates

The real DoQ service handshake, trust, query semantics, concurrency, migration, failure injection, memory behavior, package signature chain, image provenance, DoH/DoT parity, authenticated operator setup and rollback are **unverified** until separately executed and recorded. Existing DoH/DoT smoke tests remain unchanged. Do not run this optional live client against production DNS or mark the DoQ release gate complete from CI source tests alone.

References: [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250), [Microsoft .NET QUIC guidance](https://learn.microsoft.com/dotnet/fundamentals/networking/quic/quic-overview).

## November 10, 2026 — negative framed-response matrix

The `--self-test` now exercises the same strict 2-byte big-endian length decoder used by the optional `--loopback` QUIC read path. It rejects zero, one-byte, zero-length and over-4096-byte prefixes; mismatched declared body lengths, truncated DNS bodies, changed answer data and trailing bytes; while retaining the existing authoritative-response and opcode tests. The self-test requires neither MsQuic nor a live service and is automatically run inside the pinned SDK CI build. Only a separate isolated `--network=none` live handshake with verified certificates and real QUIC traffic can establish DoQ transport acceptance; CI parser success is not an operational readiness signal.
