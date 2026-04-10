# Contributing to ACP

Thanks for contributing.

## Development Setup

1. Install stable Rust toolchain.
2. Clone repository.
3. Run:

```bash
cargo test
```

## Mandatory Crypto Constraints

Do not introduce:
- `ring`
- OpenSSL bindings
- NIST curves

Use only the protocol stack documented in `README.md`.

## Protocol Invariants

Contributions must preserve:
- 3-step handshake (`ClientHello`, `ServerHello`, `ClientFinish`)
- transcript hash ordering
- strict replay policy (`counter == last_seen + 1`, first valid counter is `1`)
- little-endian encoding for integer frame fields
- no panic crossing FFI boundary

## Coding Guidelines

- Keep FFI signatures ABI-safe (`extern "C"`, primitive/pointer arguments).
- Validate all pointers and lengths.
- Prefer explicit error paths with `AcpResult`.
- Zeroize sensitive material.

## Pull Request Checklist

- Tests pass locally: `cargo test`
- New behavior is covered by tests
- Public API changes are reflected in `include/acp.h` and `interop/AcpInterop.cs`
- Security-sensitive decisions are documented in PR description
