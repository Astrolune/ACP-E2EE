# Changelog

All notable changes to this project are documented in this file.

## [0.0.0] - 2026-04-11

### Added
- Initial ACP v1 Rust `cdylib` implementation.
- Typestate session model (`Handshake` -> `Established`).
- 3-message authenticated handshake with `ClientFinish`.
- X25519 + BLAKE3 key schedule.
- XChaCha20-Poly1305 frame encryption/decryption.
- Strict replay protection using monotonic `u64` counter.
- FFI exports for session lifecycle, handshake, crypto, and error reporting.
- C header (`include/acp.h`) and C# interop wrapper (`interop/AcpInterop.cs`).
- Integration and unit tests for protocol and FFI contracts.
