# ACP (Astrolune Cipher Protocol)

ACP is a Rust implementation of a secure messaging protocol packaged as a Windows-native `cdylib` (DLL) for:
- C# (`P/Invoke`)
- C/C++ (`LoadLibrary` + `include/acp.h`)

## Status

Current branch implements ACP v1 with:
- X25519 key exchange (`x25519-dalek`)
- XChaCha20-Poly1305 AEAD (`chacha20poly1305`)
- BLAKE3 KDF + symmetric ratchet (`blake3`)
- Ed25519 handshake signatures (`ed25519-dalek`)
- zeroization for key material (`zeroize`)

## Protocol Overview

### Handshake (3 messages)

1. `ClientHello`
2. `ServerHello`
3. `ClientFinish`

`ClientFinish` carries:
- `confirmation(32) = BLAKE3_derive_key("acp/v1/finish", session_key || transcript_hash)`

Transcript hash is strictly:
- `transcript_hash = BLAKE3("ACPv1/transcript" || ClientHello_bytes || ServerHello_bytes)`

### Data Frame

Frame wire format:

`[version:u8 | msg_type:u8 | counter:u64 | nonce:24B | payload_len:u32 | ciphertext | mac:16B]`

Endianness:
- `counter`: little-endian
- `payload_len`: little-endian

Replay policy:
- first valid inbound counter is `1`
- accepted only when `counter == last_seen + 1`

## FFI API

Required exports:
- `acp_session_new`
- `acp_session_free`
- `acp_handshake_initiate`
- `acp_handshake_respond`
- `acp_handshake_finalize`
- `acp_encrypt`
- `acp_decrypt`
- `acp_last_error`

Additional key provisioning exports:
- `acp_session_set_local_signing_key`
- `acp_session_set_remote_verifying_key`

Buffer contract:
- two-call sizing (`NULL`/small output buffer returns `ACP_RESULT_BUFFER_TOO_SMALL` and required `out_len`)

Handshake call semantics:
- initiator flow: `acp_handshake_initiate` -> `acp_handshake_respond(ServerHello)` returns `ClientFinish` and transitions initiator to established
- responder flow: `acp_handshake_respond(ClientHello)` returns `ServerHello`, then `acp_handshake_finalize(ClientFinish)` completes responder establishment

## Build

```bash
cargo build --release
```

Windows DLL will be produced in:

`target/release/acp.dll`

## Test

```bash
cargo test
```

Includes:
- handshake + encryption/decryption roundtrip
- replay/out-of-order rejection checks
- FFI buffer contract checks

## Interop Files

- C header: `include/acp.h`
- C# wrapper: `interop/AcpInterop.cs`

## Security Notes

- No `ring`, no OpenSSL, no NIST curves.
- Panics are trapped with `catch_unwind` at FFI boundary.
- Key material is zeroized on drop where applicable.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.
