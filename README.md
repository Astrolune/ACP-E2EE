<p align="center">
  <a href="https://github.com/astrolune/acp">
  </a>
</p>

[![Rust](https://img.shields.io/crates/v/acp.svg)](https://crates.io/crates/acp)
[![Docs](https://docs.rs/acp/badge.svg)](https://docs.rs/acp)
[![Build status](https://github.com/astrolune/acp/actions/workflows/ci.yml/badge.svg)](https://github.com/astrolune/acp/actions/workflows/ci.yml)
[![Windows](https://img.shields.io/badge/platform-Windows-blue?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT%2FApache2-blue)](LICENSE)

# **ACP – Astrolune Cipher Protocol**

**ACP** is a secure messaging protocol implemented in **Rust**, packaged as a native Windows DLL (`cdylib`) for use from C#, C, and C++.

---

## Protocol overview

- **X25519** key exchange (`x25519-dalek`)
- **XChaCha20-Poly1305** AEAD (`chacha20poly1305`)
- **BLAKE3** KDF + symmetric ratchet (`blake3`)
- **Ed25519** handshake signatures (`ed25519-dalek`)
- **Zeroization** of key material (`zeroize`)

### Handshake (3 messages)

1. `ClientHello`
2. `ServerHello`
3. `ClientFinish`

`ClientFinish` carries:

```
confirmation(32) = BLAKE3_derive_key("acp/v1/finish", session_key || transcript_hash)
```

`transcript_hash`:

```
transcript_hash = BLAKE3_derive_key("acp/v1/transcript", ClientHello_bytes || ServerHello_bytes)
```

### Data frame format

```
[ version:u8 | msg_type:u8 | counter:u64 | nonce:24B | payload_len:u32 | ciphertext | mac:16B ]
```

- `counter` – little‑endian
- `payload_len` – little‑endian

> [!NOTE]
> The first valid inbound counter is `1`. A message is accepted **only** if `counter == last_seen + 1`.

---

## FFI API

| Function | Description |
|----------|-------------|
| `acp_session_new` | create session |
| `acp_session_free` | destroy session |
| `acp_handshake_initiate` | initiator: generate ClientHello |
| `acp_handshake_respond` | responder: ClientHello → ServerHello |
| `acp_handshake_finalize` | initiator: ServerHello → ClientFinish |
| `acp_encrypt` | encrypt frame |
| `acp_decrypt` | decrypt frame |
| `acp_last_error` | last error message |

Optional key provisioning:

- `acp_session_set_local_signing_key`
- `acp_session_set_remote_verifying_key`

### Buffer contract (two‑call pattern)

1. Call with `NULL` / small buffer → returns `ACP_RESULT_BUFFER_TOO_SMALL`, required size in `out_len`.
2. Allocate buffer of that size and call again.

> [!WARNING]
> Never ignore `ACP_RESULT_BUFFER_TOO_SMALL` – it can lead to buffer overflow and undefined behavior.

### Handshake call semantics

- **Initiator**:  
  `acp_handshake_initiate` → `ClientHello`  
  → `acp_handshake_respond(ServerHello)` → `ClientFinish` → session established

- **Responder**:  
  `acp_handshake_respond(ClientHello)` → `ServerHello`  
  → `acp_handshake_finalize(ClientFinish)` → session established

---

## Building

### 1. Install rustc, cargo and rustfmt.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup component add rustfmt
```

The `rust-toolchain.toml` file pins a specific rust version.  
On Windows, ensure you have the **MSVC toolchain** (Visual Studio Build Tools).

### 2. Download the source code.

```bash
git clone https://github.com/astrolune/acp.git
cd acp
```

### 3. Build the DLL.

```bash
cargo build --release
```

The Windows DLL will be placed at:

```
target/release/acp.dll
```

> [!TIP]
> To minimize DLL size, add to `Cargo.toml`:
> ```toml
> [profile.release]
> lto = true
> strip = true
> opt-level = "z"
> ```

> [!CAUTION]
> Debug builds (`cargo build`) are **not suitable for production** – they are slow and may leak timing information. Always use `--release` for real deployments.

---

## Testing

Run the full test suite:

```bash
cargo test
```

Tests cover:

- Handshake + encryption/decryption roundtrip
- Replay and out‑of‑order rejection
- FFI buffer contract validation

---

## Usage examples

### C# (P/Invoke)

```csharp
using var session = AcpInterop.NewSession();
AcpInterop.SetLocalSigningKey(session, privateKey);
byte[] clientHello = AcpInterop.HandshakeInitiate(session);
// send clientHello, receive serverHello...
```

Full wrapper: [`interop/AcpInterop.cs`](interop/AcpInterop.cs)

### C / C++

```c
#include "acp.h"

acp_session_t* sess = acp_session_new();
size_t size = 0;
acp_handshake_initiate(sess, NULL, &size);
uint8_t* buf = malloc(size);
acp_handshake_initiate(sess, buf, &size);
// ...
acp_session_free(sess);
```

---

## Security notes

- No OpenSSL, no `ring`, no NIST curves – only modern pure‑Rust crypto.
- Key material is zeroized on `Drop` (`zeroize`).
- Panics are caught at FFI boundary – `ACP_RESULT_PANIC` + `acp_last_error`.

> [!IMPORTANT]
> On the C/C++ side, always call `SecureZeroMemory` on sensitive buffers after use.

> [!NOTE]
> Report vulnerabilities according to [SECURITY.md](SECURITY.md).
