# 🔐 ACP – Astrolune Cipher Protocol

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Windows](https://img.shields.io/badge/platform-Windows-blue?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT%2FApache2-blue)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen?logo=githubactions)](https://github.com/astrolune/acp/actions)

**ACP** — реализация протокола безопасного обмена сообщениями на **Rust**, собранная в нативную Windows DLL (`cdylib`) для вызова из **C#**, **C** и **C++**.

---

## 📦 Компоненты

| Криптография            | Крейт                  |
|------------------------|------------------------|
| X25519 key exchange    | `x25519-dalek`         |
| XChaCha20-Poly1305     | `chacha20poly1305`     |
| BLAKE3 (KDF + ratchet) | `blake3`               |
| Ed25519 подписи        | `ed25519-dalek`        |
| Zeroization ключей     | `zeroize`              |

> ✅ **Без OpenSSL, без ring, без NIST-кривых** — только современные алгоритмы.

---

## 📡 Протокол (ACP v1)

### Рукопожатие (3 сообщения)

1. `ClientHello`
2. `ServerHello`
3. `ClientFinish`

**ClientFinish** содержит:

```
confirmation(32) = BLAKE3_derive_key("acp/v1/finish", session_key || transcript_hash)
```

Где `transcript_hash`:

```
transcript_hash = BLAKE3_derive_key("acp/v1/transcript", ClientHello_bytes || ServerHello_bytes)
```

### Формат кадра данных

```
[ version:u8 | msg_type:u8 | counter:u64 | nonce:24B | payload_len:u32 | ciphertext | mac:16B ]
```

- `counter` – little‑endian  
- `payload_len` – little‑endian  

<div style="background: #f0f4ff; border-left: 5px solid #1e88e5; padding: 12px 16px; margin: 16px 0;">
  <strong>📘 NOTE</strong><br>
  Первый допустимый inbound счётчик = <code>1</code>. Сообщение принимается <strong>только</strong> если <code>counter == last_seen + 1</code>.
</div>

---

## 🧩 FFI API (DLL exports)

| Функция | Описание |
|---------|----------|
| `acp_session_new` | создать сессию |
| `acp_session_free` | уничтожить сессию |
| `acp_handshake_initiate` | инициатор: сгенерировать ClientHello |
| `acp_handshake_respond` | ответчик: ClientHello → ServerHello |
| `acp_handshake_finalize` | инициатор: ServerHello → ClientFinish |
| `acp_encrypt` | зашифровать кадр |
| `acp_decrypt` | расшифровать кадр |
| `acp_last_error` | текст последней ошибки |

### Управление ключами (опционально)

- `acp_session_set_local_signing_key`  
- `acp_session_set_remote_verifying_key`

### Контракт буферов

**Двухшаговый вызов** (аналогично Windows API):  

1. Вызвать с `NULL` / маленьким буфером → возвращается `ACP_RESULT_BUFFER_TOO_SMALL`, в `out_len` — требуемый размер.  
2. Выделить буфер нужного размера и повторить вызов.

<div style="background: #fff3e0; border-left: 5px solid #ffa000; padding: 12px 16px; margin: 16px 0;">
  <strong>⚠️ WARNING</strong><br>
  Никогда не игнорируйте код <code>ACP_RESULT_BUFFER_TOO_SMALL</code> — это может привести к переполнению буфера и неопределённому поведению.
</div>

### Семантика handshake

- **Инициатор**:  
  `acp_handshake_initiate` → получить `ClientHello`  
  → передать `ServerHello` в `acp_handshake_respond` → получить `ClientFinish` и **сессия established**

- **Ответчик**:  
  `acp_handshake_respond(ClientHello)` → получить `ServerHello`  
  → передать `ClientFinish` в `acp_handshake_finalize` → **сессия established**

---

## 🛠️ Сборка

### Требования

- Rust 1.70+ (через [rustup](https://rustup.rs/))
- Целевая платформа: `x86_64-pc-windows-msvc` (или `gnu`)

### Команды

```bash
cargo build --release
```

**Результат:** `target/release/acp.dll`

<div style="background: #e8f5e9; border-left: 5px solid #43a047; padding: 12px 16px; margin: 16px 0;">
  <strong>💡 TIP</strong><br>
  Для минимизации размера DLL добавьте в <code>Cargo.toml</code>:
  <pre><code>[profile.release]
lto = true
strip = true
opt-level = "z"</code></pre>
</div>

<div style="background: #ffebee; border-left: 5px solid #e53935; padding: 12px 16px; margin: 16px 0;">
  <strong>❌ ERROR</strong><br>
  Паники в Rust перехватываются на границе FFI. Вместо краша функция вернёт <code>ACP_RESULT_PANIC</code>, а текст ошибки можно получить через <code>acp_last_error</code>.
</div>

---

## 🧪 Тестирование

```bash
cargo test
```

Тесты покрывают:

- полный цикл handshake + шифрование/расшифровка  
- отклонение replay и out‑of‑order сообщений  
- проверку буферного контракта FFI

---

## 🔌 Примеры вызова

### C# (P/Invoke)

```csharp
using var session = AcpInterop.NewSession();
AcpInterop.SetLocalSigningKey(session, privateKey);
byte[] clientHello = AcpInterop.HandshakeInitiate(session);
// отправить clientHello, получить serverHello...
```

Готовый враппер: [`interop/AcpInterop.cs`](interop/AcpInterop.cs)

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

## 🔒 Безопасность

- Все ключевые материалы автоматически обнуляются при `Drop` (через `zeroize`).  
- Нет зависимостей от OpenSSL — только pure Rust криптография.  
- На стороне C/C++ после использования чувствительных данных вызывайте `SecureZeroMemory`.

<div style="background: #f0f4ff; border-left: 5px solid #1e88e5; padding: 12px 16px; margin: 16px 0;">
  <strong>📘 NOTE</strong><br>
  Сообщения об уязвимостях направляйте в соответствии с <a href="SECURITY.md">SECURITY.md</a>.
</div>
