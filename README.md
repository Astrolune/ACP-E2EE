# 🔐 ACP (Astrolune Cipher Protocol)

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/your-org/acp/actions)

**ACP** – надёжная реализация протокола безопасного обмена сообщениями на **Rust**, собранная в нативную Windows DLL (`cdylib`) для использования из:
- **C#** (P/Invoke)
- **C/C++** (`LoadLibrary` + `#include <acp.h>`)

---

## 📦 Текущий статус

Ветка `main` реализует **ACP v1** со следующими криптографическими примитивами:

| Компонент               | Крейт                 |
|-------------------------|-----------------------|
| X25519 key exchange     | `x25519-dalek`        |
| XChaCha20-Poly1305 AEAD | `chacha20poly1305`    |
| BLAKE3 KDF + ratchet    | `blake3`              |
| Ed25519 handshake signatures | `ed25519-dalek`  |
| Zeroization ключей      | `zeroize`             |

> ✅ **Протокол не использует** `ring`, OpenSSL или NIST-кривые — только современные, безопасные алгоритмы.

---

## 📖 Обзор протокола

### Рукопожатие (3 сообщения)

1. `ClientHello`
2. `ServerHello`
3. `ClientFinish`

Поле `confirmation` в `ClientFinish` вычисляется как:

```
confirmation(32) = BLAKE3_derive_key("acp/v1/finish", session_key || transcript_hash)
```

Где `transcript_hash`:

```
transcript_hash = BLAKE3_derive_key("acp/v1/transcript", ClientHello_bytes || ServerHello_bytes)
```

### Формат кадра данных

**Wire layout**:

```
[ version:u8 | msg_type:u8 | counter:u64 | nonce:24B | payload_len:u32 | ciphertext | mac:16B ]
```

- `counter` – **little-endian**
- `payload_len` – **little-endian**

> 🧠 **Политика защиты от повторов (replay)**  
> Первый допустимый inbound счётчик = `1`.  
> Сообщение принимается **только если** `counter == last_seen + 1`.

---

## 🚀 FFI API

### Экспортируемые функции

| Функция | Назначение |
|---------|------------|
| `acp_session_new` | Создать сессию |
| `acp_session_free` | Уничтожить сессию |
| `acp_handshake_initiate` | Инициатор: сгенерировать ClientHello |
| `acp_handshake_respond` | Ответчик: обработать ClientHello → ServerHello |
| `acp_handshake_finalize` | Инициатор: обработать ServerHello → ClientFinish |
| `acp_encrypt` | Зашифровать кадр |
| `acp_decrypt` | Расшифровать кадр |
| `acp_last_error` | Получить последнюю ошибку |

### Управление ключами (опционально)

- `acp_session_set_local_signing_key` – установить локальный ключ подписи Ed25519
- `acp_session_set_remote_verifying_key` – установить удалённый verifying key

### Контракт буферов

**Двухшаговый вызов** (как в Windows API):
1. Вызвать с `NULL` / маленьким буфером → получаете `ACP_RESULT_BUFFER_TOO_SMALL` и требуемый размер в `out_len`.
2. Выделить буфер нужного размера и вызвать снова.

### Семантика Handshake

- **Инициатор**:  
  `acp_handshake_initiate` → получить `ClientHello`  
  → `acp_handshake_respond(ServerHello)` → получить `ClientFinish` и **перейти в established**

- **Ответчик**:  
  `acp_handshake_respond(ClientHello)` → получить `ServerHello`  
  → `acp_handshake_finalize(ClientFinish)` → **завершить установку**

---

## 🛠️ Сборка

### Требования

- Rust `1.70+` (установите через [rustup](https://rustup.rs/))
- Целевая платформа: `x86_64-pc-windows-msvc` (или `gnu`)
- (Опционально) `cargo-make` для продвинутых сценариев

### Команды сборки

```bash
# Обычная сборка в DLL
cargo build --release

# Сборка с отладочной информацией
cargo build

# Сборка с дополнительными проверками (например, overflow checks)
cargo build --profile release-with-debug
```

### Результат

```
target/release/acp.dll
```

> 💡 **Совет**: Для минимизации размера DLL добавьте в `Cargo.toml`:
> ```toml
> [profile.release]
> lto = true
> strip = true
> opt-level = "z"
> ```

---

## ⚠️ Важные замечания

> **Note**  
> Все ключевые материалы автоматически обнуляются при удалении (`Drop`) благодаря `zeroize`. Это снижает риск утечки через память.

> **Warning**  
> **Не игнорируйте возвращаемый код `ACP_RESULT_BUFFER_TOO_SMALL`** – это может привести к переполнению буфера и неопределённому поведению.

> **Error**  
> Паники в Rust-коде **перехватываются** на границе FFI с помощью `catch_unwind`. Вместо паники функция вернёт `ACP_RESULT_PANIC`, а текст ошибки можно получить через `acp_last_error`.

> **Important**  
> Протокол требует строгой последовательности счётчиков. Любое отклонение (потеря, переупорядочивание, повтор) вызовет ошибку расшифровки.

---

## 🧪 Тестирование

```bash
cargo test
```

Тесты покрывают:
- Полный цикл handshake + шифрование/расшифровка
- Отклонение replay и out-of-order сообщений
- Проверку контракта буферов FFI

---

## 🔌 Примеры использования

### C# (P/Invoke)

```csharp
using var session = AcpInterop.NewSession();
AcpInterop.SetLocalSigningKey(session, privateKey);
byte[] clientHello = AcpInterop.HandshakeInitiate(session);
// ... отправка/получение ...
```

Полный враппер находится в [`interop/AcpInterop.cs`](interop/AcpInterop.cs).

### C / C++

```c
#include "acp.h"
acp_session_t* sess = acp_session_new();
acp_handshake_initiate(sess, NULL, &size);
uint8_t* buf = malloc(size);
acp_handshake_initiate(sess, buf, &size);
// ...
acp_session_free(sess);
```

---

## 🔒 Замечания по безопасности

- **Нет зависимостей от OpenSSL** – только pure Rust криптография.
- **Все буферы** – вызывающий отвечает за их выделение и освобождение.
- **Рекомендация**: после использования чувствительных данных вызывайте `SecureZeroMemory` (C++) или `Array.Clear` (C#).

---

## 🤝 Вклад в проект

Мы приветствуем pull request'ы. Перед внесением изменений:
1. Убедитесь, что `cargo test` проходит.
2. Обновите документацию (этот README).
3. Для новых функций добавьте тесты.

Сообщения об уязвимостях направляйте в соответствии с [SECURITY.md](SECURITY.md).
