#ifndef ACP_H
#define ACP_H

#include <stdint.h>

// API version for compile-time compatibility checks
#define ACP_API_VERSION 1

#ifdef _WIN32
  #ifdef ACP_BUILDING
    #define ACP_API __declspec(dllexport)
  #else
    #define ACP_API __declspec(dllimport)
  #endif
#else
  #define ACP_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AcpSessionOpaque AcpSessionOpaque;

typedef enum AcpResult {
    ACP_RESULT_OK = 0,
    ACP_RESULT_INVALID_ARGUMENT = 1,
    ACP_RESULT_BUFFER_TOO_SMALL = 2,
    ACP_RESULT_INVALID_STATE = 3,
    ACP_RESULT_PARSE_ERROR = 4,
    ACP_RESULT_VERIFY_FAILED = 5,
    ACP_RESULT_REPLAY_DETECTED = 6,
    ACP_RESULT_CRYPTO_ERROR = 7,
    ACP_RESULT_INTERNAL_ERROR = 8,
    ACP_RESULT_PANIC = 9
} AcpResult;

// Creates a new ACP session. Returns NULL on failure.
ACP_API AcpSessionOpaque* acp_session_new(void);

// Frees an ACP session. Safe to call with NULL.
ACP_API void acp_session_free(AcpSessionOpaque* session);

// Sets the local signing key (must be exactly 32 bytes).
ACP_API AcpResult acp_session_set_local_signing_key(
    AcpSessionOpaque* session,
    const uint8_t* sk,
    uint32_t sk_len
);

// Sets the remote verifying key (must be exactly 32 bytes).
ACP_API AcpResult acp_session_set_remote_verifying_key(
    AcpSessionOpaque* session,
    const uint8_t* pk,
    uint32_t pk_len
);

// Initiates handshake as client. Call with out_payload=NULL to query required size.
ACP_API AcpResult acp_handshake_initiate(
    AcpSessionOpaque* session,
    uint8_t* out_payload,
    uint32_t* out_len
);

// Responds to handshake message. Call with out_buf=NULL to query required size.
ACP_API AcpResult acp_handshake_respond(
    AcpSessionOpaque* session,
    const uint8_t* in_buf,
    uint32_t in_len,
    uint8_t* out_buf,
    uint32_t* out_len
);

// Finalizes handshake (responder only).
ACP_API AcpResult acp_handshake_finalize(
    AcpSessionOpaque* session,
    const uint8_t* in_buf,
    uint32_t in_len
);

// Encrypts plaintext. Call with out_buf=NULL to query required size.
// Note: Maximum buffer size is limited to 4GB (uint32_t).
ACP_API AcpResult acp_encrypt(
    AcpSessionOpaque* session,
    const uint8_t* pt,
    uint32_t pt_len,
    uint8_t* out_buf,
    uint32_t* out_len
);

// Decrypts ciphertext. Call with out_buf=NULL to query required size.
// Note: Maximum buffer size is limited to 4GB (uint32_t).
ACP_API AcpResult acp_decrypt(
    AcpSessionOpaque* session,
    const uint8_t* ct,
    uint32_t ct_len,
    uint8_t* out_buf,
    uint32_t* out_len
);

// Retrieves the last error message from the current thread.
// Returns a null-terminated UTF-8 string. The out_len includes the null byte.
// Call with out_buf=NULL to query required size.
ACP_API void acp_last_error(uint8_t* out_buf, uint32_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* ACP_H */
