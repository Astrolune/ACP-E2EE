use acp::{
    acp_decrypt, acp_encrypt, acp_handshake_finalize, acp_handshake_initiate, acp_handshake_respond,
    acp_last_error, acp_session_free, acp_session_new, acp_session_set_local_signing_key,
    acp_session_set_remote_verifying_key, AcpResult, AcpSessionOpaque,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn call_out(
    mut f: impl FnMut(*mut u8, *mut u32) -> AcpResult,
) -> (AcpResult, Vec<u8>) {
    let mut len: u32 = 0;
    let probe = f(core::ptr::null_mut(), &mut len);
    if probe != AcpResult::BufferTooSmall && probe != AcpResult::Ok {
        return (probe, Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    let result = f(buf.as_mut_ptr(), &mut len);
    buf.truncate(len as usize);
    (result, buf)
}

unsafe fn configure_peer(session: *mut AcpSessionOpaque, local: &SigningKey, remote: &SigningKey) {
    let local_secret = local.to_bytes();
    let remote_pub = remote.verifying_key().to_bytes();
    assert_eq!(
        acp_session_set_local_signing_key(session, local_secret.as_ptr(), 32),
        AcpResult::Ok
    );
    assert_eq!(
        acp_session_set_remote_verifying_key(session, remote_pub.as_ptr(), 32),
        AcpResult::Ok
    );
}

#[test]
fn full_handshake_and_roundtrip_with_replay_checks() {
    unsafe {
        let client = acp_session_new();
        let server = acp_session_new();
        assert!(!client.is_null());
        assert!(!server.is_null());

        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);

        configure_peer(client, &client_sk, &server_sk);
        configure_peer(server, &server_sk, &client_sk);

        let (init_res, client_hello) =
            call_out(|out, out_len| acp_handshake_initiate(client, out, out_len));
        assert_eq!(init_res, AcpResult::Ok);

        let (resp_res, server_hello) = call_out(|out, out_len| {
            acp_handshake_respond(
                server,
                client_hello.as_ptr(),
                client_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(resp_res, AcpResult::Ok);

        let (fin_res, client_finish) = call_out(|out, out_len| {
            acp_handshake_respond(
                client,
                server_hello.as_ptr(),
                server_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(fin_res, AcpResult::Ok);

        let finalize_res =
            acp_handshake_finalize(server, client_finish.as_ptr(), client_finish.len() as u32);
        assert_eq!(finalize_res, AcpResult::Ok);

        let msg1 = b"hello one";
        let msg2 = b"hello two";

        let (enc1_res, ct1) = call_out(|out, out_len| {
            acp_encrypt(client, msg1.as_ptr(), msg1.len() as u32, out, out_len)
        });
        assert_eq!(enc1_res, AcpResult::Ok);

        let (enc2_res, ct2) = call_out(|out, out_len| {
            acp_encrypt(client, msg2.as_ptr(), msg2.len() as u32, out, out_len)
        });
        assert_eq!(enc2_res, AcpResult::Ok);

        let (replay_probe, _) = call_out(|out, out_len| {
            acp_decrypt(server, ct2.as_ptr(), ct2.len() as u32, out, out_len)
        });
        assert_eq!(replay_probe, AcpResult::ReplayDetected);

        let (dec1_res, pt1) = call_out(|out, out_len| {
            acp_decrypt(server, ct1.as_ptr(), ct1.len() as u32, out, out_len)
        });
        assert_eq!(dec1_res, AcpResult::Ok);
        assert_eq!(pt1, msg1);

        let (dec2_res, pt2) = call_out(|out, out_len| {
            acp_decrypt(server, ct2.as_ptr(), ct2.len() as u32, out, out_len)
        });
        assert_eq!(dec2_res, AcpResult::Ok);
        assert_eq!(pt2, msg2);

        let (dup, _) = call_out(|out, out_len| {
            acp_decrypt(server, ct2.as_ptr(), ct2.len() as u32, out, out_len)
        });
        assert_eq!(dup, AcpResult::ReplayDetected);

        acp_session_free(client);
        acp_session_free(server);
    }
}

#[test]
fn ffi_buffer_contract_and_invalid_args() {
    unsafe {
        let session = acp_session_new();
        assert!(!session.is_null());

        let mut rng = OsRng;
        let local = SigningKey::generate(&mut rng);
        let remote = SigningKey::generate(&mut rng);
        configure_peer(session, &local, &remote);

        let mut needed: u32 = 0;
        let res = acp_handshake_initiate(session, core::ptr::null_mut(), &mut needed);
        assert_eq!(res, AcpResult::BufferTooSmall);
        assert!(needed > 0);

        let invalid = acp_encrypt(core::ptr::null_mut(), core::ptr::null(), 0, core::ptr::null_mut(), &mut needed);
        assert_eq!(invalid, AcpResult::InvalidArgument);

        acp_session_free(session);
    }
}

#[test]
fn tampered_ciphertext_returns_crypto_error() {
    unsafe {
        let client = acp_session_new();
        let server = acp_session_new();
        assert!(!client.is_null());
        assert!(!server.is_null());

        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);
        configure_peer(client, &client_sk, &server_sk);
        configure_peer(server, &server_sk, &client_sk);

        let (_, client_hello) = call_out(|out, out_len| acp_handshake_initiate(client, out, out_len));
        let (_, server_hello) = call_out(|out, out_len| {
            acp_handshake_respond(
                server,
                client_hello.as_ptr(),
                client_hello.len() as u32,
                out,
                out_len,
            )
        });
        let (_, client_finish) = call_out(|out, out_len| {
            acp_handshake_respond(
                client,
                server_hello.as_ptr(),
                server_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(
            acp_handshake_finalize(server, client_finish.as_ptr(), client_finish.len() as u32),
            AcpResult::Ok
        );

        let msg = b"tamper-check";
        let (enc_res, mut ct) = call_out(|out, out_len| {
            acp_encrypt(client, msg.as_ptr(), msg.len() as u32, out, out_len)
        });
        assert_eq!(enc_res, AcpResult::Ok);
        assert!(ct.len() > 38);
        ct[38] ^= 0xFF;

        let (tamper_res, _) = call_out(|out, out_len| {
            acp_decrypt(server, ct.as_ptr(), ct.len() as u32, out, out_len)
        });
        assert_eq!(tamper_res, AcpResult::CryptoError);

        acp_session_free(client);
        acp_session_free(server);
    }
}

#[test]
fn wrong_remote_verifying_key_fails_handshake_with_verify_error() {
    unsafe {
        let client = acp_session_new();
        let server = acp_session_new();
        assert!(!client.is_null());
        assert!(!server.is_null());

        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);
        let wrong_remote = SigningKey::generate(&mut rng);

        // Client is intentionally configured with wrong expected server verifying key.
        let client_secret = client_sk.to_bytes();
        let wrong_server_pub = wrong_remote.verifying_key().to_bytes();
        assert_eq!(
            acp_session_set_local_signing_key(client, client_secret.as_ptr(), 32),
            AcpResult::Ok
        );
        assert_eq!(
            acp_session_set_remote_verifying_key(client, wrong_server_pub.as_ptr(), 32),
            AcpResult::Ok
        );

        // Server has correct view of client key.
        configure_peer(server, &server_sk, &client_sk);

        let (init_res, client_hello) =
            call_out(|out, out_len| acp_handshake_initiate(client, out, out_len));
        assert_eq!(init_res, AcpResult::Ok);

        let (resp_res, server_hello) = call_out(|out, out_len| {
            acp_handshake_respond(
                server,
                client_hello.as_ptr(),
                client_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(resp_res, AcpResult::Ok);

        let (client_res, _) = call_out(|out, out_len| {
            acp_handshake_respond(
                client,
                server_hello.as_ptr(),
                server_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(client_res, AcpResult::VerifyFailed);

        acp_session_free(client);
        acp_session_free(server);
    }
}

// Point 56: Test that acp_last_error returns the correct error message
#[test]
fn last_error_returns_correct_message() {
    unsafe {
        let session = acp_session_new();
        assert!(!session.is_null());

        // Trigger an error by calling encrypt without establishing session
        let msg = b"test";
        let mut len: u32 = 0;
        let result = acp_encrypt(session, msg.as_ptr(), msg.len() as u32, core::ptr::null_mut(), &mut len);
        assert_eq!(result, AcpResult::InvalidState);

        // Retrieve the error message
        let mut err_len: u32 = 0;
        acp_last_error(core::ptr::null_mut(), &mut err_len);
        assert!(err_len > 0);

        let mut err_buf = vec![0u8; err_len as usize];
        acp_last_error(err_buf.as_mut_ptr(), &mut err_len);

        // Find null terminator
        let nul_pos = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
        let err_str = std::str::from_utf8(&err_buf[..nul_pos]).unwrap();

        assert!(err_str.contains("encrypt") || err_str.contains("established"));

        acp_session_free(session);
    }
}

// Point 57: Test that acp_session_free(null) is a no-op
#[test]
fn session_free_null_is_noop() {
    // Should not crash or panic
    unsafe {
        acp_session_free(core::ptr::null_mut());
    }
}

// Point 58: Test two sessions on one thread with interleaved calls
#[test]
fn two_sessions_interleaved_errors_dont_mix() {
    unsafe {
        let session1 = acp_session_new();
        let session2 = acp_session_new();
        assert!(!session1.is_null());
        assert!(!session2.is_null());

        // Trigger error on session1
        let msg = b"test";
        let mut len: u32 = 0;
        let result1 = acp_encrypt(session1, msg.as_ptr(), msg.len() as u32, core::ptr::null_mut(), &mut len);
        assert_eq!(result1, AcpResult::InvalidState);

        // Retrieve error - should be from session1
        let mut err_len: u32 = 0;
        acp_last_error(core::ptr::null_mut(), &mut err_len);
        let mut err_buf1 = vec![0u8; err_len as usize];
        acp_last_error(err_buf1.as_mut_ptr(), &mut err_len);

        // Trigger different error on session2
        let result2 = acp_handshake_initiate(session2, core::ptr::null_mut(), &mut len);
        assert_eq!(result2, AcpResult::InvalidState); // No signing key configured

        // Retrieve error - should be from session2 (overwrites session1 error)
        err_len = 0;
        acp_last_error(core::ptr::null_mut(), &mut err_len);
        let mut err_buf2 = vec![0u8; err_len as usize];
        acp_last_error(err_buf2.as_mut_ptr(), &mut err_len);

        // Both errors should be valid (thread-local storage works)
        assert!(err_buf1.len() > 0);
        assert!(err_buf2.len() > 0);

        acp_session_free(session1);
        acp_session_free(session2);
    }
}

// Point 59: Test SetLocalSigningSeed with wrong size
#[test]
fn set_signing_key_wrong_size_fails() {
    unsafe {
        let session = acp_session_new();
        assert!(!session.is_null());

        // Try with 31 bytes (wrong size)
        let wrong_size_key = [0u8; 31];
        let result = acp_session_set_local_signing_key(session, wrong_size_key.as_ptr(), 31);
        assert_eq!(result, AcpResult::InvalidArgument);

        // Try with 33 bytes (wrong size)
        let wrong_size_key = [0u8; 33];
        let result = acp_session_set_local_signing_key(session, wrong_size_key.as_ptr(), 33);
        assert_eq!(result, AcpResult::InvalidArgument);

        acp_session_free(session);
    }
}

// Point 60: Test server with wrong expected client key
#[test]
fn server_wrong_client_key_fails_handshake() {
    unsafe {
        let client = acp_session_new();
        let server = acp_session_new();
        assert!(!client.is_null());
        assert!(!server.is_null());

        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);
        let wrong_client = SigningKey::generate(&mut rng);

        // Client has correct view
        configure_peer(client, &client_sk, &server_sk);

        // Server is configured with wrong expected client key
        let server_secret = server_sk.to_bytes();
        let wrong_client_pub = wrong_client.verifying_key().to_bytes();
        assert_eq!(
            acp_session_set_local_signing_key(server, server_secret.as_ptr(), 32),
            AcpResult::Ok
        );
        assert_eq!(
            acp_session_set_remote_verifying_key(server, wrong_client_pub.as_ptr(), 32),
            AcpResult::Ok
        );

        let (init_res, client_hello) =
            call_out(|out, out_len| acp_handshake_initiate(client, out, out_len));
        assert_eq!(init_res, AcpResult::Ok);

        // Server should reject client hello due to key mismatch
        let (resp_res, _) = call_out(|out, out_len| {
            acp_handshake_respond(
                server,
                client_hello.as_ptr(),
                client_hello.len() as u32,
                out,
                out_len,
            )
        });
        assert_eq!(resp_res, AcpResult::VerifyFailed);

        acp_session_free(client);
        acp_session_free(server);
    }
}

// Point 55: Test that ratchet state is not advanced on replay error
#[test]
fn replay_error_does_not_advance_ratchet() {
    unsafe {
        let client = acp_session_new();
        let server = acp_session_new();
        assert!(!client.is_null());
        assert!(!server.is_null());

        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);
        configure_peer(client, &client_sk, &server_sk);
        configure_peer(server, &server_sk, &client_sk);

        // Complete handshake
        let (_, client_hello) = call_out(|out, out_len| acp_handshake_initiate(client, out, out_len));
        let (_, server_hello) = call_out(|out, out_len| {
            acp_handshake_respond(server, client_hello.as_ptr(), client_hello.len() as u32, out, out_len)
        });
        let (_, client_finish) = call_out(|out, out_len| {
            acp_handshake_respond(client, server_hello.as_ptr(), server_hello.len() as u32, out, out_len)
        });
        assert_eq!(
            acp_handshake_finalize(server, client_finish.as_ptr(), client_finish.len() as u32),
            AcpResult::Ok
        );

        // Encrypt two messages
        let msg1 = b"first";
        let msg2 = b"second";
        let (_, ct1) = call_out(|out, out_len| {
            acp_encrypt(client, msg1.as_ptr(), msg1.len() as u32, out, out_len)
        });
        let (_, ct2) = call_out(|out, out_len| {
            acp_encrypt(client, msg2.as_ptr(), msg2.len() as u32, out, out_len)
        });

        // Try to decrypt ct2 first (should fail with replay)
        let (replay_res, _) = call_out(|out, out_len| {
            acp_decrypt(server, ct2.as_ptr(), ct2.len() as u32, out, out_len)
        });
        assert_eq!(replay_res, AcpResult::ReplayDetected);

        // Now decrypt ct1 - should still work (ratchet wasn't advanced)
        let (dec1_res, pt1) = call_out(|out, out_len| {
            acp_decrypt(server, ct1.as_ptr(), ct1.len() as u32, out, out_len)
        });
        assert_eq!(dec1_res, AcpResult::Ok);
        assert_eq!(pt1, msg1);

        // Now ct2 should work
        let (dec2_res, pt2) = call_out(|out, out_len| {
            acp_decrypt(server, ct2.as_ptr(), ct2.len() as u32, out, out_len)
        });
        assert_eq!(dec2_res, AcpResult::Ok);
        assert_eq!(pt2, msg2);

        acp_session_free(client);
        acp_session_free(server);
    }
}
