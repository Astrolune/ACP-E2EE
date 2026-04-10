use acp::{
    acp_decrypt, acp_encrypt, acp_handshake_finalize, acp_handshake_initiate, acp_handshake_respond,
    acp_session_free, acp_session_new, acp_session_set_local_signing_key,
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
