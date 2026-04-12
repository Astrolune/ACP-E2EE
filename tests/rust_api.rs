use acp::AcpSession;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn make_pair() -> (AcpSession, AcpSession) {
    let mut rng = OsRng;
    let client_sk = SigningKey::generate(&mut rng);
    let server_sk = SigningKey::generate(&mut rng);

    let mut client = AcpSession::new();
    client.set_local_signing_key(client_sk.to_bytes()).unwrap();
    client.set_remote_verifying_key(server_sk.verifying_key().to_bytes()).unwrap();

    let mut server = AcpSession::new();
    server.set_local_signing_key(server_sk.to_bytes()).unwrap();
    server.set_remote_verifying_key(client_sk.verifying_key().to_bytes()).unwrap();

    (client, server)
}

#[test]
fn handshake_and_roundtrip() {
    let (mut client, mut server) = make_pair();
    let ch = client.handshake_initiate().unwrap();
    let sh = server.handshake_respond(&ch).unwrap();
    let cf = client.handshake_respond(&sh).unwrap();
    server.handshake_finalize(&cf).unwrap();

    let ct = client.encrypt(b"hello aveil").unwrap();
    assert_eq!(server.decrypt(&ct).unwrap(), b"hello aveil");

    let ct2 = server.encrypt(b"hello back").unwrap();
    assert_eq!(client.decrypt(&ct2).unwrap(), b"hello back");
}

#[test]
fn replay_detection() {
    let (mut client, mut server) = make_pair();
    let ch = client.handshake_initiate().unwrap();
    let sh = server.handshake_respond(&ch).unwrap();
    let cf = client.handshake_respond(&sh).unwrap();
    server.handshake_finalize(&cf).unwrap();

    let ct = client.encrypt(b"once").unwrap();
    server.decrypt(&ct).unwrap();
    assert!(server.decrypt(&ct).is_err());
}
