use crate::error::AcpError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const HANDSHAKE_VERSION: u8 = 1;
pub const MSG_TYPE_CLIENT_HELLO: u8 = 1;
pub const MSG_TYPE_SERVER_HELLO: u8 = 2;
pub const MSG_TYPE_CLIENT_FINISH: u8 = 3;

pub const X25519_PUB_LEN: usize = 32;
pub const ED25519_PUB_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const FINISH_LEN: usize = 32;

pub const CLIENT_HELLO_LEN: usize = 1 + 1 + X25519_PUB_LEN + ED25519_PUB_LEN + ED25519_SIG_LEN;
pub const SERVER_HELLO_LEN: usize = CLIENT_HELLO_LEN;
pub const CLIENT_FINISH_LEN: usize = 1 + 1 + FINISH_LEN;

#[derive(Debug, Clone)]
pub struct HelloMessage {
    pub ephemeral_pub: [u8; 32],
    pub signer_pub: [u8; 32],
    pub signature: [u8; 64],
}

pub fn build_client_hello(
    client_ephemeral_pub: [u8; 32],
    signing_secret: &[u8; 32],
) -> Result<Vec<u8>, AcpError> {
    let signing_key = SigningKey::from_bytes(signing_secret);
    let signer_pub = signing_key.verifying_key().to_bytes();
    let sig_input = client_hello_sig_input(client_ephemeral_pub, signer_pub);
    let signature = signing_key.sign(&sig_input).to_bytes();

    let mut out = Vec::with_capacity(CLIENT_HELLO_LEN);
    out.push(HANDSHAKE_VERSION);
    out.push(MSG_TYPE_CLIENT_HELLO);
    out.extend_from_slice(&client_ephemeral_pub);
    out.extend_from_slice(&signer_pub);
    out.extend_from_slice(&signature);
    Ok(out)
}

pub fn build_server_hello(
    client_ephemeral_pub: [u8; 32],
    client_signer_pub: [u8; 32],
    server_ephemeral_pub: [u8; 32],
    signing_secret: &[u8; 32],
) -> Result<Vec<u8>, AcpError> {
    let signing_key = SigningKey::from_bytes(signing_secret);
    let server_signer_pub = signing_key.verifying_key().to_bytes();
    let sig_input = server_hello_sig_input(
        client_ephemeral_pub,
        server_ephemeral_pub,
        client_signer_pub,
        server_signer_pub,
    );
    let signature = signing_key.sign(&sig_input).to_bytes();

    let mut out = Vec::with_capacity(SERVER_HELLO_LEN);
    out.push(HANDSHAKE_VERSION);
    out.push(MSG_TYPE_SERVER_HELLO);
    out.extend_from_slice(&server_ephemeral_pub);
    out.extend_from_slice(&server_signer_pub);
    out.extend_from_slice(&signature);
    Ok(out)
}

pub fn parse_client_hello(input: &[u8]) -> Result<HelloMessage, AcpError> {
    parse_hello(input, MSG_TYPE_CLIENT_HELLO)
}

pub fn parse_server_hello(input: &[u8]) -> Result<HelloMessage, AcpError> {
    parse_hello(input, MSG_TYPE_SERVER_HELLO)
}

fn parse_hello(input: &[u8], expected_msg_type: u8) -> Result<HelloMessage, AcpError> {
    if input.len() != CLIENT_HELLO_LEN {
        return Err(AcpError::ParseError("invalid hello length"));
    }
    if input[0] != HANDSHAKE_VERSION {
        return Err(AcpError::ParseError("unsupported handshake version"));
    }
    if input[1] != expected_msg_type {
        return Err(AcpError::ParseError("unexpected handshake message type"));
    }
    let ephemeral_pub: [u8; 32] = input[2..34]
        .try_into()
        .map_err(|_| AcpError::ParseError("invalid ephemeral key bytes"))?;
    let signer_pub: [u8; 32] = input[34..66]
        .try_into()
        .map_err(|_| AcpError::ParseError("invalid signer key bytes"))?;
    let signature: [u8; 64] = input[66..130]
        .try_into()
        .map_err(|_| AcpError::ParseError("invalid signature bytes"))?;
    Ok(HelloMessage {
        ephemeral_pub,
        signer_pub,
        signature,
    })
}

pub fn verify_client_hello(hello: &HelloMessage) -> Result<(), AcpError> {
    verify_signature(
        hello.signer_pub,
        hello.signature,
        &client_hello_sig_input(hello.ephemeral_pub, hello.signer_pub),
    )
}

pub fn verify_server_hello(
    hello: &HelloMessage,
    client_ephemeral_pub: [u8; 32],
    client_signer_pub: [u8; 32],
) -> Result<(), AcpError> {
    verify_signature(
        hello.signer_pub,
        hello.signature,
        &server_hello_sig_input(
            client_ephemeral_pub,
            hello.ephemeral_pub,
            client_signer_pub,
            hello.signer_pub,
        ),
    )
}

fn verify_signature(
    signer_pub: [u8; 32],
    signature: [u8; 64],
    message: &[u8],
) -> Result<(), AcpError> {
    let verifying = VerifyingKey::from_bytes(&signer_pub)
        .map_err(|_| AcpError::VerifyFailed("invalid ed25519 verifying key"))?;
    let sig = Signature::from_bytes(&signature);
    verifying
        .verify(message, &sig)
        .map_err(|_| AcpError::VerifyFailed("invalid ed25519 signature"))
}

pub fn transcript_hash(client_hello_bytes: &[u8], server_hello_bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        "ACPv1/transcript".len() + client_hello_bytes.len() + server_hello_bytes.len(),
    );
    input.extend_from_slice(b"ACPv1/transcript");
    input.extend_from_slice(client_hello_bytes);
    input.extend_from_slice(server_hello_bytes);
    blake3::hash(&input).into()
}

pub fn derive_root_key(shared_secret: [u8; 32], transcript_hash: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&shared_secret);
    input.extend_from_slice(&transcript_hash);
    blake3::derive_key("acp/v1/root", &input)
}

pub fn derive_session_key(root_key: [u8; 32]) -> [u8; 32] {
    blake3::derive_key("acp/v1/session_key", &root_key)
}

pub fn build_client_finish(confirmation: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CLIENT_FINISH_LEN);
    out.push(HANDSHAKE_VERSION);
    out.push(MSG_TYPE_CLIENT_FINISH);
    out.extend_from_slice(&confirmation);
    out
}

pub fn parse_client_finish(input: &[u8]) -> Result<[u8; 32], AcpError> {
    if input.len() != CLIENT_FINISH_LEN {
        return Err(AcpError::ParseError("invalid client finish length"));
    }
    if input[0] != HANDSHAKE_VERSION {
        return Err(AcpError::ParseError("unsupported handshake version"));
    }
    if input[1] != MSG_TYPE_CLIENT_FINISH {
        return Err(AcpError::ParseError("unexpected handshake message type"));
    }
    input[2..34]
        .try_into()
        .map_err(|_| AcpError::ParseError("invalid confirmation bytes"))
}

pub fn finish_confirmation(session_key: [u8; 32], transcript_hash: [u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity("ACPv1/finish".len() + 64);
    input.extend_from_slice(b"ACPv1/finish");
    input.extend_from_slice(&session_key);
    input.extend_from_slice(&transcript_hash);
    blake3::hash(&input).into()
}

fn client_hello_sig_input(client_ephemeral_pub: [u8; 32], client_signer_pub: [u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity("ACPv1/clienthello".len() + 64);
    input.extend_from_slice(b"ACPv1/clienthello");
    input.extend_from_slice(&client_ephemeral_pub);
    input.extend_from_slice(&client_signer_pub);
    input
}

fn server_hello_sig_input(
    client_ephemeral_pub: [u8; 32],
    server_ephemeral_pub: [u8; 32],
    client_signer_pub: [u8; 32],
    server_signer_pub: [u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity("ACPv1/serverhello".len() + 128);
    input.extend_from_slice(b"ACPv1/serverhello");
    input.extend_from_slice(&client_ephemeral_pub);
    input.extend_from_slice(&server_ephemeral_pub);
    input.extend_from_slice(&client_signer_pub);
    input.extend_from_slice(&server_signer_pub);
    input
}

#[cfg(test)]
mod tests {
    use super::{
        build_client_hello, build_server_hello, parse_client_hello, parse_server_hello,
        transcript_hash, verify_client_hello, verify_server_hello,
    };
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn signatures_verify_and_fail_on_tamper() {
        let mut rng = OsRng;
        let client_sk = SigningKey::generate(&mut rng);
        let server_sk = SigningKey::generate(&mut rng);
        let client_eph = [11u8; 32];
        let server_eph = [22u8; 32];

        let client_hello =
            build_client_hello(client_eph, &client_sk.to_bytes()).expect("client hello");
        let parsed_client = parse_client_hello(&client_hello).expect("parse");
        verify_client_hello(&parsed_client).expect("verify client");

        let server_hello = build_server_hello(
            client_eph,
            client_sk.verifying_key().to_bytes(),
            server_eph,
            &server_sk.to_bytes(),
        )
        .expect("server hello");
        let parsed_server = parse_server_hello(&server_hello).expect("parse");
        verify_server_hello(
            &parsed_server,
            client_eph,
            client_sk.verifying_key().to_bytes(),
        )
        .expect("verify server");

        let mut tampered = server_hello.clone();
        tampered[66] ^= 0xFF;
        let parsed_tampered = parse_server_hello(&tampered).expect("parse tampered");
        verify_server_hello(
            &parsed_tampered,
            client_eph,
            client_sk.verifying_key().to_bytes(),
        )
        .expect_err("tamper must fail");
    }

    #[test]
    fn transcript_order_matters() {
        let a = [1u8; 130];
        let b = [2u8; 130];
        let h1 = transcript_hash(&a, &b);
        let h2 = transcript_hash(&b, &a);
        assert_ne!(h1, h2);
    }
}
