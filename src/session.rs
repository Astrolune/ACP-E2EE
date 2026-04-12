use crate::error::AcpError;
use crate::frame::{Frame, ACP_VERSION, MAC_LEN, MSG_TYPE_DATA, NONCE_LEN};
use crate::handshake::{
    build_client_finish, build_client_hello, build_server_hello, derive_root_key, derive_session_key,
    finish_confirmation, parse_client_finish, parse_client_hello, parse_server_hello, transcript_hash,
    verify_client_hello, verify_server_hello, CLIENT_FINISH_LEN, CLIENT_HELLO_LEN, SERVER_HELLO_LEN,
};
use crate::ratchet::{SessionRole, SymmetricRatchet};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for encryption keys that ensures zeroization on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Type-state marker for handshake phase.
pub struct Handshake;

/// Type-state marker for established session phase.
pub struct Established;

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secret32([u8; 32]);

impl Secret32 {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Session with type-state tracking.
///
/// Note: This uses both type-state pattern (PhantomData<S>) and runtime enum
/// (SessionInner). The type-state provides compile-time guarantees for internal
/// methods, while SessionInner enables runtime state transitions through SessionHandle.
pub struct AcpSession<S> {
    inner: SessionInner,
    _marker: core::marker::PhantomData<S>,
}

enum SessionInner {
    Handshake(HandshakeInner),
    Established(EstablishedInner),
}

struct HandshakeInner {
    local_signing_secret: Option<Secret32>,
    remote_verifying_key: Option<[u8; 32]>,
    progress: HandshakeProgress,
}

enum HandshakeProgress {
    Idle,
    InitiatorAwaitServer {
        eph_secret: EphemeralSecret,
        client_hello: Vec<u8>,
        client_ephemeral_pub: [u8; 32],
        client_signer_pub: [u8; 32],
    },
    ResponderAwaitFinish {
        expected_confirmation: [u8; 32],
        ratchet: SymmetricRatchet,
    },
}

struct EstablishedInner {
    ratchet: SymmetricRatchet,
}

pub enum SessionStateMachine {
    Handshake(AcpSession<Handshake>),
    Established(AcpSession<Established>),
}

/// Wrapper for the session state machine.
///
/// Note: The `state` field is private to prevent external code from breaking
/// state invariants. Use `state()` and `state_mut()` accessors if needed.
pub struct SessionHandle {
    state: SessionStateMachine,
}

enum RespondOutcome {
    HandshakePayload(Vec<u8>),
    Established { payload: Vec<u8>, session: AcpSession<Established> },
}

impl SessionHandle {
    pub fn new() -> Self {
        Self {
            state: SessionStateMachine::Handshake(AcpSession::<Handshake>::new()),
        }
    }

    pub fn state(&self) -> &SessionStateMachine {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut SessionStateMachine {
        &mut self.state
    }

    pub fn set_local_signing_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(s) => s.set_local_signing_key(key),
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("cannot set signing key after handshake"))
            }
        }
    }

    pub fn set_remote_verifying_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(s) => s.set_remote_verifying_key(key),
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("cannot set remote key after handshake"))
            }
        }
    }

    pub fn handshake_initiate(&mut self) -> Result<Vec<u8>, AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(s) => s.initiate(),
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("session already established"))
            }
        }
    }

    /// Handles the second handshake leg for either role.
    ///
    /// Behavior by role/state:
    /// - Responder in `Idle`: consumes `ClientHello` and returns `ServerHello`.
    /// - Initiator in `InitiatorAwaitServer`: consumes `ServerHello`, derives keys,
    ///   transitions to `Established`, and returns `ClientFinish`.
    ///
    /// Because the initiator final transition happens here, `handshake_finalize`
    /// is only called by responders to verify `ClientFinish`.
    pub fn handshake_respond(&mut self, input: &[u8]) -> Result<Vec<u8>, AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(s) => match s.respond(input)? {
                RespondOutcome::HandshakePayload(payload) => Ok(payload),
                RespondOutcome::Established { payload, session } => {
                    self.state = SessionStateMachine::Established(session);
                    Ok(payload)
                }
            },
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("session already established"))
            }
        }
    }

    pub fn handshake_finalize(&mut self, input: &[u8]) -> Result<(), AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(s) => {
                let established = s.finalize(input)?;
                self.state = SessionStateMachine::Established(established);
                Ok(())
            }
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("session already established"))
            }
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(_) => {
                Err(AcpError::invalid_state("encrypt requires established session"))
            }
            SessionStateMachine::Established(s) => s.encrypt(plaintext),
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AcpError> {
        match &mut self.state {
            SessionStateMachine::Handshake(_) => {
                Err(AcpError::invalid_state("decrypt requires established session"))
            }
            SessionStateMachine::Established(s) => s.decrypt(ciphertext),
        }
    }

    pub fn preview_handshake_initiate_len(&self) -> Result<usize, AcpError> {
        match &self.state {
            SessionStateMachine::Handshake(s) => s.preview_initiate_len(),
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("session already established"))
            }
        }
    }

    pub fn preview_handshake_respond_len(&self, input: &[u8]) -> Result<usize, AcpError> {
        match &self.state {
            SessionStateMachine::Handshake(s) => s.preview_respond_len(input),
            SessionStateMachine::Established(_) => {
                Err(AcpError::invalid_state("session already established"))
            }
        }
    }

    pub fn preview_encrypt_len(&self, pt_len: usize) -> Result<usize, AcpError> {
        match &self.state {
            SessionStateMachine::Handshake(_) => {
                Err(AcpError::invalid_state("encrypt requires established session"))
            }
            SessionStateMachine::Established(_) => {
                let payload_len =
                    u32::try_from(pt_len).map_err(|_| AcpError::invalid_argument("plaintext too large"))?;
                Ok(crate::frame::HEADER_LEN + crate::frame::NONCE_LEN + payload_len as usize + MAC_LEN)
            }
        }
    }

    pub fn preview_decrypt_len(&self, input: &[u8]) -> Result<usize, AcpError> {
        match &self.state {
            SessionStateMachine::Handshake(_) => {
                Err(AcpError::invalid_state("decrypt requires established session"))
            }
            SessionStateMachine::Established(_) => {
                let frame = Frame::decode(input)?;
                if frame.version != ACP_VERSION {
                    return Err(AcpError::parse_error("unsupported frame version"));
                }
                if frame.msg_type != MSG_TYPE_DATA {
                    return Err(AcpError::parse_error("unexpected frame message type"));
                }
                Ok(frame.payload_len as usize)
            }
        }
    }
}

impl AcpSession<Handshake> {
    /// Creates a new handshake session.
    ///
    /// Note: AcpSession<Established> does not have a `new()` constructor;
    /// it can only be created via `from_ratchet()` after successful handshake.
    fn new() -> Self {
        Self {
            inner: SessionInner::Handshake(HandshakeInner {
                local_signing_secret: None,
                remote_verifying_key: None,
                progress: HandshakeProgress::Idle,
            }),
            _marker: core::marker::PhantomData,
        }
    }

    fn set_local_signing_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        let inner = self.handshake_inner_mut()?;
        inner.local_signing_secret = Some(Secret32::from_bytes(key));
        Ok(())
    }

    fn set_remote_verifying_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        let inner = self.handshake_inner_mut()?;
        inner.remote_verifying_key = Some(key);
        Ok(())
    }

    fn initiate(&mut self) -> Result<Vec<u8>, AcpError> {
        let inner = self.handshake_inner_mut()?;
        if !matches!(inner.progress, HandshakeProgress::Idle) {
            return Err(AcpError::invalid_state("handshake already started"));
        }
        let secret = inner
            .local_signing_secret
            .as_ref()
            .ok_or(AcpError::invalid_state("local signing key not configured"))?;
        let eph_secret = EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph_secret).to_bytes();
        let client_hello = build_client_hello(eph_pub, secret.as_bytes())?;
        let client_signer_pub = ed25519_dalek::SigningKey::from_bytes(secret.as_bytes())
            .verifying_key()
            .to_bytes();
        inner.progress = HandshakeProgress::InitiatorAwaitServer {
            eph_secret,
            client_hello: client_hello.clone(),
            client_ephemeral_pub: eph_pub,
            client_signer_pub,
        };
        Ok(client_hello)
    }

    fn preview_initiate_len(&self) -> Result<usize, AcpError> {
        let inner = self.handshake_inner_ref()?;
        if !matches!(inner.progress, HandshakeProgress::Idle) {
            return Err(AcpError::invalid_state("handshake already started"));
        }
        if inner.local_signing_secret.is_none() {
            return Err(AcpError::invalid_state("local signing key not configured"));
        }
        Ok(CLIENT_HELLO_LEN)
    }

    fn respond(&mut self, input: &[u8]) -> Result<RespondOutcome, AcpError> {
        let inner = self.handshake_inner_mut()?;
        let progress = core::mem::replace(&mut inner.progress, HandshakeProgress::Idle);
        match progress {
            HandshakeProgress::Idle => {
                let remote_key = inner
                    .remote_verifying_key
                    .ok_or(AcpError::invalid_state("remote verifying key not configured"))?;
                let secret = inner
                    .local_signing_secret
                    .as_ref()
                    .ok_or(AcpError::invalid_state("local signing key not configured"))?;
                let client_hello = parse_client_hello(input)?;
                verify_client_hello(&client_hello)?;
                ensure_remote_key(client_hello.signer_pub, remote_key)?;

                let server_secret = EphemeralSecret::random_from_rng(OsRng);
                let server_pub = PublicKey::from(&server_secret).to_bytes();
                let server_hello = build_server_hello(
                    client_hello.ephemeral_pub,
                    client_hello.signer_pub,
                    server_pub,
                    secret.as_bytes(),
                )?;
                let shared = server_secret.diffie_hellman(&PublicKey::from(client_hello.ephemeral_pub));
                let transcript = transcript_hash(input, &server_hello);
                let mut shared_bytes = *shared.as_bytes();
                drop(shared);
                let mut root = derive_root_key(shared_bytes, transcript);
                shared_bytes.zeroize();
                let mut session_key = derive_session_key(root);
                let expected_confirmation = finish_confirmation(session_key, transcript);
                let ratchet = SymmetricRatchet::from_root(root, SessionRole::Responder);
                session_key.zeroize();
                root.zeroize();
                inner.progress = HandshakeProgress::ResponderAwaitFinish {
                    expected_confirmation,
                    ratchet,
                };
                Ok(RespondOutcome::HandshakePayload(server_hello))
            }
            HandshakeProgress::InitiatorAwaitServer {
                eph_secret,
                client_hello,
                client_ephemeral_pub,
                client_signer_pub,
            } => {
                let remote_key = inner
                    .remote_verifying_key
                    .ok_or(AcpError::invalid_state("remote verifying key not configured"))?;
                let server_hello = parse_server_hello(input)?;
                verify_server_hello(&server_hello, client_ephemeral_pub, client_signer_pub)?;
                ensure_remote_key(server_hello.signer_pub, remote_key)?;
                let shared = eph_secret.diffie_hellman(&PublicKey::from(server_hello.ephemeral_pub));
                let transcript = transcript_hash(&client_hello, input);
                let mut shared_bytes = *shared.as_bytes();
                drop(shared);
                let mut root = derive_root_key(shared_bytes, transcript);
                shared_bytes.zeroize();
                let mut session_key = derive_session_key(root);
                let confirmation = finish_confirmation(session_key, transcript);
                let finish = build_client_finish(confirmation);
                let established = AcpSession::<Established>::from_ratchet(SymmetricRatchet::from_root(
                    root,
                    SessionRole::Initiator,
                ));
                session_key.zeroize();
                root.zeroize();
                Ok(RespondOutcome::Established {
                    payload: finish,
                    session: established,
                })
            }
            HandshakeProgress::ResponderAwaitFinish { .. } => {
                inner.progress = progress;
                Err(AcpError::invalid_state(
                    "responder is waiting for client finish; call finalize",
                ))
            }
        }
    }

    fn preview_respond_len(&self, input: &[u8]) -> Result<usize, AcpError> {
        let inner = self.handshake_inner_ref()?;
        match &inner.progress {
            HandshakeProgress::Idle => {
                if inner.remote_verifying_key.is_none() {
                    return Err(AcpError::invalid_state("remote verifying key not configured"));
                }
                if inner.local_signing_secret.is_none() {
                    return Err(AcpError::invalid_state("local signing key not configured"));
                }
                parse_client_hello(input)?;
                Ok(SERVER_HELLO_LEN)
            }
            HandshakeProgress::InitiatorAwaitServer { .. } => {
                if inner.remote_verifying_key.is_none() {
                    return Err(AcpError::invalid_state("remote verifying key not configured"));
                }
                parse_server_hello(input)?;
                Ok(CLIENT_FINISH_LEN)
            }
            HandshakeProgress::ResponderAwaitFinish { .. } => Err(AcpError::invalid_state(
                "responder is waiting for client finish; call finalize",
            )),
        }
    }

    fn finalize(&mut self, input: &[u8]) -> Result<AcpSession<Established>, AcpError> {
        let inner = self.handshake_inner_mut()?;
        let progress = core::mem::replace(&mut inner.progress, HandshakeProgress::Idle);
        match progress {
            HandshakeProgress::ResponderAwaitFinish {
                expected_confirmation,
                ratchet,
            } => {
                let got = parse_client_finish(input)?;
                if got != expected_confirmation {
                    return Err(AcpError::verify_failed("client finish confirmation mismatch"));
                }
                Ok(AcpSession::<Established>::from_ratchet(ratchet))
            }
            other => {
                inner.progress = other;
                Err(AcpError::invalid_state(
                    "finalize is only valid for responder after sending server hello",
                ))
            }
        }
    }

    fn handshake_inner_mut(&mut self) -> Result<&mut HandshakeInner, AcpError> {
        match &mut self.inner {
            SessionInner::Handshake(inner) => Ok(inner),
            SessionInner::Established(_) => Err(AcpError::internal_error("invalid typestate access")),
        }
    }

    fn handshake_inner_ref(&self) -> Result<&HandshakeInner, AcpError> {
        match &self.inner {
            SessionInner::Handshake(inner) => Ok(inner),
            SessionInner::Established(_) => Err(AcpError::internal_error("invalid typestate access")),
        }
    }
}

impl AcpSession<Established> {
    /// Creates an established session from a ratchet.
    ///
    /// This is the only way to construct AcpSession<Established>.
    fn from_ratchet(ratchet: SymmetricRatchet) -> Self {
        Self {
            inner: SessionInner::Established(EstablishedInner { ratchet }),
            _marker: core::marker::PhantomData,
        }
    }

    fn established_inner_mut(&mut self) -> Result<&mut EstablishedInner, AcpError> {
        match &mut self.inner {
            SessionInner::Established(inner) => Ok(inner),
            SessionInner::Handshake(_) => Err(AcpError::internal_error("invalid typestate access")),
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AcpError> {
        let inner = self.established_inner_mut()?;
        let (key_bytes, counter) = inner.ratchet.next_send_key()?;
        let key = EncryptionKey::new(key_bytes);
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| AcpError::crypto_error("bad key"))?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut ciphertext = plaintext.to_vec();
        let payload_len = u32::try_from(ciphertext.len())
            .map_err(|_| AcpError::invalid_argument("plaintext too large"))?;
        let frame_stub = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter,
            nonce,
            payload_len,
            ciphertext: Vec::new(),
            mac: [0u8; MAC_LEN],
        };
        let aad = frame_stub.aad_bytes();
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, &mut ciphertext)
            .map_err(|_| AcpError::crypto_error("encryption failure"))?;
        let frame = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter,
            nonce,
            payload_len,
            ciphertext,
            mac: tag.into(),
        };
        Ok(frame.encode())
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>, AcpError> {
        let inner = self.established_inner_mut()?;
        let frame = Frame::decode(input)?;
        if frame.version != ACP_VERSION {
            return Err(AcpError::parse_error("unsupported frame version"));
        }
        if frame.msg_type != MSG_TYPE_DATA {
            return Err(AcpError::parse_error("unexpected frame message type"));
        }
        let key_bytes = inner.ratchet.recv_key_for_counter(frame.counter)?;
        let key = EncryptionKey::new(key_bytes);
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| AcpError::crypto_error("bad key"))?;
        let aad = frame.aad_bytes();
        let mut plaintext = frame.ciphertext;
        let tag = Tag::from_slice(&frame.mac);
        cipher
            .decrypt_in_place_detached(XNonce::from_slice(&frame.nonce), &aad, &mut plaintext, tag)
            .map_err(|_| AcpError::crypto_error("decryption failure"))?;
        Ok(plaintext)
    }
}

/// Verifies that the peer's signing key matches the configured remote key.
/// Uses constant-time comparison to prevent timing attacks.
fn ensure_remote_key(got: [u8; 32], expected: [u8; 32]) -> Result<(), AcpError> {
    use subtle::ConstantTimeEq;
    if got.ct_eq(&expected).into() {
        Ok(())
    } else {
        Err(AcpError::verify_failed(
            "peer signing key does not match configured remote key",
        ))
    }
}
