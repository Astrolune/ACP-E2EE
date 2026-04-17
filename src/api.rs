use crate::error::AcpError;
use crate::session::SessionHandle;

pub struct AcpSession(SessionHandle);

impl AcpSession {
    pub fn new() -> Self {
        Self(SessionHandle::new())
    }

    pub fn set_local_signing_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        self.0.set_local_signing_key(key)
    }

    pub fn set_remote_verifying_key(&mut self, key: [u8; 32]) -> Result<(), AcpError> {
        self.0.set_remote_verifying_key(key)
    }

    pub fn handshake_initiate(&mut self) -> Result<Vec<u8>, AcpError> {
        self.0.handshake_initiate()
    }

    pub fn handshake_respond(&mut self, input: &[u8]) -> Result<Vec<u8>, AcpError> {
        self.0.handshake_respond(input)
    }

    pub fn handshake_finalize(&mut self, input: &[u8]) -> Result<(), AcpError> {
        self.0.handshake_finalize(input)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AcpError> {
        self.0.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, AcpError> {
        self.0.decrypt(ciphertext)
    }
}

impl Default for AcpSession {
    fn default() -> Self { Self::new() }
}
