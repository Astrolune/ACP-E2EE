use crate::error::AcpError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricRatchet {
    send_chain: Key32,
    recv_chain: Key32,
    next_send_counter: u64,
    last_recv_counter: u64,
}

impl SymmetricRatchet {
    pub fn from_root(root_key: [u8; 32], role: SessionRole) -> Self {
        let c2s = blake3::derive_key("acp/v1/chain/client_to_server", &root_key);
        let s2c = blake3::derive_key("acp/v1/chain/server_to_client", &root_key);
        let (send_chain, recv_chain) = match role {
            SessionRole::Initiator => (c2s, s2c),
            SessionRole::Responder => (s2c, c2s),
        };
        Self {
            send_chain: Key32::new(send_chain),
            recv_chain: Key32::new(recv_chain),
            next_send_counter: 1,
            last_recv_counter: 0,
        }
    }

    pub fn next_send_key(&mut self) -> ([u8; 32], u64) {
        let counter = self.next_send_counter;
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(self.send_chain.as_bytes());
        input.extend_from_slice(&counter.to_le_bytes());
        let key = blake3::derive_key("acp/v1/msg_key", &input);
        let next_chain = blake3::derive_key("acp/v1/chain_step", self.send_chain.as_bytes());
        self.send_chain = Key32::new(next_chain);
        self.next_send_counter = self
            .next_send_counter
            .checked_add(1)
            .unwrap_or(self.next_send_counter);
        (key, counter)
    }

    pub fn recv_key_for_counter(&mut self, counter: u64) -> Result<[u8; 32], AcpError> {
        let expected = self.last_recv_counter.saturating_add(1);
        if counter != expected {
            return Err(AcpError::ReplayDetected(
                "counter must equal last_seen + 1 (first valid counter is 1)",
            ));
        }
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(self.recv_chain.as_bytes());
        input.extend_from_slice(&counter.to_le_bytes());
        let key = blake3::derive_key("acp/v1/msg_key", &input);
        let next_chain = blake3::derive_key("acp/v1/chain_step", self.recv_chain.as_bytes());
        self.recv_chain = Key32::new(next_chain);
        self.last_recv_counter = counter;
        Ok(key)
    }

    #[cfg(test)]
    pub fn next_send_counter(&self) -> u64 {
        self.next_send_counter
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionRole, SymmetricRatchet};

    #[test]
    fn ratchet_is_deterministic_and_unique() {
        let root = [5u8; 32];
        let mut a = SymmetricRatchet::from_root(root, SessionRole::Initiator);
        let mut b = SymmetricRatchet::from_root(root, SessionRole::Initiator);

        let (a1, c1) = a.next_send_key();
        let (b1, c1b) = b.next_send_key();
        assert_eq!(c1, 1);
        assert_eq!(c1b, 1);
        assert_eq!(a1, b1);

        let (a2, c2) = a.next_send_key();
        assert_eq!(c2, 2);
        assert_ne!(a1, a2);
        assert_eq!(a.next_send_counter(), 3);
    }

    #[test]
    fn strict_replay_policy() {
        let root = [3u8; 32];
        let mut recv = SymmetricRatchet::from_root(root, SessionRole::Responder);
        let _ = recv.recv_key_for_counter(1).expect("first");
        let err = recv.recv_key_for_counter(3).expect_err("gap must fail");
        assert!(format!("{err}").contains("counter must equal"));
    }
}
