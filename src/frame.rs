use crate::error::AcpError;

pub const ACP_VERSION: u8 = 1;
pub const MSG_TYPE_DATA: u8 = 0x10;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;
pub const HEADER_LEN: usize = 1 + 1 + 8 + NONCE_LEN + 4;

#[derive(Debug, Clone)]
pub struct Frame {
    pub version: u8,
    pub msg_type: u8,
    pub counter: u64,
    pub nonce: [u8; NONCE_LEN],
    pub payload_len: u32,
    pub ciphertext: Vec<u8>,
    pub mac: [u8; MAC_LEN],
}

impl Frame {
    pub fn aad_bytes(&self) -> [u8; HEADER_LEN] {
        let mut header = [0u8; HEADER_LEN];
        header[0] = self.version;
        header[1] = self.msg_type;
        header[2..10].copy_from_slice(&self.counter.to_le_bytes());
        header[10..34].copy_from_slice(&self.nonce);
        header[34..38].copy_from_slice(&self.payload_len.to_le_bytes());
        header
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len() + MAC_LEN);
        out.extend_from_slice(&self.aad_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcpError> {
        if input.len() < HEADER_LEN + MAC_LEN {
            return Err(AcpError::ParseError("frame too short"));
        }
        let version = input[0];
        let msg_type = input[1];
        let counter = u64::from_le_bytes(
            input[2..10]
                .try_into()
                .map_err(|_| AcpError::ParseError("invalid counter bytes"))?,
        );
        let nonce: [u8; NONCE_LEN] = input[10..34]
            .try_into()
            .map_err(|_| AcpError::ParseError("invalid nonce bytes"))?;
        // payload_len is explicitly little-endian.
        let payload_len = u32::from_le_bytes(
            input[34..38]
                .try_into()
                .map_err(|_| AcpError::ParseError("invalid payload_len bytes"))?,
        );
        let expected = HEADER_LEN + payload_len as usize + MAC_LEN;
        if input.len() != expected {
            return Err(AcpError::ParseError("payload length mismatch"));
        }
        let ciphertext = input[HEADER_LEN..HEADER_LEN + payload_len as usize].to_vec();
        let mac: [u8; MAC_LEN] = input[input.len() - MAC_LEN..]
            .try_into()
            .map_err(|_| AcpError::ParseError("invalid mac bytes"))?;
        Ok(Self {
            version,
            msg_type,
            counter,
            nonce,
            payload_len,
            ciphertext,
            mac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, ACP_VERSION, MAC_LEN, MSG_TYPE_DATA, NONCE_LEN};

    #[test]
    fn frame_roundtrip() {
        let frame = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter: 42,
            nonce: [7u8; NONCE_LEN],
            payload_len: 3,
            ciphertext: vec![1, 2, 3],
            mac: [9u8; MAC_LEN],
        };
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded.version, ACP_VERSION);
        assert_eq!(decoded.msg_type, MSG_TYPE_DATA);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.payload_len, 3);
        assert_eq!(decoded.ciphertext, vec![1, 2, 3]);
        assert_eq!(decoded.mac, [9u8; MAC_LEN]);
    }

    #[test]
    fn frame_rejects_malformed_payload_len() {
        let frame = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter: 1,
            nonce: [0u8; NONCE_LEN],
            payload_len: 4,
            ciphertext: vec![1, 2, 3],
            mac: [0u8; MAC_LEN],
        };
        let encoded = frame.encode();
        let err = Frame::decode(&encoded).expect_err("should reject");
        assert!(format!("{err}").contains("payload length mismatch"));
    }

    #[test]
    fn payload_len_le_is_used() {
        let frame = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter: 0x0102_0304_0506_0708,
            nonce: [1u8; NONCE_LEN],
            payload_len: 0x1122_3344,
            ciphertext: vec![],
            mac: [2u8; MAC_LEN],
        };
        let encoded = frame.encode();
        assert_eq!(&encoded[34..38], &0x1122_3344u32.to_le_bytes());
    }
}
