use crate::error::AcpError;

pub const ACP_VERSION: u8 = 1;
pub const MSG_TYPE_DATA: u8 = 0x10;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;
pub const HEADER_LEN: usize = 1 + 1 + 8 + 4; // version + msg_type + counter + payload_len

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
        header[10..14].copy_from_slice(&self.payload_len.to_le_bytes());
        header
    }

    pub fn encode(&self) -> Vec<u8> {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert_eq!(self.payload_len as usize, self.ciphertext.len());

        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + self.ciphertext.len() + MAC_LEN);
        out.extend_from_slice(&self.aad_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, AcpError> {
        if input.len() < HEADER_LEN + NONCE_LEN + MAC_LEN {
            return Err(AcpError::parse_error("frame too short"));
        }
        let version = input[0];
        let msg_type = input[1];
        let counter = u64::from_le_bytes(
            input[2..10]
                .try_into()
                .map_err(|_| AcpError::parse_error("invalid counter bytes"))?,
        );
        let payload_len = u32::from_le_bytes(
            input[10..14]
                .try_into()
                .map_err(|_| AcpError::parse_error("invalid payload_len bytes"))?,
        );

        let expected = HEADER_LEN
            .checked_add(NONCE_LEN)
            .and_then(|v| v.checked_add(payload_len as usize))
            .and_then(|v| v.checked_add(MAC_LEN))
            .ok_or_else(|| AcpError::parse_error("payload_len causes overflow"))?;

        if input.len() != expected {
            return Err(AcpError::parse_error("payload length mismatch"));
        }

        let nonce: [u8; NONCE_LEN] = input[HEADER_LEN..HEADER_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| AcpError::parse_error("invalid nonce bytes"))?;

        let ciphertext_start = HEADER_LEN + NONCE_LEN;
        let ciphertext_end = ciphertext_start + payload_len as usize;
        let ciphertext = input[ciphertext_start..ciphertext_end].to_vec();

        let mac: [u8; MAC_LEN] = input[input.len() - MAC_LEN..]
            .try_into()
            .map_err(|_| AcpError::parse_error("invalid mac bytes"))?;
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
    use super::{Frame, ACP_VERSION, HEADER_LEN, MAC_LEN, MSG_TYPE_DATA, NONCE_LEN};

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
        assert_eq!(&encoded[10..14], &0x1122_3344u32.to_le_bytes());
    }

    #[test]
    fn payload_len_le_decode() {
        let frame = Frame {
            version: ACP_VERSION,
            msg_type: MSG_TYPE_DATA,
            counter: 0x0102_0304_0506_0708,
            nonce: [1u8; NONCE_LEN],
            payload_len: 2,
            ciphertext: vec![0xAA, 0xBB],
            mac: [2u8; MAC_LEN],
        };
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded.payload_len, 2);
        assert_eq!(decoded.counter, 0x0102_0304_0506_0708);
        assert_eq!(decoded.ciphertext, vec![0xAA, 0xBB]);
    }

    #[test]
    fn decode_rejects_overflow_payload_len() {
        let mut bad_frame = vec![0u8; HEADER_LEN + NONCE_LEN + MAC_LEN];
        bad_frame[0] = ACP_VERSION;
        bad_frame[1] = MSG_TYPE_DATA;
        bad_frame[10..14].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = Frame::decode(&bad_frame).expect_err("should reject overflow");
        assert!(format!("{err}").contains("overflow") || format!("{err}").contains("mismatch"));
    }
}
