use core::fmt;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcpResult {
    Ok = 0,
    InvalidArgument = 1,
    BufferTooSmall = 2,
    InvalidState = 3,
    ParseError = 4,
    VerifyFailed = 5,
    ReplayDetected = 6,
    CryptoError = 7,
    InternalError = 8,
    Panic = 9,
}

#[derive(Debug)]
pub enum AcpError {
    InvalidArgument(&'static str),
    BufferTooSmall(usize),
    InvalidState(&'static str),
    ParseError(&'static str),
    VerifyFailed(&'static str),
    ReplayDetected(&'static str),
    CryptoError(&'static str),
    InternalError(&'static str),
}

impl AcpError {
    pub fn result_code(&self) -> AcpResult {
        match self {
            Self::InvalidArgument(_) => AcpResult::InvalidArgument,
            Self::BufferTooSmall(_) => AcpResult::BufferTooSmall,
            Self::InvalidState(_) => AcpResult::InvalidState,
            Self::ParseError(_) => AcpResult::ParseError,
            Self::VerifyFailed(_) => AcpResult::VerifyFailed,
            Self::ReplayDetected(_) => AcpResult::ReplayDetected,
            Self::CryptoError(_) => AcpResult::CryptoError,
            Self::InternalError(_) => AcpResult::InternalError,
        }
    }
}

impl fmt::Display for AcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::BufferTooSmall(needed) => write!(f, "buffer too small, need {needed} bytes"),
            Self::InvalidState(msg) => write!(f, "invalid state: {msg}"),
            Self::ParseError(msg) => write!(f, "parse error: {msg}"),
            Self::VerifyFailed(msg) => write!(f, "verification failed: {msg}"),
            Self::ReplayDetected(msg) => write!(f, "replay detected: {msg}"),
            Self::CryptoError(msg) => write!(f, "crypto error: {msg}"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AcpError {}
