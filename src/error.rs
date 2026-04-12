use core::fmt;
use std::borrow::Cow;

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
    InvalidArgument(Cow<'static, str>),
    BufferTooSmall(usize),
    InvalidState(Cow<'static, str>),
    ParseError(Cow<'static, str>),
    VerifyFailed(Cow<'static, str>),
    ReplayDetected(Cow<'static, str>),
    CryptoError(Cow<'static, str>),
    InternalError(Cow<'static, str>),
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

    pub fn buffer_size_needed(&self) -> Option<usize> {
        match self {
            Self::BufferTooSmall(needed) => Some(*needed),
            _ => None,
        }
    }

    pub fn invalid_argument(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    pub fn invalid_state(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::InvalidState(msg.into())
    }

    pub fn parse_error(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::ParseError(msg.into())
    }

    pub fn verify_failed(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::VerifyFailed(msg.into())
    }

    pub fn replay_detected(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::ReplayDetected(msg.into())
    }

    pub fn crypto_error(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::CryptoError(msg.into())
    }

    pub fn internal_error(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::InternalError(msg.into())
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

impl std::error::Error for AcpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
