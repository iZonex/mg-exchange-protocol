//! Unified error types for the MGEP protocol.

use std::fmt;

/// Top-level MGEP error.
#[derive(Debug)]
pub enum MgepError {
    /// Message decoding error.
    Decode(DecodeError),
    /// Session protocol error.
    Session(crate::session::SessionError),
    /// Transport / IO error.
    Transport(std::io::Error),
    /// Authentication or encryption error.
    Auth(AuthError),
}

impl fmt::Display for MgepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "decode: {}", e),
            Self::Session(e) => write!(f, "session: {}", e),
            Self::Transport(e) => write!(f, "transport: {}", e),
            Self::Auth(e) => write!(f, "auth: {}", e),
        }
    }
}

impl std::error::Error for MgepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Session(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::Auth(e) => Some(e),
        }
    }
}

impl From<DecodeError> for MgepError {
    fn from(e: DecodeError) -> Self { Self::Decode(e) }
}

impl From<crate::session::SessionError> for MgepError {
    fn from(e: crate::session::SessionError) -> Self { Self::Session(e) }
}

impl From<std::io::Error> for MgepError {
    fn from(e: std::io::Error) -> Self { Self::Transport(e) }
}

impl From<AuthError> for MgepError {
    fn from(e: AuthError) -> Self { Self::Auth(e) }
}

/// Message decoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer is too short for the expected struct.
    BufferTooShort { expected: usize, actual: usize },
    /// Frame header declares an invalid message size.
    InvalidFrameSize { size: u32 },
    /// Unknown or unsupported schema ID.
    InvalidSchemaId { schema_id: u16 },
    /// Unknown message type within schema.
    InvalidMessageType { schema_id: u16, msg_type: u16 },
    /// Flex block count exceeds available data.
    FlexBlockOverflow { declared_count: u16, available_bytes: usize },
    /// Flex block exceeds maximum allowed size.
    FlexBlockTooLarge { size: usize, max: usize },
    /// Schema version not supported.
    UnsupportedVersion { version: u8, max: u8 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: need {} bytes, got {}", expected, actual)
            }
            Self::InvalidFrameSize { size } => {
                write!(f, "invalid frame size: {}", size)
            }
            Self::InvalidSchemaId { schema_id } => {
                write!(f, "unknown schema_id: 0x{:04X}", schema_id)
            }
            Self::InvalidMessageType { schema_id, msg_type } => {
                write!(f, "unknown msg_type 0x{:02X} in schema 0x{:04X}", msg_type, schema_id)
            }
            Self::FlexBlockOverflow { declared_count, available_bytes } => {
                write!(f, "flex block overflow: {} fields declared but only {} bytes available",
                    declared_count, available_bytes)
            }
            Self::FlexBlockTooLarge { size, max } => {
                write!(f, "flex block too large: {} bytes (max {})", size, max)
            }
            Self::UnsupportedVersion { version, max } => {
                write!(f, "unsupported version {} (max {})", version, max)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Authentication / encryption errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// HMAC verification failed.
    HmacVerifyFailed,
    /// Message too short to contain auth tag.
    MessageTooShortForAuth { size: usize },
    /// Decryption failed (GCM tag mismatch).
    DecryptionFailed,
    /// Missing encryption key.
    NoKey,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HmacVerifyFailed => write!(f, "HMAC verification failed"),
            Self::MessageTooShortForAuth { size } => {
                write!(f, "message too short for auth: {} bytes", size)
            }
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::NoKey => write!(f, "no encryption key configured"),
        }
    }
}

impl std::error::Error for AuthError {}
