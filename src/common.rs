use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::result;
use thiserror::Error as ThisError;

pub const EXTENDED_HEADER: [u8; 4] = [0xFF, 0x00, 0x5A, 0xA5];

/// RecordID is u24 and 0xFFFFFF is used for status, so max value is 0xFFFFFE = 16777214
pub const EVENT_LOG_MAX_ID: u32 = 16777214;

#[derive(ThisError, Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProtocolError {
    #[error("Unknown event type: {0}")]
    UnknownEventType(u8),
    #[error("Unknown command code: {0}")]
    UnknownCommandCode(u8),
    #[error("Unknown controller type: {0}")]
    UnknownControllerType(u8),
    #[error("Unknown event function code: {0}")]
    UnknownEventFunctionCode(u8),
    #[error("Unknown port number: {0}")]
    UnknownPortNumber(u8),
    #[error("Unknown controller access mode: {0}")]
    UnknownControllerAccessMode(u8),
    #[error("Unknown baud rate: {0}")]
    UnknownUartBaudRate(u8),
    #[error("Unknown uart type: {0}")]
    UnknownUartType(u8),
    #[error("Unknown host baud rate: {0}")]
    UnknownHostBaudRate(u8),
    #[error("Unknown operation mode: {0}")]
    UnknownOperationMode(u8),
    #[error("Response message too short")]
    MessageTooShort,
    #[error("Response message length mismatch")]
    MessageLengthMismatch,
    #[error("Unexpected header value")]
    UnexpectedHeaderValue,
    #[error("Unexpected first header byte: {0}")]
    UnexpectedFirstHeaderByte(u8),
    #[error("Not enough data in response")]
    NotEnoughData,
    #[error("Unexpected command code")]
    UnexpectedCommandCode,
    #[error("Invalid message: bad XOR value")]
    BadXorValue,
    #[error("Invalid message: bad checksum value")]
    BadChecksumValue,
    #[error("Event log out of range")]
    EventLogOutOfRange,
    #[error("User not found")]
    UserNotFound,
    #[error("Protocol version mismatch")]
    VersionMismatch,
    #[error("No response from reader")]
    NoResponse,
    #[error("Command not acknowledged")]
    CommandNotAcknowledged,
    #[error("Invalid date value")]
    InvalidDate,
    #[error("Invalid date-time value")]
    InvalidDateTime,
}

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] ProtocolError),
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
}

pub type Result<T> = result::Result<T, Error>;
