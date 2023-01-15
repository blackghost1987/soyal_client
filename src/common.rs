use serde::{Deserialize, Serialize};
use std::convert;
use std::fmt::Debug;
use std::result;

pub const EXTENDED_HEADER: [u8; 4] = [0xFF, 0x00, 0x5A, 0xA5];

/// RecordID is u24 and 0xFFFFFF is used for status, so max value is 0xFFFFFE = 16777214
pub const EVENT_LOG_MAX_ID: u32 = 16777214;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ProtocolError {
    UnknownEventType,
    UnknownCommandCode,
    UnknownControllerType,
    UnknownEventFunctionCode,
    UnknownPortNumber,
    UnknownControllerAccessMode,
    UnknownUartBaudRate,
    UnknownUartType,
    UnknownHostBaudRate,
    UnknownRS485PortType,
    UnknownOperationMode,
    MessageTooShort,
    MessageLengthMismatch,
    UnexpectedHeaderValue,
    UnexpectedFirstHeaderByte,
    NotEnoughData,
    UnexpectedCommandCode,
    BadXorValue,
    BadChecksumValue,
    EventLogOutOfRange,
    UserNotFound,
    VersionMismatch,
    NoResponse,
    CommandNotAcknowledged,
}

#[derive(Debug)]
pub enum Error {
    IOError(std::io::Error),
    ProtocolError(ProtocolError),
}

impl convert::From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IOError(e)
    }
}

impl convert::From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Error {
        Error::ProtocolError(e)
    }
}

pub type Result<T> = result::Result<T, Error>;
