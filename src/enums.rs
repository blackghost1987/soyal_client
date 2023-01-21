use crate::common::*;
use crate::structs::*;

use std::fmt::Debug;
use std::{convert, fmt};

use serde::{Deserialize, Serialize};

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EchoCode {
    RequestedData               = 0x03,
    CommandAcknowledged         = 0x04,
    CommandUnacknowledged       = 0x05,
    AuthenticationFailed        = 0x06,
    NoTagsPresented             = 0x07,
    NotLogin                    = 0x08,
    CRCError                    = 0x09,
    NotAuthenticated            = 0x0A,
    AuthenticationLayerRejected = 0x0B,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ControllerType {
    AR881E    = 0xC0,
    AR725Ev2  = 0xC1,
    AR829Ev5  = 0xC2,
    AR821EFv5 = 0xC3,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ControllerAccessMode {
    PINOnly           = 8, // 4 digit PIN
    UserAddressAndPIN = 4, // 5 digit address + 4 digit PIN
}
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum UserAccessMode {
    Invalid,
    ReadOnly,
    CardOrPIN,
    CardPlusPIN,
}

impl UserAccessMode {
    pub fn decode(msb: bool, lsb: bool) -> UserAccessMode {
        match (msb, lsb) {
            (false, false) => UserAccessMode::Invalid,
            (false, true) => UserAccessMode::ReadOnly,
            (true, false) => UserAccessMode::CardOrPIN,
            (true, true) => UserAccessMode::CardPlusPIN,
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            UserAccessMode::Invalid => 0b00000000,
            UserAccessMode::ReadOnly => 0b00000001,
            UserAccessMode::CardOrPIN => 0b00000010,
            UserAccessMode::CardPlusPIN => 0b00000011,
        }
    }
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum OperationMode {
    Users16kFloors64 = 0x00,
    Users32kFloors32 = 0x01,
    Users65kFloors16 = 0x02,
}
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AlarmType {
    ForceAlarm,
    OpenTooLongAlarm,
}

impl AlarmType {
    pub fn decode(data: u8) -> AlarmType {
        if data >= 128 {
            AlarmType::ForceAlarm
        } else {
            AlarmType::OpenTooLongAlarm
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum UART2Type {
    Fingerprint9000,
    Fingerprint3DO1500,
    LiftController,
    SlavePortAR716E,
    VoiceModuleOrReader, // voice module port for EV5, channel 1 reader port for AR721Ev2
    SerialPrinter,
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum UartBaudRate {
    Baud4800  = 0b00000000,
    Baud9600  = 0b01000000,
    Baud19200 = 0b10000000,
    Baud38400 = 0b11000000,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HostBaudRate {
    Baud9600   = 0x00,
    Baud19200  = 0x01,
    Baud38400  = 0x02,
    Baud57600  = 0x03,
    Baud115200 = 0x04,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum UART3Type {
    YungTAILiftPort     = 0b00000000,
    LEDDisplayPanel     = 0b00100000,
    VoiceModuleOrReader = 0b00110000, // voice module port for EV5, channel 2 reader port for AR721Ev2
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RS485PortFunction {
    LiftControlOutput = 0b00000000,
    HostCommunication = 0b00010000,
    LEDDisplayPanel   = 0b00100000,
    SerialPrinter     = 0b00110000,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy , PartialEq, Serialize, Deserialize)]
pub enum UIDDisplayFormat {
    Disabled = 0b00000000,
    WG32     = 0b00000001,
    ABA10    = 0b00000010,
    HEX      = 0b00000011,
    WG26     = 0b00000100,
    ABA8     = 0b00000101,
    Custom   = 0b00000110,
}
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControllerStatus {
    IoStatus(IoStatusData),
    AllKeysPressed(AllKeysPressedData), // 4 or 5 keys pressed (depends on Mode 4 v. 8)
    NewCardPresent(NewCardPresentData),
    KeypadEvent(KeypadEventData), // some keys pressed - only in Hosting mode!
}

impl convert::From<IoStatusData> for ControllerStatus {
    fn from(e: IoStatusData) -> ControllerStatus {
        ControllerStatus::IoStatus(e)
    }
}

impl convert::From<AllKeysPressedData> for ControllerStatus {
    fn from(e: AllKeysPressedData) -> ControllerStatus {
        ControllerStatus::AllKeysPressed(e)
    }
}

impl convert::From<NewCardPresentData> for ControllerStatus {
    fn from(e: NewCardPresentData) -> ControllerStatus {
        ControllerStatus::NewCardPresent(e)
    }
}

impl convert::From<KeypadEventData> for ControllerStatus {
    fn from(e: KeypadEventData) -> ControllerStatus {
        ControllerStatus::KeypadEvent(e)
    }
}

impl ControllerStatus {
    pub fn decode(event_type: u8, data: &[u8]) -> Result<ControllerStatus> {
        match event_type {
            0x00 => IoStatusData::decode(data).map(ControllerStatus::from),
            0x01 => AllKeysPressedData::decode(data).map(ControllerStatus::from),
            0x02 => NewCardPresentData::decode(data).map(ControllerStatus::from),
            0x06 => KeypadEventData::decode(data).map(ControllerStatus::from),
            other => Err(ProtocolError::UnknownEventType(other).into()),
        }
    }
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EventFunctionCode {
    SiteCodeError                    = 0,
    InvalidUserPIN                   = 1,
    KeypadLockedByErrorLimit         = 2,
    InvalidCard                      = 3,
    TimeZoneError                    = 4,
    DoorGroupError                   = 5,
    ExpiryDate                       = 6,
    OverAccessTimes                  = 7,
    PINCodeError                     = 8,
    PressDuressPB                    = 9,
    AccessByCardAndPIN               = 10,
    NormalAccessByTag                = 11,
    ForceControllerRelayOn           = 12,
    ForceControllerRelayOff          = 13,
    ControllerArmed                  = 14,
    ControllerDisarmed               = 15,
    Egress                           = 16,
    AlarmEvent                       = 17,
    //18
    //19
    ControllerPowerOff               = 20,
    Duress                           = 21,
    GuardsForHelp                    = 22,
    CleanerAccess                    = 23,
    ControllerPowerOn                = 24,
    ForceControllerRelayError        = 25,
    ReaderReturnToNormal             = 26,
    HelpButtonPressed                = 27,
    AccessByPIN                      = 28,
    DigitalInputActive               = 29,
    //30
    RS485SlaveReaderOffline          = 31,
    RS485SlaveReaderOnline           = 32,
    UserPINCodeChanged               = 33,
    ChangeUserPINError               = 34,
    EnterAutoDoorOpenProcedure       = 35,
    ExitAutoDoorOpenProcedure        = 36,
    AutoDisarmed                     = 37,
    AutoArmed                        = 38,
    AccessByFingerprintOrVein        = 39,
    FingerprintIdentifyFailed        = 40,
    //41
    RemoteControlUpKeyPressed        = 42,
    DisableReader                    = 43,
    EnableReader                     = 44,
    RemoteControlPanicKeyPressed     = 45,
    UserEntranceAtParkingSystem      = 46,
    UserExitAtParkingSystem          = 47,
    CounterTriggeredAtParkingSystem  = 48,
    LatchRelay                       = 49,
    //50
    //51
    //52
    EnterExitEditMode                = 53,
    //54
    FreeAccessModeEnabledDisabled    = 55,
    AccessViaFingerprintError        = 56,
    //57
    //58
    InhibitCardWhileDoorOpen         = 59,
    NeverOpenDoorAfterCardAccessed   = 60,
    //61
    MifareCardDateTimeReadError      = 62,
    MifareCardCommandReadError       = 63,
    MifareCardDeductError            = 64,
    SORGlobalCardAccessed            = 65,
    SORDisturberLayerError           = 66,
    AccessRejectedBeforeBeginDate    = 67,
    AccessRejectedExpiry             = 68,
    AccessRejectedCardValueNotEnough = 69,
    AccessOkAndCardValueDeducted     = 70,
    AccessOkAndReadLiftDataFailed    = 71,
    SORGlobalAccessOkAndDeducted     = 72,
    SORGlobalAccessValueNotEnough    = 73,
    SORGlobalAccessOkButDeductFailed = 74,
    SORGlobalAccessWithoutDeducted   = 75,
    //..
    BlackTableTagAccessed            = 86,
    AccessViaVeinOk                  = 100,
    AccessViaVeinReject              = 101,
    InhibitedByInternalLockLocked    = 102,
    FireAlarmInputTriggered          = 104,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EventPortNumber {
    MainPort     = 17,
    WiegandPort1 = 18,
    WiegandPort2 = 19,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RelayPortNumber {
    MainPort     = 0x00,
    WiegandPort1 = 0x01,
    WiegandPort2 = 0x02,
    AllPorts     = 0xFF,
}
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RelayCommand {
    GetCurrentStatus = 0x00,
    EnableArmedState = 0x80,
    DisableArmedState = 0x81,
    DoorRelayOn = 0x82,
    DoorRelayOff = 0x83,
    DoorRelayPulse = 0x84,
    AlarmRelayOn = 0x85,
    AlarmRelayOff = 0x86,
    AlarmRelayPulse = 0x87,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TagId {
    TagId32(TagId32),
    TagId64(TagId64),
}

impl fmt::Display for TagId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TagId::TagId32(t) => write!(f, "{}", t),
            TagId::TagId64(t) => write!(f, "{}", t),
        }
    }
}

impl convert::From<TagId32> for TagId {
    fn from(t: TagId32) -> TagId {
        TagId::TagId32(t)
    }
}

impl convert::From<TagId64> for TagId {
    fn from(t: TagId64) -> TagId {
        TagId::TagId64(t)
    }
}
