use std::fmt::Debug;
use std::convert;
use std::result;

use serde::{Serialize, Deserialize};
use chrono::{NaiveDate, Datelike};

pub const EXTENDED_HEADER: [u8; 4] = [0xFF, 0x00, 0x5A, 0xA5];

/// RecordID is u24 and 0xFFFFFF is used for status, so max value is 0xFFFFFE = 16777214
pub const EVENT_LOG_MAX_ID: u32 = 16777214;

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    UnknownEventType,
    UnknownCommandCode,
    UnknownControllerType,
    UnknownEventFunctionCode,
    UnknownPortNumber,
    MessageTooShort,
    MessageLengthMismatch,
    UnexpectedHeaderValue,
    UnexpectedFirstHeaderByte,
    NotEnoughData,
    UnexpectedCommandCode,
    BadXorValue,
    BadChecksumValue,
    EventLogOutOfRange,
}

#[derive(Debug)]
pub enum ClientError {
    IOError(std::io::Error),
    ProtocolError(ProtocolError),
}

impl convert::From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> ClientError {
        ClientError::IOError(e)
    }
}

impl convert::From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> ClientError {
        ClientError::ProtocolError(e)
    }
}

pub type Result<T> = result::Result<T, ClientError>;

enum_from_primitive! {
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControllerType {
    AR881E    = 0xC0,
    AR725Ev2  = 0xC1,
    AR829Ev5  = 0xC2,
    AR821EFv5 = 0xC3,
}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControllerAccessMode {
    PinOnly,           // Mode 8: 4 digit PIN
    UserAddressAndPin, // Mode 4: 5 digit address + 4 digit PIN
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserAccessMode {
    Invalid,
    ReadOnly,
    CardOrPIN,
    CardPlusPin,
}

impl UserAccessMode {
    pub fn decode(msb: bool, lsb: bool) -> UserAccessMode {
        match (msb, lsb) {
            (false, false) => UserAccessMode::Invalid,
            (false, true)  => UserAccessMode::ReadOnly,
            (true, false)  => UserAccessMode::CardOrPIN,
            (true, true)   => UserAccessMode::CardPlusPin,
        }
    }

    pub fn encode(&self) -> u8 {
        match self {
            UserAccessMode::Invalid =>     0b00000000,
            UserAccessMode::ReadOnly =>    0b00000001,
            UserAccessMode::CardOrPIN =>   0b00000010,
            UserAccessMode::CardPlusPin => 0b00000011,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusData {
    pub keypad_locked: bool,
    pub door_release_output: bool,
    pub alarm_output: bool,
    pub arming: bool,
    pub controller_alarm: bool,
    pub egress_released: bool,
    pub door_open: bool,
}

impl StatusData {
    pub fn decode(data: u8) -> StatusData {
        StatusData {
            keypad_locked:       data & 0b10000000 != 0,
            door_release_output: data & 0b01000000 != 0,
            alarm_output:        data & 0b00100000 != 0,
            arming:              data & 0b00010000 != 0,
            controller_alarm:    data & 0b00001000 != 0,
            // RFU:              data & 0b00000100 != 0,
            egress_released:     data & 0b00000010 != 0,
            door_open:           data & 0b00000001 != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlarmType {
    ForceAlarm,
    OpenTooLongAlarm,
}

impl AlarmType {
    pub fn decode(data: u8) -> AlarmType {
        if data >= 128 { AlarmType::ForceAlarm } else { AlarmType::OpenTooLongAlarm }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControllerOptions {
    pub anti_pass_back_enabled: bool,
    pub anti_pass_back_in: bool,
    pub force_open_alarm: bool,
    pub egress_button: bool,
    pub skip_pin_check: bool,
    pub auto_open_zone: bool,
    pub auto_lock_door: bool,
    pub time_attendance_disabled: bool,
}

impl ControllerOptions {
    pub fn decode(data: u8) -> ControllerOptions {
        ControllerOptions {
            anti_pass_back_enabled:   data & 0b10000000 != 0,
            anti_pass_back_in:        data & 0b01000000 != 0,
            force_open_alarm:         data & 0b00100000 != 0,
            egress_button:            data & 0b00010000 != 0,
            skip_pin_check:           data & 0b00001000 != 0,
            auto_open_zone:           data & 0b00000100 != 0,
            auto_lock_door:           data & 0b00000010 != 0,
            time_attendance_disabled: data & 0b00000001 != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtendedControllerOptions {
    pub door_relay_active_in_auto_open_time_zone: bool,
    pub stop_alarm_at_door_closed: bool,
    pub free_tag_access_mode: bool,
    pub use_main_door_relay_for_weigand_port: bool,
    pub auto_disarmed_time_zone: bool,
    pub key_pad_inhibited: bool,
    pub egress_button_sound: bool,
}

impl ExtendedControllerOptions {
    pub fn decode(data: u8) -> ExtendedControllerOptions {
        ExtendedControllerOptions {
            door_relay_active_in_auto_open_time_zone: data & 0b10000000 != 0,
            stop_alarm_at_door_closed:                data & 0b01000000 != 0,
            free_tag_access_mode:                     data & 0b00100000 != 0,
            use_main_door_relay_for_weigand_port:     data & 0b00010000 != 0,
            auto_disarmed_time_zone:                  data & 0b00001000 != 0,
            key_pad_inhibited:                        data & 0b00000100 != 0,
            // reserved                               data & 0b00000010 != 0,
            egress_button_sound:                      data & 0b00000001 != 0,
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IoStatusData {
    pub status_data: StatusData,
    pub alarm_type: Option<AlarmType>,
    pub controller_options: ControllerOptions,
}

impl IoStatusData {
    pub fn decode(data: &[u8]) -> Result<IoStatusData> {
        let status_data = StatusData::decode(data[0]);
        let alarm_type = match status_data.alarm_output {
            true => Some(AlarmType::decode(data[1])),
            false => None,
        };
        let controller_options = ControllerOptions::decode(data[2]);
        // data[3] RFU

        Ok(IoStatusData {
            status_data,
            alarm_type,
            controller_options,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllKeysPressedData {
    pub fifth_key_data: Option<u8>,
    pub input_value: u16,
    pub device_params: ControllerOptions,
    //elevator_controller_params: ElevatorControllerParams, // 401RO16’s parameter (24*xxx#) // TODO implement
    //key_data: KeyData, // TODO implement
}

impl AllKeysPressedData {
    pub fn decode(data: &[u8]) -> Result<AllKeysPressedData> {
        if data.len() < 13 {
            return Err(ProtocolError::NotEnoughData.into());
        }
        let fifth_key_data = if data[0] & 0b1000000 != 0 { Some(data[0]) } else { None };
        let input_value = u16::from_be_bytes([data[1], data[2]]);
        let device_params = ControllerOptions::decode(data[4]);

        Ok(AllKeysPressedData {
            input_value,
            fifth_key_data,
            device_params
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NewCardPresentData {
    //time_and_attendance: TimeAndAttendance, // TODO implement
    //exit_input: ExitInput, // TODO implement
    pub site_code: u16,
    pub input_value: u16, // if there was no input before flashing card this shows the previous value
    pub card_code: u16,
    pub id_em4001: u8,
    pub device_params: ControllerOptions,
    pub from_wiegand: bool,
    pub setting_forced_open_alarm: bool,
}

impl NewCardPresentData {
    pub fn decode(data: &[u8]) -> Result<NewCardPresentData> {
        if data.len() < 10 {
            return Err(ProtocolError::NotEnoughData.into());
        }
        let site_code    = u16::from_be_bytes([data[1], data[2]]);
        let input_value  = u16::from_be_bytes([data[3], data[4]]);
        let card_code    = u16::from_be_bytes([data[5], data[6]]);
        let id_em4001    = data[7];

        let device_params = ControllerOptions::decode(data[8]);

        let from_wiegand =              data[9] & 0b1000000 != 0;
        let setting_forced_open_alarm = data[9] & 0b0100000 != 0;

        Ok(NewCardPresentData {
            site_code,
            input_value,
            card_code,
            id_em4001,
            device_params,
            from_wiegand,
            setting_forced_open_alarm,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeypadEventData {
    // TODO implement KeypadEventData
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControllerStatus {
    IoStatus(IoStatusData),
    AllKeysPressed(AllKeysPressedData), // 4 or 5 keys pressed (depends on Mode 4 v. 8)
    NewCardPresent(NewCardPresentData),
    KeypadEvent(KeypadEventData), // some keys pressed
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
            0x06 => Ok(ControllerStatus::KeypadEvent(KeypadEventData {})),
            _ => Err(ProtocolError::UnknownEventType.into()),
        }
    }
}

enum_from_primitive! {
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortNumber {
    MainPort     = 17,
    WeigandPort1 = 18,
    WeigandPort2 = 19,
}
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserMode {
    pub access_mode: UserAccessMode,
    pub patrol_card: bool,
    pub card_omitted_after_fingerprint_rec: bool,
    pub fingerprint_omitted_after_card_rec: bool,
    pub expire_check: bool,
    pub anti_pass_back_control: bool,
    pub password_change_available: bool,
}

impl UserMode {
    pub fn decode(data: u8) -> UserMode {
        let access_mode_msb = data & 0b1000000 != 0;
        let access_mode_lsb = data & 0b0100000 != 0;

        UserMode {
            access_mode: UserAccessMode::decode(access_mode_msb, access_mode_lsb),
            patrol_card:                        data & 0b00100000 != 0,
            card_omitted_after_fingerprint_rec: data & 0b00010000 != 0,
            fingerprint_omitted_after_card_rec: data & 0b00001000 != 0,
            expire_check:                       data & 0b00000100 != 0,
            anti_pass_back_control:             data & 0b00000010 != 0,
            password_change_available:          data & 0b00000001 != 0,
        }
    }

    pub fn encode(&self) -> u8 {
        let mut data = self.access_mode.encode() << 6;
        if self.patrol_card                        { data += 0b00100000; }
        if self.card_omitted_after_fingerprint_rec { data += 0b00010000; }
        if self.fingerprint_omitted_after_card_rec { data += 0b00001000; }
        if self.expire_check                       { data += 0b00000100; }
        if self.anti_pass_back_control             { data += 0b00000010; }
        if self.password_change_available          { data += 0b00000001; }
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserAccessTimeZone {
    pub weigand_port_same_time_zone: bool,
    pub user_time_zone: u8, // Zero for free zone control, maximum is 63
}

impl UserAccessTimeZone {
    pub fn decode(data: u8) -> UserAccessTimeZone {
        UserAccessTimeZone {
            weigand_port_same_time_zone: data & 0b10000000 != 0,
            user_time_zone: data & 0b00111111,
        }
    }

    pub fn encode(&self) -> u8 {
        assert!(self.user_time_zone < 63, "maximum time zone is 63!");
        let mut data = self.user_time_zone;
        if self.weigand_port_same_time_zone {
            data += 0b1000000;
        }
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserParameters {
    pub tag_uid: u64,
    pub pin_code: u32,
    pub mode: UserMode,
    pub zone: UserAccessTimeZone,
    pub available_doors_bitmap: u16,
    pub last_allowed_date: NaiveDate,
    pub level: u8,
    pub enable_anti_pass_back_check: bool,
}

impl UserParameters {
    pub fn decode(data: &[u8]) -> Result<UserParameters> {
        if data.len() < 24 {
            return Err(ProtocolError::NotEnoughData.into());
        }

        let tag_uid = u64::from_be_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]);
        let pin_code = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let mode = UserMode::decode(data[12]);
        let zone = UserAccessTimeZone::decode(data[13]);
        let available_doors_bitmap = u16::from_be_bytes([data[14], data[15]]);

        let year = 2000 + data[16] as i32;
        let month = data[17] as u32;
        let day = data[18] as u32;
        let last_allowed_date = NaiveDate::from_ymd(year, month, day);

        let level = data[19];
        let enable_anti_pass_back_check = data[20] & 0b1000000 != 0;

        Ok(UserParameters {
            tag_uid,
            pin_code,
            mode,
            zone,
            available_doors_bitmap,
            last_allowed_date,
            level,
            enable_anti_pass_back_check,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        data.extend_from_slice(&self.tag_uid.to_be_bytes());
        data.extend_from_slice(&self.pin_code.to_be_bytes());
        data.push(self.mode.encode());
        data.push(self.zone.encode());
        data.extend_from_slice(&self.available_doors_bitmap.to_be_bytes());

        let year = self.last_allowed_date.year() - 2000;
        assert!(year < 0, "year minimum is 2000");
        assert!(year > 255, "year maximum is 2255");
        data.push(year as u8);
        data.push(self.last_allowed_date.month() as u8);
        data.push(self.last_allowed_date.day() as u8);

        data.push(self.level);
        let option_byte = if self.enable_anti_pass_back_check { 0b1000000 } else { 0b0000000 };
        data.push(option_byte);

        assert_eq!(data.len(), 26);

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_controller_options() {
        assert_eq!(ControllerOptions::decode(16), ControllerOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: true,
            skip_pin_check: false,
            auto_open_zone: false,
            auto_lock_door: false,
            time_attendance_disabled: false
        });

        assert_eq!(ControllerOptions::decode(15), ControllerOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: false,
            skip_pin_check: true,
            auto_open_zone: true,
            auto_lock_door: true,
            time_attendance_disabled: true
        });
    }

}
