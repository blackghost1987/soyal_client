use std::fmt::Debug;
use std::convert;
use std::result;

use serde::{Serialize, Deserialize};

pub const EXTENDED_HEADER: [u8; 4] = [0xFF, 0x00, 0x5A, 0xA5];

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    UnknownEventType,
    MessageTooShort,
    MessageLengthMismatch,
    UnexpectedHeaderValue,
    UnexpectedFirstHeaderByte,
    NotEnoughData,
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
    //key_data: KeyData, TODO implement
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
    // TODO implement
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EchoEvent {
    IoStatus(IoStatusData),
    AllKeysPressed(AllKeysPressedData), // 4 or 5 keys pressed (depends on Mode 4 v. 8)
    NewCardPresent(NewCardPresentData),
    KeypadEvent(KeypadEventData), // some keys pressed
}

impl convert::From<IoStatusData> for EchoEvent {
    fn from(e: IoStatusData) -> EchoEvent {
        EchoEvent::IoStatus(e)
    }
}

impl convert::From<AllKeysPressedData> for EchoEvent {
    fn from(e: AllKeysPressedData) -> EchoEvent {
        EchoEvent::AllKeysPressed(e)
    }
}

impl convert::From<NewCardPresentData> for EchoEvent {
    fn from(e: NewCardPresentData) -> EchoEvent {
        EchoEvent::NewCardPresent(e)
    }
}

impl convert::From<KeypadEventData> for EchoEvent {
    fn from(e: KeypadEventData) -> EchoEvent {
        EchoEvent::KeypadEvent(e)
    }
}

impl EchoEvent {
    pub fn decode(event_type: u8, data: &[u8]) -> Result<EchoEvent> {
        match event_type {
            0x00 => IoStatusData::decode(data).map(EchoEvent::from),
            0x01 => AllKeysPressedData::decode(data).map(EchoEvent::from),
            0x02 => NewCardPresentData::decode(data).map(EchoEvent::from),
            0x06 => Ok(EchoEvent::KeypadEvent(KeypadEventData {})),
            _ => Err(ProtocolError::UnknownEventType.into()),
        }
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