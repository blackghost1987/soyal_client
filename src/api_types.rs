use std::fmt::Debug;
use std::ops::BitXorAssign;
use std::convert;

use serde::{Serialize, Deserialize};

const EXTENDED_HEADER: [u8; 4] = [0xFF, 0x00, 0x5A, 0xA5];

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    UnknownEventType,
    MessageTooShort,
    MessageLengthMismatch,
    UnexpectedHeaderValue,
    UnexpectedFirstHeaderByte,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedMessage<'a> {
    pub destination_id: u8, // 0x00: bus master, 0xFF: broadcast
    pub command_code: u8,
    pub data: &'a [u8],
}

impl<'a> ExtendedMessage<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let length: u16 = self.data.len() as u16 + 4; // 4 extra bytes: destination_id, command_code, xor, sum

        assert!(length < 250, "Extended message data part too long!");

        let full_length: u16 = length + 4 + 2; // 4 header + 2 length bytes

        let mut buffer = Vec::<u8>::with_capacity(full_length as usize);
        buffer.extend_from_slice(&EXTENDED_HEADER);
        buffer.extend_from_slice(&length.to_be_bytes());
        buffer.push(self.destination_id);
        buffer.push(self.command_code);
        buffer.extend_from_slice(&self.data);

        let mut xor_res: u8 = 0xFF;
        xor_res.bitxor_assign(self.destination_id);
        xor_res.bitxor_assign(self.command_code);
        for d in self.data {
            xor_res.bitxor_assign(d);
        }
        buffer.push(xor_res);

        let mut sum_res: u8 = 0;
        sum_res = sum_res.wrapping_add(self.destination_id);
        sum_res = sum_res.wrapping_add(self.command_code);
        for d in self.data {
            sum_res = sum_res.wrapping_add(*d);
        }
        sum_res = sum_res.wrapping_add(xor_res);
        buffer.push(sum_res);

        buffer
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusData {
    keypad_locked: bool,
    door_release_output: bool,
    alarm_output: bool,
    arming: bool,
    controller_alarm: bool,
    egress_released: bool,
    door_open: bool,
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
    anti_pass_back_enabled: bool,
    anti_pass_back_in: bool,
    force_open_alarm: bool,
    egress_button: bool,
    skip_pin_check: bool,
    auto_open_zone: bool,
    auto_lock_door: bool,
    time_attendance_disabled: bool,
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
pub struct IoStatusData {
    status_data: StatusData,
    alarm_type: Option<AlarmType>,
    controller_options: ControllerOptions,
}

impl IoStatusData {
    pub fn decode(data: &[u8]) -> Result<IoStatusData, ClientError> {
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
pub struct AllKeysPressed {
    fifth_key_data: Option<u8>,
    input_value: u16,
    //device_params: DeviceParameters, // TODO implement
    //elevator_controller_params: ElevatorControllerParams, // 401RO16’s parameter (24*xxx#) // TODO implement
    //key_data: KeyData, TODO implement
}

impl AllKeysPressed {
    pub fn decode(data: &[u8]) -> Result<AllKeysPressed, ClientError> {
        let fifth_key_data = if data[0] & 0b1000000 != 0 { Some(data[0]) } else { None };
        let input_value = u16::from_be_bytes([data[1], data[2]]);

        Ok(AllKeysPressed {
            input_value,
            fifth_key_data,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NewCardPresentData {
    // TODO implement
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeypadEventData {
    // TODO implement
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EchoEvent {
    IoStatus(IoStatusData),
    AllKeysPressed(AllKeysPressed), // 4 or 5 keys pressed (depends on Mode 8)
    NewCardPresent(NewCardPresentData),
    KeypadEvent(KeypadEventData), // some keys pressed
}

impl convert::From<IoStatusData> for EchoEvent {
    fn from(e: IoStatusData) -> EchoEvent {
        EchoEvent::IoStatus(e)
    }
}

impl convert::From<AllKeysPressed> for EchoEvent {
    fn from(e: AllKeysPressed) -> EchoEvent {
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
    pub fn decode(event_type: u8, data: &[u8]) -> Result<EchoEvent, ClientError> {
        match event_type {
            0x00 => IoStatusData::decode(data).map(EchoEvent::from),
            0x01 => AllKeysPressed::decode(data).map(EchoEvent::from),
            0x02 => Ok(EchoEvent::NewCardPresent(NewCardPresentData {})),
            0x06 => Ok(EchoEvent::KeypadEvent(KeypadEventData {})),
            _ => Err(ProtocolError::UnknownEventType.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchoResponse {
    pub destination_id: u8, // 0x00 Host
    pub function_code: u8,
    pub source: u8,
    pub event_type: u8,
    pub data: EchoEvent,
}

impl EchoResponse {
    pub fn decode(raw: &Vec<u8>) -> Result<EchoResponse, ClientError> {
        let non_header = match raw[0]  {
            0x7E => Ok(&raw[1..]),
            0xFF => match raw[0..4] == EXTENDED_HEADER {
                true => Ok(&raw[4..]),
                false => Err(ProtocolError::UnexpectedHeaderValue)
            },
            _    => Err(ProtocolError::UnexpectedFirstHeaderByte)
        }?;

        if non_header.len() < 8 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let expected_msg_length = u16::from_be_bytes([non_header[0], non_header[1]]) as usize;
        let msg_length = non_header.len() - 2;
        if expected_msg_length != msg_length {
            eprintln!("Message length mismatch, expected: {} but got: {}", expected_msg_length, msg_length);
            return Err(ProtocolError::MessageLengthMismatch.into());
        };

        // ignore the first 2 length bytes
        let raw_msg = &non_header[2..];

        let destination_id = raw_msg[0];
        let function_code  = raw_msg[1];
        let source         = raw_msg[2];
        let event_type     = raw_msg[3];

        let _sum = raw_msg.get(msg_length-1).expect("Missing sum value");
        let _xor = raw_msg.get(msg_length-2).expect("Missing xor value");
        // TODO validate xor and sum

        let expected_data_length = expected_msg_length - 6;
        let raw_data = &raw_msg[4..msg_length-2];
        assert_eq!(expected_data_length, raw_data.len(), "Data length mismatch");

        let data = EchoEvent::decode(event_type, raw_data)?;

        Ok(EchoResponse {
            destination_id,
            function_code,
            source,
            event_type: event_type,
            data: data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_no_data() {
        let d = ExtendedMessage {
            destination_id: 1,
            command_code: 0x18,
            data: &[],
        };
        assert_eq!(d.encode(), vec!(0xFF, 0x00, 0x5A, 0xA5, 0x00, 0x04, 0x01, 0x18, 0xE6, 0xFF))
    }

    #[test]
    fn encode_with_data() {
        let d = ExtendedMessage {
            destination_id: 1,
            command_code: 0x18,
            data: &[0x01, 0x02],
        };
        assert_eq!(d.encode(), vec!(0xFF, 0x00, 0x5A, 0xA5, 0x00, 0x06, 0x01, 0x18, 0x01, 0x02, 0xE5, 0x01))
    }

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

    #[test]
    fn decode_echo_response() {
        let raw = vec!(255, 0, 90, 165, 0, 10, 0, 9, 1, 0, 1, 0, 16, 0, 230, 1);
        let d = EchoResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 0);
            assert_eq!(echo.data, EchoEvent::IoStatus(IoStatusData {
                status_data: StatusData {
                    keypad_locked: false,
                    door_release_output: false,
                    alarm_output: false,
                    arming: false,
                    controller_alarm: false,
                    egress_released: false,
                    door_open: true
                },
                alarm_type: None,
                controller_options: ControllerOptions {
                    anti_pass_back_enabled: false,
                    anti_pass_back_in: false,
                    force_open_alarm: false,
                    egress_button: true,
                    skip_pin_check: false,
                    auto_open_zone: false,
                    auto_lock_door: false,
                    time_attendance_disabled: false
                },
            }));
        }
    }
}
