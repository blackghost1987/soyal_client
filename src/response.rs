use serde::{Serialize, Deserialize};

use crate::api_types::*;

pub trait Response<T> {
    fn decode(raw: &Vec<u8>) -> Result<T>;

    fn get_message_part(raw: &Vec<u8>) -> Result<&[u8]> {
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

        let _sum = raw_msg.get(msg_length-1).expect("Missing sum value");
        let _xor = raw_msg.get(msg_length-2).expect("Missing xor value");
        // TODO validate xor and sum

        // ignore the last two xor/sum bytes
        Ok(&raw_msg[0..msg_length-2])
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

impl Response<EchoResponse> for EchoResponse {
    fn decode(raw: &Vec<u8>) -> Result<EchoResponse> {
        let raw_msg = Self::get_message_part(raw)?;
        let msg_length = raw_msg.len();

        let destination_id = raw_msg[0];
        let function_code  = raw_msg[1];
        let source         = raw_msg[2];
        let event_type     = raw_msg[3];

        let raw_data = &raw_msg[4..msg_length];
        let data = EchoEvent::decode(event_type, raw_data)?;

        Ok(EchoResponse {
            destination_id,
            function_code,
            source,
            event_type,
            data,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialNumberResponse {
    pub destination_id: u8, // 0x00 Host
    pub command: u8,
    pub source: u8,
    //pub flash_size_code: ???
    pub serial: Vec<u8>,
}

impl Response<SerialNumberResponse> for SerialNumberResponse {
    fn decode(raw: &Vec<u8>) -> Result<SerialNumberResponse> {
        let raw_msg = Self::get_message_part(raw)?;

        let destination_id = raw_msg[0];
        let command = raw_msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let source = raw_msg[2];
        let serial = raw_msg[5..17].to_vec();

        Ok(SerialNumberResponse {
            destination_id,
            command,
            source,
            serial,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDelayResponse {
    pub destination_id: u8, // 0x00 Host
    pub command: u8,
    pub source: u8,
    pub main_port_door_time: u16,
    pub wg_port_door_time: u16,
    pub alarm_relay_time: u16,
    pub lift_controller_time: u16,
}

impl Response<RelayDelayResponse> for RelayDelayResponse {
    fn decode(raw: &Vec<u8>) -> Result<RelayDelayResponse> {
        let raw_msg = Self::get_message_part(raw)?;

        let destination_id = raw_msg[0];
        let command = raw_msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let source = raw_msg[2];
        let main_port_door_time  = u16::from_be_bytes([raw_msg[3], raw_msg[4]]);
        let wg_port_door_time    = u16::from_be_bytes([raw_msg[5], raw_msg[6]]);
        let alarm_relay_time     = u16::from_be_bytes([raw_msg[7], raw_msg[8]]);
        let lift_controller_time = u16::from_be_bytes([raw_msg[9], raw_msg[10]]);

        Ok(RelayDelayResponse {
            destination_id,
            command,
            source,
            main_port_door_time,
            wg_port_door_time,
            alarm_relay_time,
            lift_controller_time,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPasswordResponse {
    pub destination_id: u8, // 0x00 Host
    pub command: u8,
    pub password: u32,
}

impl Response<EditPasswordResponse> for EditPasswordResponse {
    fn decode(raw: &Vec<u8>) -> Result<EditPasswordResponse> {
        let raw_msg = Self::get_message_part(raw)?;
        let destination_id = raw_msg[0];
        let command = raw_msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let password = u32::from_be_bytes([raw_msg[2], raw_msg[3], raw_msg[4], raw_msg[5]]);

        Ok(EditPasswordResponse {
            destination_id,
            command,
            password,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_echo_io_response() {
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

    #[test]
    fn decode_echo_all_keys_response() {
        let raw = vec!(255, 0, 90, 165, 0, 21, 0, 9, 1, 1, 139, 4, 210, 0, 16, 1, 0, 5, 0, 3, 4, 0, 1, 11, 0, 178, 71);
        let d = EchoResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 1);
            assert_eq!(echo.data, EchoEvent::AllKeysPressed(AllKeysPressedData {
                fifth_key_data: None,
                input_value: 1234,
                device_params: ControllerOptions {
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

    #[test]
    fn decode_echo_new_card_response() {
        let raw = vec!(255, 0, 90, 165, 0, 23, 0, 9, 1, 2, 11, 18, 221, 0, 0, 186, 139, 0, 16, 0, 138, 0, 0, 0, 0, 0, 0, 154, 127);
        let d = EchoResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 2);
            assert_eq!(echo.data, EchoEvent::NewCardPresent(NewCardPresentData {
                site_code: 4829,
                input_value: 0,
                card_code: 47755,
                id_em4001: 0,
                device_params: ControllerOptions {
                    anti_pass_back_enabled: false,
                    anti_pass_back_in: false,
                    force_open_alarm: false,
                    egress_button: true,
                    skip_pin_check: false,
                    auto_open_zone: false,
                    auto_lock_door: false,
                    time_attendance_disabled: false
                },
                from_wiegand: false,
                setting_forced_open_alarm: false
            }));
        }
    }
}