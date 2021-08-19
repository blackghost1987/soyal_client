use serde::{Serialize, Deserialize};

use crate::api_types::*;
use std::convert::TryFrom;

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
        let msg = Self::get_message_part(raw)?;
        let msg_length = msg.len();

        let destination_id = msg[0];
        let function_code  = msg[1];
        let source         = msg[2];
        let event_type     = msg[3];

        let raw_data = &msg[4..msg_length];
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
        let msg = Self::get_message_part(raw)?;

        let destination_id = msg[0];
        let command = msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let source = msg[2];
        let serial = msg[5..17].to_vec();

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
    pub main_port_door_relay_time:    u16, // 10ms
    pub weigand_port_door_relay_time: u16, // 10ms
    pub alarm_relay_time:       u16, // 10ms
    pub lift_controller_time:   u16, // 10ms
}

impl Response<RelayDelayResponse> for RelayDelayResponse {
    fn decode(raw: &Vec<u8>) -> Result<RelayDelayResponse> {
        let msg = Self::get_message_part(raw)?;

        let destination_id = msg[0];
        let command = msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let source = msg[2];
        let main_port_door_relay_time    = u16::from_be_bytes([msg[3], msg[4]]);
        let weigand_port_door_relay_time = u16::from_be_bytes([msg[5], msg[6]]);
        let alarm_relay_time     = u16::from_be_bytes([msg[7], msg[8]]);
        let lift_controller_time = u16::from_be_bytes([msg[9], msg[10]]);

        Ok(RelayDelayResponse {
            destination_id,
            command,
            source,
            main_port_door_relay_time,
            weigand_port_door_relay_time,
            alarm_relay_time,
            lift_controller_time,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPasswordResponse {
    pub destination_id: u8, // 0x00 Host
    pub command: u8,
    // FIXME maybe there's a source param here as well? are there dangling data?
    pub password: u32,
}

impl Response<EditPasswordResponse> for EditPasswordResponse {
    fn decode(raw: &Vec<u8>) -> Result<EditPasswordResponse> {
        let msg = Self::get_message_part(raw)?;
        let destination_id = msg[0];
        let command = msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let password = u32::from_be_bytes([msg[2], msg[3], msg[4], msg[5]]);

        Ok(EditPasswordResponse {
            destination_id,
            command,
            password,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControllerType {
    AR881E    = 0xC0,
    AR725Ev2  = 0xC1,
    AR829Ev5  = 0xC2,
    AR821EFv5 = 0xC3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessMode {
    PinOnly,           // Mode 8: 4 digit PIN
    UserAddressAndPin, // Mode 4: 5 digit address + 4 digit PIN
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerOptionsResponse {
    pub destination_id: u8, // 0x00 Host
    pub command: u8,
    pub source: u8,
    pub controller_type: ControllerType,
    pub main_port_door_number:    u8,
    pub weigand_port_door_number: u8,
    pub edit_password:           u32,
    pub master_user_range_start: u32,
    pub master_user_range_end:   u32,
    pub general_password:        u16,
    pub duress_code:             u16,
    //pub connected_reader_bitmask: ??? // AR721Ev2 only
    tag_hold_time:                u16, // 10ms
    main_port_door_relay_time:    u16, // 10ms
    weigand_port_door_relay_time: u16, // 10ms
    alarm_relay_time:             u16, // 10ms
    main_port_options:             ControllerOptions,
    weigand_port_options:          ControllerOptions,
    main_port_extended_options:    ExtendedControllerOptions,
    weigand_port_extended_options: ExtendedControllerOptions,
    main_port_door_close_time:    u8, // seconds
    weigand_port_door_close_time: u8, // seconds
    main_port_arming:    bool,
    weigand_port_arming: bool,
    // TODO access_mode: AccessMode,
    armed_output_pulse_width: u8, // 10 ms
    arming_delay: u8, // seconds
    alarm_delay:  u8, // seconds
    // Data43: UART2 / UART3
    // Data44: CommonOptions
    // Data45: DisplayOptions
    // Data46..Data52 - only present for later versions
}

impl Response<ControllerOptionsResponse> for ControllerOptionsResponse {
    fn decode(raw: &Vec<u8>) -> Result<ControllerOptionsResponse> {
        let msg = Self::get_message_part(raw)?;
        let destination_id = msg[0];
        let command = msg[1];
        assert_eq!(command, 3, "Getter Response command should be 0x03");
        let data = &msg[2..];

        let source = data[0];
        // FIXME how to do this?
        //let controller_type = ControllerType::try_from(data[1])?;
        let controller_type = ControllerType::AR725Ev2;
        let main_port_door_number    = data[2];
        let weigand_port_door_number = data[3];
        let edit_password = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let master_user_range_start = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let master_user_range_end   = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let general_password        = u16::from_be_bytes([data[16], data[17]]);
        let duress_code             = u16::from_be_bytes([data[18], data[19]]);
        // Data 20-21 reserved
        // Data 22-23 connected_reader_bitmask - unimplemented
        let tag_hold_time = u16::from_be_bytes([data[24], data[25]]);
        let main_port_door_relay_time    = u16::from_be_bytes([data[26], data[27]]);
        let weigand_port_door_relay_time = u16::from_be_bytes([data[28], data[29]]);
        let alarm_relay_time = u16::from_be_bytes([data[30], data[31]]);
        let main_port_options    = ControllerOptions::decode(data[32]);
        let weigand_port_options = ControllerOptions::decode(data[33]);
        let main_port_extended_options    = ExtendedControllerOptions::decode(data[34]);
        let weigand_port_extended_options = ExtendedControllerOptions::decode(data[35]);
        let main_port_door_close_time    = data[36];
        let weigand_port_door_close_time = data[37];
        let main_port_arming    = data[38] & 0b00000001 != 0;
        let weigand_port_arming = data[38] & 0b00000010 != 0;
        // TODO let access_mode = AccessMode::decode(data[39)
        let armed_output_pulse_width = data[40];
        let arming_delay = data[41];
        let alarm_delay =  data[42];

        Ok(ControllerOptionsResponse {
            destination_id,
            command,
            source,
            controller_type,
            main_port_door_number,
            weigand_port_door_number,
            edit_password,
            master_user_range_start,
            master_user_range_end,
            general_password,
            duress_code,
            tag_hold_time,
            main_port_door_relay_time,
            weigand_port_door_relay_time,
            alarm_relay_time,
            main_port_options,
            weigand_port_options,
            main_port_extended_options,
            weigand_port_extended_options,
            main_port_door_close_time,
            weigand_port_door_close_time,
            main_port_arming,
            weigand_port_arming,
            armed_output_pulse_width,
            arming_delay,
            alarm_delay,
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