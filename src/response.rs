use crate::api_types::*;

use chrono::{DateTime, Local, TimeZone};
use enum_primitive::FromPrimitive;
use serde::{Serialize, Deserialize};
use std::ops::BitXorAssign;
use either::Either;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EchoResponse<'a> {
    pub destination_id: u8, // 0x00 == Host (PC)
    pub command: EchoCode,
    pub data: &'a [u8],
}

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

        let expected_msg_length = u16::from_be_bytes([non_header[0], non_header[1]]) as usize;
        let msg_length = non_header.len() - 2;
        if expected_msg_length != msg_length {
            eprintln!("Message length mismatch, expected: {} but got: {}", expected_msg_length, msg_length);
            return Err(ProtocolError::MessageLengthMismatch.into());
        };

        // ignore the first 2 length bytes
        let raw_msg = &non_header[2..];

        // get and test XOR and SUM values
        let sum = raw_msg.get(msg_length-1).expect("Missing sum value");
        let xor = raw_msg.get(msg_length-2).expect("Missing xor value");

        //println!("Received XOR: {:#X?}, SUM {:#X?}", xor, sum);

        let mut xor_res: u8 = 0xFF;
        for d in &raw_msg[..msg_length-2] {
            xor_res.bitxor_assign(d);
        }

        //println!("Calculated XOR: {:#X?}", xor_res);

        if xor_res != *xor {
            return Err(ProtocolError::BadXorValue.into());
        }

        let mut sum_res: u8 = 0;
        for d in &raw_msg[..msg_length-1] {
            sum_res = sum_res.wrapping_add(*d);
        }

        //println!("Calculated SUM: {:#X?}", sum_res);

        if sum_res != *sum {
            return Err(ProtocolError::BadChecksumValue.into());
        }

        // ignore the last two XOR/SUM bytes
        Ok(&raw_msg[0..msg_length-2])
    }

    fn get_data_parts(raw: &Vec<u8>, expected_command: Option<EchoCode>) -> Result<EchoResponse> {
        let msg = Self::get_message_part(raw)?;
        let destination_id = msg[0];
        let command: EchoCode = EchoCode::from_u8(msg[1]).ok_or(ProtocolError::UnknownCommandCode)?;

        if let Some(exp) = expected_command {
            if exp != command {
                return Err(ProtocolError::UnexpectedCommandCode.into())
            }
        }

        let data = &msg[2..];
        Ok(EchoResponse { destination_id, command, data })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerStatusResponse {
    pub destination_id: u8,
    pub function_code: u8,
    pub source: u8,
    pub event_type: u8,
    pub data: ControllerStatus,
}

impl Response<ControllerStatusResponse> for ControllerStatusResponse {
    fn decode(raw: &Vec<u8>) -> Result<ControllerStatusResponse> {
        let msg = Self::get_message_part(raw)?;

        if msg.len() < 5 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let destination_id = msg[0];
        let function_code  = msg[1];
        let source         = msg[2];
        let event_type     = msg[3];
        let data = ControllerStatus::decode(event_type, &msg[4..])?;

        Ok(ControllerStatusResponse {
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
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    //pub flash_size_code: ???
    pub serial: Vec<u8>,
}

impl Response<SerialNumberResponse> for SerialNumberResponse {
    fn decode(raw: &Vec<u8>) -> Result<SerialNumberResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 15 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let serial = data[3..15].to_vec();

        Ok(SerialNumberResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            source,
            serial,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDelayResponse {
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    pub main_port_door_relay_time:    u16, // 10ms
    pub weigand_port_door_relay_time: u16, // 10ms
    pub alarm_relay_time:       u16, // 10ms
    pub lift_controller_time:   u16, // 10ms
}

impl Response<RelayDelayResponse> for RelayDelayResponse {
    fn decode(raw: &Vec<u8>) -> Result<RelayDelayResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 9 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let main_port_door_relay_time    = u16::from_be_bytes([data[1], data[2]]);
        let weigand_port_door_relay_time = u16::from_be_bytes([data[3], data[4]]);
        let alarm_relay_time     = u16::from_be_bytes([data[5], data[6]]);
        let lift_controller_time = u16::from_be_bytes([data[7], data[8]]);

        Ok(RelayDelayResponse {
            destination_id: parts.destination_id,
            command: parts.command,
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
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    pub password: u32,
}

impl Response<EditPasswordResponse> for EditPasswordResponse {
    fn decode(raw: &Vec<u8>) -> Result<EditPasswordResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 5 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let password = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        Ok(EditPasswordResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            source,
            password,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerOptionsResponse {
    pub destination_id: u8,
    pub command: EchoCode,
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
    pub tag_hold_time:                u16, // 10ms
    pub main_port_door_relay_time:    u16, // 10ms
    pub weigand_port_door_relay_time: u16, // 10ms
    pub alarm_relay_time:             u16, // 10ms
    pub main_port_options:             ControllerOptions,
    pub weigand_port_options:          ControllerOptions,
    pub main_port_extended_options:    ExtendedControllerOptions,
    pub weigand_port_extended_options: ExtendedControllerOptions,
    pub main_port_door_close_time:    u8, // seconds
    pub weigand_port_door_close_time: u8, // seconds
    pub main_port_arming:    bool,
    pub weigand_port_arming: bool,
    pub access_mode: ControllerAccessMode,
    pub armed_output_pulse_width: u8, // 10 ms
    pub arming_delay: u8, // seconds
    pub alarm_delay:  u8, // seconds
    // Data43: UART2 / UART3 device
    // Data44: CommonOptions
    // Data45: DisplayOptions
    // Data46..Data51: only present for later versions
    // Data52: reserved
}

impl Response<ControllerOptionsResponse> for ControllerOptionsResponse {
    fn decode(raw: &Vec<u8>) -> Result<ControllerOptionsResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 43 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let controller_type = ControllerType::from_u8(data[1]).ok_or(ProtocolError::UnknownControllerType)?;
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
        let access_mode = ControllerAccessMode::from_u8(data[39]).ok_or(ProtocolError::UnknownControllerAccessMode)?;
        let armed_output_pulse_width = data[40];
        let arming_delay = data[41];
        let alarm_delay =  data[42];

        Ok(ControllerOptionsResponse {
            destination_id: parts.destination_id,
            command: parts.command,
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
            access_mode,
            armed_output_pulse_width,
            arming_delay,
            alarm_delay,
       })
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAndMacAddressResponse {
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    pub address_data: IpAndMacAddress,
}

impl Response<IpAndMacAddressResponse> for IpAndMacAddressResponse {
    fn decode(raw: &Vec<u8>) -> Result<IpAndMacAddressResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 32 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        // data[1] ??? what is this? documentation doesn't have it

        let address_data = IpAndMacAddress::decode(&data[2..]);

        Ok(IpAndMacAddressResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            source,
            address_data
        })
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteTCPServerParamsResponse {
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    pub remote_server_params: RemoteTCPServerParams,
}

impl Response<RemoteTCPServerParamsResponse> for RemoteTCPServerParamsResponse {
    fn decode(raw: &Vec<u8>) -> Result<RemoteTCPServerParamsResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 13 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let remote_server_params = RemoteTCPServerParams::decode(&data[1..]);

        Ok(RemoteTCPServerParamsResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            source,
            remote_server_params
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogStatusResponse {
    pub destination_id: u8,
    pub command: EchoCode,
    pub event_log_counter:  u8,
    pub queue_input_point:  u8,
    pub queue_output_point: u8,
}

impl Response<EventLogStatusResponse> for EventLogStatusResponse {
    fn decode(raw: &Vec<u8>) -> Result<EventLogStatusResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        if data.len() < 3 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        Ok(EventLogStatusResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            event_log_counter:  data[0],
            queue_input_point:  data[1],
            queue_output_point: data[2],
        })
    }
}

pub fn handle_ack_or_nack(raw: Vec<u8>) -> Result<Either<AckResponse, NackResponse>> {
    match AckResponse::decode(&raw) {
        Ok(x) => Ok(Either::Left(x)),
        Err(_) => NackResponse::decode(&raw).map(Either::Right)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckResponse {
    pub destination_id: u8,
    pub source: u8,
    // controller specific data
}

impl Response<AckResponse> for AckResponse {
    fn decode(raw: &Vec<u8>) -> Result<AckResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::CommandAcknowledged))?;
        let data = parts.data;

        if data.len() < 1 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        
        Ok(AckResponse {
            destination_id: parts.destination_id,
            source
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NackResponse {
    pub destination_id: u8,
    pub source: u8,
    // controller specific data
}

impl Response<NackResponse> for NackResponse {
    fn decode(raw: &Vec<u8>) -> Result<NackResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::CommandUnacknowledged))?;
        let data = parts.data;

        if data.len() < 1 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];

        Ok(NackResponse {
            destination_id: parts.destination_id,
            source
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogResponse {
    pub destination_id: u8,
    pub function_code: EventFunctionCode,
    pub source: u8,
    pub timestamp: DateTime<Local>,
    pub port_number: PortNumber,
    pub user_address_or_tag_id: u16,
    pub tag_id_for_normal_access: (u16, u16),
    // Sub Code
    // Sub Func. // function code AlarmEvent
    // Ext Code
    // User level
    pub door_number: u8,
    pub sor_deduction_amount: u16,
    pub sor_balance: u16,
    pub user_inputted_code: Option<u32>, // only available for function code InvalidUserPIN
}

impl Response<EventLogResponse> for EventLogResponse {
    fn decode(raw: &Vec<u8>) -> Result<EventLogResponse> {
        let msg = Self::get_message_part(raw)?;

        let destination_id = msg[0];
        let function_code = EventFunctionCode::from_u8(msg[1]).ok_or(ProtocolError::UnknownEventFunctionCode)?;
        let data = &msg[2..];

        if data.len() < 25 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];

        let year = 2000 + data[7] as i32;
        let month = data[6] as u32;
        let day = data[5] as u32;
        let hour = data[3] as u32;
        let minute = data[2] as u32;
        let second = data[1] as u32;
        let timestamp = Local.ymd(year, month, day).and_hms(hour, minute, second);

        let port_number = PortNumber::from_u8(data[8]).ok_or(ProtocolError::UnknownPortNumber)?;

        let user_address_or_tag_id = u16::from_be_bytes([data[9], data[10]]);
        let tag_id_for_normal_access = (u16::from_be_bytes([data[15], data[16]]), u16::from_be_bytes([data[19], data[20]]));

        let door_number = data[17];

        let sor_deduction_amount = u16::from_be_bytes([data[21], data[22]]);
        let sor_balance          = u16::from_be_bytes([data[23], data[24]]);

        let user_inputted_code = if function_code == EventFunctionCode::InvalidUserPIN {
            Some(u32::from_be_bytes([data[25], data[26], data[27], data[28]]))
        } else { None };

        Ok(EventLogResponse {
            destination_id,
            function_code,
            source,
            timestamp,
            port_number,
            user_address_or_tag_id,
            tag_id_for_normal_access,
            door_number,
            sor_deduction_amount,
            sor_balance,
            user_inputted_code,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserParametersResponse {
    pub destination_id: u8,
    pub command: EchoCode,
    pub source: u8,
    pub user_parameters: UserParameters,
}

impl Response<UserParametersResponse> for UserParametersResponse {
    fn decode(raw: &Vec<u8>) -> Result<UserParametersResponse> {
        let parts = Self::get_data_parts(raw, Some(EchoCode::RequestedData))?;
        let data = parts.data;

        //println!("User data: {:?}, len: {}", data, data.len());

        if data.len() < 25 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let source = data[0];
        let user_parameters = UserParameters::decode(&data[1..25])?;

        Ok(UserParametersResponse {
            destination_id: parts.destination_id,
            command: parts.command,
            source,
            user_parameters,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_status_io_response() {
        let raw = vec!(255, 0, 90, 165, 0, 10, 0, 9, 1, 0, 1, 0, 16, 0, 230, 1);
        let d = ControllerStatusResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 0);
            assert_eq!(echo.data, ControllerStatus::IoStatus(IoStatusData {
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
    fn decode_status_all_keys_response() {
        let raw = vec!(255, 0, 90, 165, 0, 21, 0, 9, 1, 1, 139, 4, 210, 0, 16, 1, 0, 5, 0, 3, 4, 0, 1, 11, 0, 178, 71);
        let d = ControllerStatusResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 1);
            assert_eq!(echo.data, ControllerStatus::AllKeysPressed(AllKeysPressedData {
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
    fn decode_status_new_card_response() {
        let raw = vec!(255, 0, 90, 165, 0, 23, 0, 9, 1, 2, 11, 18, 221, 0, 0, 186, 139, 0, 16, 0, 138, 0, 0, 0, 0, 0, 0, 154, 127);
        let d = ControllerStatusResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(echo) = d {
            assert_eq!(echo.destination_id, 0);
            assert_eq!(echo.function_code, 9);
            assert_eq!(echo.source, 1);
            assert_eq!(echo.event_type, 2);
            assert_eq!(echo.data, ControllerStatus::NewCardPresent(NewCardPresentData {
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

    #[test]
    fn decode_controller_options_response() {
        let raw = vec!(255, 0, 90, 165, 0, 57, 0, 3, 1, 193, 1, 2, 0, 1, 226, 64, 0, 0, 0, 0, 0, 0, 0, 0, 4, 210, 0, 0, 0, 0, 1, 4, 0, 100, 2, 188, 2, 188, 5, 220, 48, 16, 1, 17, 15, 15, 0, 8, 0, 1, 1, 65, 24, 9, 5, 0, 0, 0, 3, 3, 0, 159, 13);
        let d = ControllerOptionsResponse::decode(&raw);
        assert!(d.is_ok());
        if let Ok(options) = d {
            assert_eq!(options.destination_id, 0);
            assert_eq!(options.command, EchoCode::RequestedData);
            assert_eq!(options.source, 1);
            assert_eq!(options.controller_type, ControllerType::AR725Ev2);
            assert_eq!(options.main_port_door_number, 1);
            assert_eq!(options.weigand_port_door_number, 2);
            assert_eq!(options.edit_password, 123456);
            assert_eq!(options.master_user_range_start, 0);
            assert_eq!(options.master_user_range_end, 0);
            assert_eq!(options.general_password, 1234);
            assert_eq!(options.duress_code, 0);
            assert_eq!(options.tag_hold_time, 100);
            assert_eq!(options.main_port_door_relay_time, 700);
            assert_eq!(options.weigand_port_door_relay_time, 700);
            assert_eq!(options.alarm_relay_time, 1500);
            assert_eq!(options.main_port_options,    ControllerOptions { anti_pass_back_enabled: false, anti_pass_back_in: false, force_open_alarm: true,  egress_button: true, skip_pin_check: false, auto_open_zone: false, auto_lock_door: false, time_attendance_disabled: false });
            assert_eq!(options.weigand_port_options, ControllerOptions { anti_pass_back_enabled: false, anti_pass_back_in: false, force_open_alarm: false, egress_button: true, skip_pin_check: false, auto_open_zone: false, auto_lock_door: false, time_attendance_disabled: false });
            assert_eq!(options.main_port_extended_options,    ExtendedControllerOptions { door_relay_active_in_auto_open_time_zone: false, stop_alarm_at_door_closed: false, free_tag_access_mode: false, use_main_door_relay_for_weigand_port: false, auto_disarmed_time_zone: false, key_pad_inhibited: false, egress_button_sound: true });
            assert_eq!(options.weigand_port_extended_options, ExtendedControllerOptions { door_relay_active_in_auto_open_time_zone: false, stop_alarm_at_door_closed: false, free_tag_access_mode: false, use_main_door_relay_for_weigand_port: true,  auto_disarmed_time_zone: false, key_pad_inhibited: false, egress_button_sound: true });
            assert_eq!(options.main_port_door_close_time, 15);
            assert_eq!(options.weigand_port_door_close_time, 15);
            assert_eq!(options.main_port_arming, false);
            assert_eq!(options.weigand_port_arming, false);
            assert_eq!(options.access_mode, ControllerAccessMode::PinOnly);
            assert_eq!(options.armed_output_pulse_width, 0);
            assert_eq!(options.arming_delay, 1);
            assert_eq!(options.alarm_delay, 1);
        }
    }
}