use crate::enums::*;
use crate::common::*;

use std::fmt::Debug;
use std::net::Ipv4Addr;

use semver::Version;
use serde::{Serialize, Deserialize};
use chrono::{NaiveDate, Datelike, DateTime, Local, TimeZone};
use macaddr::MacAddr6;
use enum_primitive::FromPrimitive;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SlaveFlags {
    pub slave_mode_enabled: bool,
    pub keyboard_locked: bool,
    pub lcd_update_locked: bool,
    pub inhibit_125khz_tags: bool,
    pub inhibit_13_56mhz_tags: bool,
    pub fire_alarm_input_enabled: bool,
    pub alarm_on_invalid_tag: bool,
}

impl SlaveFlags {
    pub fn decode(data: u8) -> SlaveFlags {
        SlaveFlags {
            slave_mode_enabled:       data & 0b10000000 != 0,
            keyboard_locked:          data & 0b01000000 != 0,
            lcd_update_locked:        data & 0b00100000 != 0,
            inhibit_125khz_tags:      data & 0b00010000 != 0,
            inhibit_13_56mhz_tags:    data & 0b00001000 != 0,
            fire_alarm_input_enabled: data & 0b00000100 != 0,
            alarm_on_invalid_tag:     data & 0b00000010 != 0,
            // bit 0 reserved
        }
    }

    pub fn encode(&self) -> u8 {
        let mut data = 0b00000000;
        if self.slave_mode_enabled       { data += 0b10000000; }
        if self.keyboard_locked          { data += 0b01000000; }
        if self.lcd_update_locked        { data += 0b00100000; }
        if self.inhibit_125khz_tags      { data += 0b00010000; }
        if self.inhibit_13_56mhz_tags    { data += 0b00001000; }
        if self.fire_alarm_input_enabled { data += 0b00000100; }
        if self.alarm_on_invalid_tag     { data += 0b00000010; }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UARTData {
    pub uart2_type: UART2Type,
    pub uart2_baud_rate: UartBaudRate,
    pub uart3_type: UART3Type,
}

impl UARTData {
    pub fn decode(data: u8) -> Result<UARTData> {
        let uart2_type = match data & 0b00000011 {
            0b00000000 => Ok(UART2Type::Fingerprint3DO1500),
            0b00000001 => match data & 0b00001111 {
                0b00000001 => Ok(UART2Type::LiftController),
                0b00000101 => Ok(UART2Type::SlavePortAR716E),
                0b00001001 => Ok(UART2Type::VoiceModuleOrReader),
                0b00001101 => Ok(UART2Type::SerialPrinter),
                _ => Err(ProtocolError::UnknownUartType) // should not happen
            },
            0b00000010 => Err(ProtocolError::UnknownUartType), // reserved
            0b00000011 => Ok(UART2Type::Fingerprint9000),
            _ => Err(ProtocolError::UnknownUartType) // should not happen
        }?;

        let baud_rate_bits = data & 0b11000000;
        let uart2_baud_rate = UartBaudRate::from_u8(baud_rate_bits).ok_or(ProtocolError::UnknownUartBaudRate)?;
        let uart3_type = UART3Type::from_u8(data & 0b00110000).ok_or(ProtocolError::UnknownUartType)?;

        Ok(UARTData {
            uart2_type,
            uart2_baud_rate,
            uart3_type,
        })
    }

    pub fn encode(&self) -> u8 {
        let mut data = match self.uart2_type {
            UART2Type::Fingerprint9000 =>     0b00000011,
            UART2Type::Fingerprint3DO1500 =>  0b00000000,
            UART2Type::LiftController =>      0b00000001,
            UART2Type::SlavePortAR716E =>     0b00000101,
            UART2Type::VoiceModuleOrReader => 0b00001001,
            UART2Type::SerialPrinter =>       0b00001101,
        };

        data += self.uart2_baud_rate as u8;
        data += self.uart3_type as u8;

        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommonOptions {
    pub enable_black_table_check: bool,
    pub show_local_language_manual: bool,
    pub rs485_port_function: RS485PortFunction,
    pub wiegand_signal_output_disable: bool,
    pub lcd_display_date_in_dd_mm: bool,
    pub auto_reset_anti_pass_back: bool,
    pub trigger_alarm_on_expired_user: bool,
}

impl CommonOptions {
    pub fn decode(data: u8) -> CommonOptions {
        let rs485_port_function = RS485PortFunction::from_u8(data & 0b00110000).expect("RS485 port decoding should not fail");

        CommonOptions {
            enable_black_table_check:      data & 0b10000000 != 0,
            show_local_language_manual:    data & 0b01000000 != 0,
            rs485_port_function,
            wiegand_signal_output_disable: data & 0b00001000 != 0,
            lcd_display_date_in_dd_mm:     data & 0b00000100 != 0,
            auto_reset_anti_pass_back:     data & 0b00000010 != 0,
            trigger_alarm_on_expired_user: data & 0b00000001 != 0,
        }
    }

    pub fn encode(&self) -> u8 {
        let mut data = 0b00000000;
        if self.enable_black_table_check      { data += 0b10000000; }
        if self.show_local_language_manual    { data += 0b01000000; }
        data += self.rs485_port_function as u8;
        if self.wiegand_signal_output_disable { data += 0b00001000; }
        if self.lcd_display_date_in_dd_mm     { data += 0b00000100; }
        if self.auto_reset_anti_pass_back     { data += 0b00000010; }
        if self.trigger_alarm_on_expired_user { data += 0b00000001; }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayOptions {
    pub fingerprint_enroll_duplication_check: bool,
    pub auto_duty_code_shift_table_enabled: bool,
    pub show_wiegand_port_message_on_main_lcd: bool,
    pub uid_display_format: UIDDisplayFormat,
}

impl DisplayOptions {
    pub fn decode(data: u8) -> DisplayOptions {
        let uid_display_format = UIDDisplayFormat::from_u8(data & 0b00000111).expect("UID display format decoding should not fail");

        DisplayOptions {
            fingerprint_enroll_duplication_check:  data & 0b00100000 != 0,
            auto_duty_code_shift_table_enabled:    data & 0b00010000 != 0,
            show_wiegand_port_message_on_main_lcd: data & 0b00001000 != 0,
            uid_display_format,
        }
    }

    pub fn encode(&self) -> u8 {
        let mut data = 0b00000000;
        if self.fingerprint_enroll_duplication_check  { data += 0b00100000; }
        if self.auto_duty_code_shift_table_enabled    { data += 0b00010000; }
        if self.show_wiegand_port_message_on_main_lcd { data += 0b00001000; }
        data += self.uid_display_format as u8;
        data
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerOptions {
    pub main_port_door_number:    u8,
    pub wiegand_port_door_number: u8,
    pub edit_password:           u32,
    pub master_user_range_start: u32,
    pub master_user_range_end:   u32,
    pub general_password:        u16,
    pub duress_code:             u16,
    // Data20-21: reserved
    pub connected_reader_bitmask:     u16, // AR721Ev2 only
    pub tag_hold_time:                u16, // 10ms
    pub main_port_door_relay_time:    u16, // 10ms
    pub wiegand_port_door_relay_time: u16, // 10ms
    pub alarm_relay_time:             u16, // 10ms
    pub main_port_options:             ControllerPortOptions,
    pub wiegand_port_options:          ControllerPortOptions,
    pub main_port_extended_options:    ExtendedControllerOptions,
    pub wiegand_port_extended_options: ExtendedControllerOptions,
    pub main_port_door_close_time:    u8, // seconds
    pub wiegand_port_door_close_time: u8, // seconds
    pub main_port_arming:    bool,
    pub wiegand_port_arming: bool,
    pub access_mode: ControllerAccessMode,
    pub armed_output_pulse_width: u8, // 10 ms
    pub arming_delay: u8, // seconds
    pub alarm_delay:  u8, // seconds
    pub uart_data: UARTData,
    pub common_options: CommonOptions,
    pub display_options: DisplayOptions,
    pub keyboard_lock_error_times: Option<u8>, // version 2.5 and later
    pub host_port_baud: Option<HostBaudRate>,  // version 2.5 and later
    pub slave_flags: Option<SlaveFlags>,       // version 2.5 and later
    pub operation_mode: Option<OperationMode>, // version 2.9 and later
    pub main_port_egress_beeps: Option<u8>,    // version 3.3 and later
    pub wiegand_port_egress_beeps: Option<u8>, // version 3.3 and later
    // Data52: reserved
}

impl ControllerOptions {
    pub fn decode(data: &[u8], version: Version) -> Result<ControllerOptions> {
        let mut expected_length = 46;
        if version >= Version::new(2, 5, 0) { expected_length = 49; }
        if version >= Version::new(2, 9, 0) { expected_length = 50; }
        if version >= Version::new(3, 3, 0) { expected_length = 52; }
        if data.len() < expected_length {
            return Err(ProtocolError::NotEnoughData.into());
        }

        let main_port_door_number    = data[2];
        let wiegand_port_door_number = data[3];
        let edit_password = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let master_user_range_start = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let master_user_range_end   = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let general_password        = u16::from_be_bytes([data[16], data[17]]);
        let duress_code             = u16::from_be_bytes([data[18], data[19]]);
        // Data 20-21 reserved
        let connected_reader_bitmask = u16::from_be_bytes([data[22], data[23]]);
        let tag_hold_time = u16::from_be_bytes([data[24], data[25]]);
        let main_port_door_relay_time    = u16::from_be_bytes([data[26], data[27]]);
        let wiegand_port_door_relay_time = u16::from_be_bytes([data[28], data[29]]);
        let alarm_relay_time = u16::from_be_bytes([data[30], data[31]]);
        let main_port_options    = ControllerPortOptions::decode(data[32]);
        let wiegand_port_options = ControllerPortOptions::decode(data[33]);
        let main_port_extended_options    = ExtendedControllerOptions::decode(data[34]);
        let wiegand_port_extended_options = ExtendedControllerOptions::decode(data[35]);
        let main_port_door_close_time    = data[36];
        let wiegand_port_door_close_time = data[37];
        let main_port_arming    = data[38] & 0b00000001 != 0;
        let wiegand_port_arming = data[38] & 0b00000010 != 0;
        let access_mode = ControllerAccessMode::from_u8(data[39]).ok_or(ProtocolError::UnknownControllerAccessMode)?;
        let armed_output_pulse_width = data[40];
        let arming_delay = data[41];
        let alarm_delay =  data[42];
        let uart_data = UARTData::decode(data[43])?;
        let common_options = CommonOptions::decode(data[44]);
        let display_options = DisplayOptions::decode(data[45]);

        // TODO use then_some when bool_to_option is stabilized https://github.com/rust-lang/rust/issues/64260
        let keyboard_lock_error_times = (version >= Version::new(2, 5, 0)).then(|| data[46]);

        let host_port_baud =          if version >= Version::new(2, 5, 0) {
            Some(HostBaudRate::from_u8(data[47]).ok_or(ProtocolError::UnknownHostBaudRate)?)
        } else { None };

        let slave_flags =               (version >= Version::new(2, 5, 0)).then(|| SlaveFlags::decode(data[48]));

        let operation_mode =          if version >= Version::new(2, 9, 0) {
            Some(OperationMode::from_u8(data[49]).ok_or(ProtocolError::UnknownOperationMode)?)
        } else { None };

        let main_port_egress_beeps =    (version >= Version::new(3, 3, 0)).then(|| data[50]);
        let wiegand_port_egress_beeps = (version >= Version::new(3, 3, 0)).then(|| data[51]);

        Ok(ControllerOptions {
            main_port_door_number,
            wiegand_port_door_number,
            edit_password,
            master_user_range_start,
            master_user_range_end,
            general_password,
            duress_code,
            connected_reader_bitmask,
            tag_hold_time,
            main_port_door_relay_time,
            wiegand_port_door_relay_time,
            alarm_relay_time,
            main_port_options,
            wiegand_port_options,
            main_port_extended_options,
            wiegand_port_extended_options,
            main_port_door_close_time,
            wiegand_port_door_close_time,
            main_port_arming,
            wiegand_port_arming,
            access_mode,
            armed_output_pulse_width,
            arming_delay,
            alarm_delay,
            uart_data,
            common_options,
            display_options,
            keyboard_lock_error_times,
            host_port_baud,
            slave_flags,
            operation_mode,
            main_port_egress_beeps,
            wiegand_port_egress_beeps,
        })
    }

    pub fn encode(&self, version: Version) -> Result<Vec<u8>> {
        let mut data = vec![
            self.main_port_door_number,
            self.wiegand_port_door_number
        ];
        data.extend_from_slice(&self.edit_password.to_be_bytes());
        data.extend_from_slice(&self.master_user_range_start.to_be_bytes());
        data.extend_from_slice(&self.master_user_range_end.to_be_bytes());
        data.extend_from_slice(&self.general_password.to_be_bytes());
        data.extend_from_slice(&self.duress_code.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00]); // reserved
        data.extend_from_slice(&self.connected_reader_bitmask.to_be_bytes()); // doc error, bytes22-23 duplicated? must be zero?
        data.extend_from_slice(&self.tag_hold_time.to_be_bytes());
        data.extend_from_slice(&self.main_port_door_relay_time.to_be_bytes());
        data.extend_from_slice(&self.wiegand_port_door_relay_time.to_be_bytes());
        data.extend_from_slice(&self.alarm_relay_time.to_be_bytes());
        data.push(self.main_port_options.encode());
        data.push(self.wiegand_port_options.encode());
        data.push(self.main_port_extended_options.encode(true));
        data.push(self.wiegand_port_extended_options.encode(false));
        data.push(self.main_port_door_close_time);
        data.push(self.wiegand_port_door_close_time);

        let mut arming_status = 0x00000000;
        if self.main_port_arming { arming_status += 0b00000001; }
        if self.wiegand_port_arming { arming_status += 0b00000010; }
        data.push(arming_status);

        data.push(self.access_mode as u8);
        data.push(self.armed_output_pulse_width);
        data.push(self.arming_delay);
        data.push(self.alarm_delay);
        data.push(self.uart_data.encode());
        data.push(self.common_options.encode());
        data.push(self.display_options.encode());

        if version >= Version::new(2, 5, 0) {
            let k = self.keyboard_lock_error_times.ok_or(ProtocolError::VersionMismatch)?;
            let h = self.host_port_baud.ok_or(ProtocolError::VersionMismatch)? as u8;
            let s = self.slave_flags.ok_or(ProtocolError::VersionMismatch)?.encode();
            data.push(k);
            data.push(h);
            data.push(s);
        }

        if version >= Version::new(2, 9, 0) {
            let o = self.operation_mode.ok_or(ProtocolError::VersionMismatch)?;
            data.push(o as u8);
        }

        if version >= Version::new(3, 3, 0) {
            let mb = self.main_port_egress_beeps.ok_or(ProtocolError::VersionMismatch)?;
            let wb = self.wiegand_port_egress_beeps.ok_or(ProtocolError::VersionMismatch)?;
            data.push(mb);
            data.push(wb);
        }

        data.push(0x00); // Data52: reserved

        Ok(data)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerPortOptions {
    pub anti_pass_back_enabled: bool,
    pub anti_pass_back_in: bool,
    pub force_open_alarm: bool,
    pub egress_button: bool,
    pub skip_pin_check: bool,
    pub auto_open_zone: bool,
    pub auto_lock_door: bool,
    pub time_attendance_disabled: bool,
}

impl ControllerPortOptions {
    pub fn decode(data: u8) -> ControllerPortOptions {
        ControllerPortOptions {
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

    pub fn encode(&self) -> u8 {
        let mut data = 0b00000000;
        if self.anti_pass_back_enabled   { data += 0b10000000; }
        if self.anti_pass_back_in        { data += 0b01000000; }
        if self.force_open_alarm         { data += 0b00100000; }
        if self.egress_button            { data += 0b00010000; }
        if self.skip_pin_check           { data += 0b00001000; }
        if self.auto_open_zone           { data += 0b00000100; }
        if self.auto_lock_door           { data += 0b00000010; }
        if self.time_attendance_disabled { data += 0b00000001; }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtendedControllerOptions {
    pub door_relay_active_in_auto_open_time_zone: bool,
    pub stop_alarm_at_door_closed: bool,
    pub free_tag_access_mode: bool,
    pub use_main_door_relay_for_wiegand_port: bool,
    pub auto_disarmed_time_zone: bool,
    pub key_pad_inhibited: bool,
    pub fingerprint_only_enabled: bool,
    pub egress_button_sound: bool,
}

impl ExtendedControllerOptions {
    pub fn decode(data: u8) -> ExtendedControllerOptions {
        ExtendedControllerOptions {
            door_relay_active_in_auto_open_time_zone: data & 0b10000000 != 0,
            stop_alarm_at_door_closed:                data & 0b01000000 != 0,
            free_tag_access_mode:                     data & 0b00100000 != 0,
            use_main_door_relay_for_wiegand_port:     data & 0b00010000 != 0, // only present for wiegand port
            auto_disarmed_time_zone:                  data & 0b00001000 != 0,
            key_pad_inhibited:                        data & 0b00000100 != 0,
            fingerprint_only_enabled:                 data & 0b00000010 != 0, // only present for main port
            egress_button_sound:                      data & 0b00000001 != 0,
        }
    }

    pub fn encode(&self, main_port: bool) -> u8 {
        let mut data = 0b00000000;
        if self.door_relay_active_in_auto_open_time_zone { data += 0b10000000; }
        if self.stop_alarm_at_door_closed                { data += 0b01000000; }
        if self.free_tag_access_mode                     { data += 0b00100000; }
        if !main_port && self.use_main_door_relay_for_wiegand_port { data += 0b00010000; }
        if self.auto_disarmed_time_zone                  { data += 0b00001000; }
        if self.key_pad_inhibited                        { data += 0b00000100; }
        if main_port && self.fingerprint_only_enabled    { data += 0b00000010; }
        if self.egress_button_sound                      { data += 0b00000001; }
        data
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DIPortStatus {
    main_egress_active: bool,
    main_door_sensor_active: bool,
    wiegand_egress_active: bool,
    wiegand_door_sensor_active: bool,
}

impl DIPortStatus {
    pub fn decode(data: u8) -> DIPortStatus {
        // Note: Active == 0 !!!
        DIPortStatus {
            main_egress_active:          data & 0b00000001 == 0,
            main_door_sensor_active:     data & 0b00000010 == 0,
            wiegand_egress_active:       data & 0b00000100 == 0,
            wiegand_door_sensor_active:  data & 0b00001000 == 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayPortStatus {
    main_door_relay_active: bool,
    wiegand_door_relay_active: bool,
    alarm_relay_active: bool,
}

impl RelayPortStatus {
    pub fn decode(data: u8) -> RelayPortStatus {
        // Note: Active == 0 !!!
        RelayPortStatus {
            main_door_relay_active:    data & 0b00000001 == 0,
            wiegand_door_relay_active: data & 0b00010000 == 0,
            alarm_relay_active:        data & 0b10000000 == 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IoStatusData {
    pub status_data: StatusData,
    pub alarm_type: Option<AlarmType>,
    pub controller_options: ControllerPortOptions,
}

impl IoStatusData {
    pub fn decode(data: &[u8]) -> Result<IoStatusData> {
        let status_data = StatusData::decode(data[0]);
        let alarm_type = match status_data.alarm_output {
            true => Some(AlarmType::decode(data[1])),
            false => None,
        };
        let controller_options = ControllerPortOptions::decode(data[2]);
        // data[3] RFU

        Ok(IoStatusData {
            status_data,
            alarm_type,
            controller_options,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllKeysPressedData {
    pub fifth_key_data: Option<u8>,
    pub input_value: u16,
    pub device_params: ControllerPortOptions,
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
        let device_params = ControllerPortOptions::decode(data[4]);

        Ok(AllKeysPressedData {
            input_value,
            fifth_key_data,
            device_params
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewCardPresentData {
    //time_and_attendance: TimeAndAttendance, // TODO implement
    //exit_input: ExitInput, // TODO implement
    pub site_code: u16,
    pub input_value: u16, // if there was no input before flashing card this shows the previous value
    pub card_code: u16,
    pub id_em4001: u8,
    pub device_params: ControllerPortOptions,
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

        let device_params = ControllerPortOptions::decode(data[8]);

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeypadEventData {
    pub key_counter: u8,
    pub key_data: Vec<u8>,
}

impl KeypadEventData {
    pub fn decode(data: &[u8]) -> Result<KeypadEventData> {
        if data.len() < 3 {
            return Err(ProtocolError::NotEnoughData.into());
        }
        let key_counter = data[1];
        let key_data = data[2..].to_vec();

        Ok(KeypadEventData {
            key_counter,
            key_data
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserAccessTimeZone {
    pub wiegand_port_same_time_zone: bool,
    pub user_time_zone: u8, // Zero for free zone control, maximum is 63
}

impl UserAccessTimeZone {
    pub fn decode(data: u8) -> UserAccessTimeZone {
        UserAccessTimeZone {
            wiegand_port_same_time_zone: data & 0b10000000 != 0,
            user_time_zone: data & 0b00111111,
        }
    }

    pub fn encode(&self) -> u8 {
        assert!(self.user_time_zone < 63, "maximum time zone is 63!");
        let mut data = self.user_time_zone;
        if self.wiegand_port_same_time_zone {
            data += 0b1000000;
        }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserParameters {
    pub tag_id: TagId64,
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

        let tag_id = TagId64::decode(&data[0..8])?;

        if tag_id == TagId64::USER_NOT_FOUND {
            return Err(ProtocolError::UserNotFound.into());
        }

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
            tag_id,
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

        data.extend_from_slice(&self.tag_id.encode());

        data.extend_from_slice(&self.pin_code.to_be_bytes());
        data.push(self.mode.encode());
        data.push(self.zone.encode());
        data.extend_from_slice(&self.available_doors_bitmap.to_be_bytes());

        let year = self.last_allowed_date.year() - 2000;
        println!("year: {:?}", year);
        assert!(year >= 0, "year minimum is 2000");
        assert!(year <= 255, "year maximum is 2255");
        data.push(year as u8);
        data.push(self.last_allowed_date.month() as u8);
        data.push(self.last_allowed_date.day() as u8);

        data.push(self.level);
        let option_byte = if self.enable_anti_pass_back_check { 0b1000000 } else { 0b0000000 };
        data.push(option_byte);

        // reserved bytes
        data.extend_from_slice(&[0x00, 0x00, 0x00]);

        assert_eq!(data.len(), 24, "Bad user data length");

        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteTCPServerParams {
    pub first_remote_address: Ipv4Addr,
    pub first_remote_port: u16,
    pub second_remote_address: Ipv4Addr,
    pub second_remote_port: u16,
}

impl RemoteTCPServerParams {
    pub fn decode(data: &[u8]) -> RemoteTCPServerParams {
        let first_remote_address  = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let first_remote_port     = u16::from_be_bytes([data[4], data[5]]);
        let second_remote_address = Ipv4Addr::new(data[6], data[7], data[8], data[9]);
        let second_remote_port    = u16::from_be_bytes([data[10], data[11]]);

        RemoteTCPServerParams {
            first_remote_address,
            first_remote_port,
            second_remote_address,
            second_remote_port,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::new();
        let first_addr:  u32 = self.first_remote_address.into();
        let second_addr: u32 = self.second_remote_address.into();

        data.extend_from_slice(&first_addr.to_be_bytes());
        data.extend_from_slice(&self.first_remote_port.to_be_bytes());
        data.extend_from_slice(&second_addr.to_be_bytes());
        data.extend_from_slice(&self.second_remote_port.to_be_bytes());

        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpAndMacAddress {
    pub mac_address: MacAddr6,
    pub ip_address:  Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub gateway_address: Ipv4Addr,
    pub tcp_port: u16,
    pub dns_primary:   Ipv4Addr,
    pub dns_secondary: Ipv4Addr,
    pub http_server_port: u16,
}

impl IpAndMacAddress {
    pub fn decode(data: &[u8]) -> IpAndMacAddress {
        let mac_address      = MacAddr6::new(data[0], data[1], data[2], data[3], data[4], data[5]);
        let ip_address       = Ipv4Addr::new(data[6], data[7], data[8], data[9]);
        let subnet_mask      = Ipv4Addr::new(data[10], data[11], data[12], data[13]);
        let gateway_address  = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
        let tcp_port         = u16::from_be_bytes([data[18], data[19]]);
        let dns_primary      = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let dns_secondary    = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        let http_server_port = u16::from_be_bytes([data[28], data[29]]);

        IpAndMacAddress {
            mac_address,
            ip_address,
            subnet_mask,
            gateway_address,
            tcp_port,
            dns_primary,
            dns_secondary,
            http_server_port
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = vec![0x00];
        let ip_addr:      u32 = self.ip_address.into();
        let subnet_mask:  u32 = self.subnet_mask.into();
        let gateway_addr: u32 = self.gateway_address.into();
        let dns_primary:  u32 = self.dns_primary.into();
        let dns_secondary: u32 = self.dns_secondary.into();

        data.extend_from_slice(self.mac_address.as_bytes());
        data.extend_from_slice(&ip_addr.to_be_bytes());
        data.extend_from_slice(&subnet_mask.to_be_bytes());
        data.extend_from_slice(&gateway_addr.to_be_bytes());
        data.extend_from_slice(&self.tcp_port.to_be_bytes());
        data.extend_from_slice(&dns_primary.to_be_bytes());
        data.extend_from_slice(&dns_secondary.to_be_bytes());
        data.extend_from_slice(&self.http_server_port.to_be_bytes());

        data
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClockData {
    pub time: DateTime<Local>,
    pub firmware_version: semver::Version,
    pub firmware_identify_code: u8,
    pub controller_type: ControllerType,
}

impl ClockData {
    pub fn decode(data: &[u8]) -> Result<ClockData> {
        if data.len() < 12 {
            return Err(ProtocolError::MessageTooShort.into())
        }

        let year = 2000 + data[6] as i32;
        let month = data[5] as u32;
        let day = data[4] as u32;
        let hour = data[2] as u32;
        let minute = data[1] as u32;
        let second = data[0] as u32;
        let time = Local.ymd(year, month, day).and_hms(hour, minute, second);

        let firmware_major = (data[7] & 0xF0) >> 4;
        let firmware_minor = data[7] & 0x0F;
        let firmware_version = semver::Version::new(firmware_major as u64, firmware_minor as u64, 0);
        // data 8-9 reserved
        let firmware_identify_code = data[10];
        let controller_type = ControllerType::from_u8(data[11]).ok_or(ProtocolError::UnknownControllerType)?;

        Ok(ClockData {
            time,
            firmware_version,
            firmware_identify_code,
            controller_type,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TagId32 {
    pub first:  u16,
    pub second: u16,
}

impl TagId32 {
    pub fn new(first: u16, second: u16) -> TagId32 {
        TagId32 { first, second }
    }

    pub fn decode(data: &[u8]) -> Result<TagId32> {
        if data.len() < 4 {
            return Err(ProtocolError::MessageTooShort.into());
        }

        Ok(TagId32 {
            first:  u16::from_be_bytes([data[0], data[1]]),
            second: u16::from_be_bytes([data[2], data[3]]),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut res = Vec::<u8>::new();
        res.extend_from_slice(&self.first.to_be_bytes());
        res.extend_from_slice(&self.second.to_be_bytes());
        res
    }

    pub fn numeric_format(&self) -> u32 {
        ((self.first as u32) << 16) + (self.second as u32)
    }

    pub fn hex_format(&self) -> String {
        let numeric: u32 = self.numeric_format();
        format!("{:08X}", numeric)
    }
}

impl From<TagId32> for u32 {
    fn from(t: TagId32) -> u32 { t.numeric_format() }
}

impl fmt::Display for TagId32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:05}:{:05}", self.first, self.second)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TagId64 {
    pub first:  u16,
    pub second: u16,
    pub third:  u16,
    pub fourth: u16,
}

impl TagId64 {
    pub const USER_NOT_FOUND: TagId64 = TagId64 {
        first:  0xFFFF,
        second: 0xFFFF,
        third:  0xFFFF,
        fourth: 0xFFFF,
    };

    pub fn new(first: u16, second: u16, third: u16, fourth: u16) -> TagId64 {
        TagId64 { first, second, third, fourth }
    }

    pub fn decode(data: &[u8]) -> Result<TagId64> {
        if data.len() < 8 {
            return Err(ProtocolError::MessageTooShort.into());
        }

        Ok(TagId64 {
            first:  u16::from_be_bytes([data[0], data[1]]),
            second: u16::from_be_bytes([data[2], data[3]]),
            third:  u16::from_be_bytes([data[4], data[5]]),
            fourth: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut res = Vec::<u8>::new();
        res.extend_from_slice(&self.first.to_be_bytes());
        res.extend_from_slice(&self.second.to_be_bytes());
        res.extend_from_slice(&self.third.to_be_bytes());
        res.extend_from_slice(&self.fourth.to_be_bytes());
        res
    }
}

impl From<TagId64> for u64 {
    fn from(t: TagId64) -> u64 {
        ((t.first as u64) << 48) +
        ((t.second as u64) << 32) +
        ((t.third as u64) << 16) +
        (t.fourth as u64)
    }
}

impl fmt::Display for TagId64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:05}:{:05}:{:05}:{:05}", self.first, self.second, self.third, self.fourth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_controller_options() {
        assert_eq!(ControllerPortOptions::decode(16), ControllerPortOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: true,
            skip_pin_check: false,
            auto_open_zone: false,
            auto_lock_door: false,
            time_attendance_disabled: false,
        });

        assert_eq!(ControllerPortOptions::decode(15), ControllerPortOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: false,
            skip_pin_check: true,
            auto_open_zone: true,
            auto_lock_door: true,
            time_attendance_disabled: true,
        });
    }

}
