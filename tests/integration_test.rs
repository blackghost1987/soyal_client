use std::net::Ipv4Addr;

use soyal_client::*;
use chrono::{NaiveDate, Local};
use macaddr::MacAddr6;
use soyal_client::structs::*;
use soyal_client::enums::*;

// WARNING: Hardware-in-the-loop tests! Set real device IP here:
const IP_ADDR: [u8; 4] = [192, 168, 1, 127];

fn create_client() -> SoyalClient {
    let access_data = AccessData {
        ip: Ipv4Addr::from(IP_ADDR),
        port: 1621,
        destination_id: 1,
    };
    SoyalClient::new(access_data, Some(true))
}

#[test]
#[ignore]
fn test_get_reader_status() {
    let client = create_client();
    let res = client.get_reader_status();
    println!("Hardware status: {:?}", res);
    assert!(res.is_ok())
}

#[test]
#[ignore]
fn test_get_controller_options() {
    let client = create_client();
    let res = client.get_controller_options();
    println!("Controller params: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_set_controller_options() {
    let client = create_client();
    let controller_options = ControllerOptions {
        main_port_door_number: 1,
        wiegand_port_door_number: 2,
        edit_password: 123456,
        master_user_range_start: 0,
        master_user_range_end: 0,
        general_password: 1234,
        duress_code: 0,
        connected_reader_bitmask: 260,
        tag_hold_time: 100,
        main_port_door_relay_time: 700,
        wiegand_port_door_relay_time: 700,
        alarm_relay_time: 1500,
        main_port_options: ControllerPortOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: true,
            skip_pin_check: false,
            auto_open_zone: false,
            auto_lock_door: false,
            time_attendance_disabled: false
        },
        wiegand_port_options: ControllerPortOptions {
            anti_pass_back_enabled: false,
            anti_pass_back_in: false,
            force_open_alarm: false,
            egress_button: true,
            skip_pin_check: false,
            auto_open_zone: false,
            auto_lock_door: false,
            time_attendance_disabled: false
        },
        main_port_extended_options: ExtendedControllerOptions {
            door_relay_active_in_auto_open_time_zone: false,
            stop_alarm_at_door_closed: false,
            free_tag_access_mode: false,
            use_main_door_relay_for_wiegand_port: false,
            auto_disarmed_time_zone: false,
            key_pad_inhibited: false,
            fingerprint_only_enabled: false,
            egress_button_sound: true
        },
        wiegand_port_extended_options: ExtendedControllerOptions {
            door_relay_active_in_auto_open_time_zone: false,
            stop_alarm_at_door_closed: false,
            free_tag_access_mode: false,
            use_main_door_relay_for_wiegand_port: true,
            auto_disarmed_time_zone: false,
            key_pad_inhibited: false,
            fingerprint_only_enabled: false,
            egress_button_sound: true
        },
        main_port_door_close_time: 15,
        wiegand_port_door_close_time: 15,
        main_port_arming: false,
        wiegand_port_arming: false,
        access_mode: ControllerAccessMode::PINOnly,
        armed_output_pulse_width: 0,
        arming_delay: 1,
        alarm_delay: 1,
        uart_data: UARTData { uart2_type: UART2Type::LiftController, uart2_baud_rate: UartBaudRate::Baud9600, uart3_type: UART3Type::YungTAILiftPort },
        common_options: CommonOptions { enable_black_table_check: false, show_local_language_manual: false, rs485_port_function: RS485PortFunction::HostCommunication, wiegand_signal_output_disable: true, lcd_display_date_in_dd_mm: false, auto_reset_anti_pass_back: false, trigger_alarm_on_expired_user: false },
        display_options: DisplayOptions { fingerprint_enroll_duplication_check: false, auto_duty_code_shift_table_enabled: false, show_wiegand_port_message_on_main_lcd: true, uid_display_format: UIDDisplayFormat::WG32 },
        keyboard_lock_error_times: Some(5),
        host_port_baud: Some(HostBaudRate::Baud9600),
        slave_flags: Some(SlaveFlags { slave_mode_enabled: false, keyboard_locked: false, lcd_update_locked: false, inhibit_125khz_tags: false, inhibit_13_56mhz_tags: false, fire_alarm_input_enabled: false, alarm_on_invalid_tag: false }),
        operation_mode: Some(OperationMode::Users16kFloors64),
        main_port_egress_beeps: Some(3),
        wiegand_port_egress_beeps: Some(3),
    };

    let res = client.set_controller_options(1, controller_options);
    println!("Set controller params response: {:?}", res);
    assert!(res.is_ok());
}


#[test]
#[ignore]
fn test_get_remote_tcp_params() {
    let client = create_client();
    let res = client.get_remote_tcp_server_params();
    println!("TCP params: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_set_remote_tcp_params() {
    let client = create_client();
    let res = client.set_remote_tcp_server_params(RemoteTCPServerParams {
        first_remote_address: Ipv4Addr::UNSPECIFIED,
        first_remote_port: 0,
        second_remote_address: Ipv4Addr::UNSPECIFIED,
        second_remote_port: 0
    });
    println!("TCP params setting response: {:?}", res);
    assert!(res.is_ok());
}


#[test]
#[ignore]
fn test_get_ip_and_mac_address() {
    let client = create_client();
    let res = client.get_ip_and_mac_address();
    println!("IP and MAC: {:?}", res);
    assert!(res.is_ok())
}

#[test]
#[ignore]
fn test_set_ip_and_mac_address() {
    let client = create_client();
    let res = client.set_ip_and_mac_address(IpAndMacAddress {
        mac_address: MacAddr6::new(0x00, 0x13, 0x57, 0x04, 0x9D, 0x9E),
        ip_address: Ipv4Addr::new(192, 168, 1, 127),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        gateway_address: Ipv4Addr::new(192, 168, 1, 254),
        tcp_port: 1621,
        dns_primary:   Ipv4Addr::new(168, 95, 1, 1),
        dns_secondary: Ipv4Addr::new(168, 95, 192, 1),
        http_server_port: 80
    });
    println!("TCP params setting response: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_get_relay_delays() {
    let client = create_client();
    let res = client.get_relay_delay_time();
    println!("Hardware delays: {:?}", res);
    assert!(res.is_ok())
}

#[test]
#[ignore]
fn test_get_edit_pass() {
    let client = create_client();
    let res = client.get_controller_edit_password();
    println!("Hardware password: {:?}", res);
    assert!(res.is_ok())
}

#[test]
#[ignore]
fn test_get_reader_serial() {
    let client = create_client();
    let res = client.get_reader_serial_number();
    println!("Hardware serial: {:?}", res);
    assert!(res.is_ok())
}

#[test]
#[ignore]
fn test_event_log_status() {
    let client = create_client();
    let res = client.get_event_log_status();
    println!("Event log status: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_oldest_event_log() {
    let client = create_client();
    let res = client.get_oldest_event_log();
    println!("Oldest event log: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_specific_event_log() {
    let client = create_client();
    let res = client.get_specific_event_log(3);
    println!("Specific event log: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_remove_oldest_event_log() {
    let client = create_client();
    let res = client.remove_oldest_event_log();
    println!("Remove oldest event log response: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_empty_event_log() {
    let client = create_client();
    let res = client.empty_event_log();
    println!("Empty event log response: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_get_user_params() {
    let client = create_client();
    let res = client.get_user_parameters(2);
    println!("User params: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_set_user_params() {
    let client = create_client();
    let user_params = UserParameters {
        tag_uid: (0, 0, 131, 13316),
        pin_code: 0,
        mode: UserMode {
            access_mode: UserAccessMode::CardOrPIN,
            patrol_card: false,
            card_omitted_after_fingerprint_rec: true,
            fingerprint_omitted_after_card_rec: true,
            expire_check: false,
            anti_pass_back_control: true,
            password_change_available: true
        },
        zone: UserAccessTimeZone { wiegand_port_same_time_zone: true, user_time_zone: 0 },
        available_doors_bitmap: 0xFFFF,
        last_allowed_date: NaiveDate::from_ymd(2099, 12, 31),
        level: 0,
        enable_anti_pass_back_check: false
    };
    let res = client.set_user_parameters(2, user_params);
    println!("User params: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_get_relay_control() {
    let client = create_client();
    let res = client.relay_control(RelayCommand::GetCurrentStatus, PortNumber::AllPorts);
    println!("Relay status: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_set_relay_control() {
    let client = create_client();
    let res = client.relay_control(RelayCommand::DoorRelayPulse, PortNumber::AllPorts);
    println!("Relay status after enable: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_get_clock() {
    let client = create_client();
    let res = client.get_real_time_clock();
    println!("Get RTC response: {:?}", res);
    assert!(res.is_ok());
}

#[test]
#[ignore]
fn test_set_clock() {
    let client = create_client();
    let res = client.set_real_time_clock(Local::now());
    println!("Set RTC response: {:?}", res);
    assert!(res.is_ok());
}
