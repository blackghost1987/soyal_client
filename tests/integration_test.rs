use std::net::{IpAddr, Ipv4Addr};

use soyal_client::*;
use soyal_client::api_types::*;
use chrono::NaiveDate;
use macaddr::MacAddr6;

// WARNING: Hardware-in-the-loop tests! Set real access data here:
const IP_ADDR: [u8; 4] = [192, 168, 1, 127];

fn create_client() -> SoyalClient {
    let access_data = AccessData {
        ip: IpAddr::from(Ipv4Addr::from(IP_ADDR)),
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
        zone: UserAccessTimeZone { weigand_port_same_time_zone: true, user_time_zone: 0 },
        available_doors_bitmap: 0xFFFF,
        last_allowed_date: NaiveDate::from_ymd(2099, 12, 31),
        level: 0,
        enable_anti_pass_back_check: false
    };
    let res = client.set_user_parameters(2, user_params);
    println!("User params: {:?}", res);
    assert!(res.is_ok());
}