use soyal_client::*;
use std::net::{IpAddr, Ipv4Addr};

// WARNING: Hardware-in-the-loop tests! Set real access data here:
const IP_ADDR: [u8; 4] = [192, 168, 1, 127];
const USERNAME: &str = "SuperAdm";
const PASSWORD: &str = "721568";

fn create_client() -> SoyalClient {
    let access_data = AccessData {
        ip: IpAddr::from(Ipv4Addr::from(IP_ADDR)),
        port: 1621,
        destination_id: 1,
        username: USERNAME.to_string(),
        password: PASSWORD.to_string(),

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
fn test_get_reader_serial() {
    let client = create_client();
    let res = client.get_reader_serial_number();
    println!("Hardware serial: {:?}", res);
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
fn test_get_relay_delays() {
    let client = create_client();
    let res = client.get_relay_delay_time();
    println!("Hardware delays: {:?}", res);
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