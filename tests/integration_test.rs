use soyal_client::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
#[ignore]
fn reader_in_the_loop_test() {
    let access_data = AccessData {
        ip: IpAddr::from(Ipv4Addr::new(192, 168, 1, 127)),
        port: 1621,
        destination_id: 1,
        username: "SuperAdm".to_string(),
        password: "721568".to_string(),

    };
    let client = SoyalClient::new(access_data, Some(true));
    let res = client.test_reader();
    assert!(res.is_ok())
}
