pub mod api_types;

use std::io::prelude::*;
use std::net::{IpAddr, TcpStream, SocketAddr};
use serde::Serialize;
use std::io;
use crate::api_types::*;

#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: IpAddr,
    pub port: u16,
    pub destination_id: u8,
    pub username: String,
    pub password: String,
}

pub struct SoyalClient {
    access_data: AccessData,
    debug_log: bool,
}

impl SoyalClient {
    pub fn new(access_data: AccessData, debug_log: Option<bool>) -> SoyalClient {
        SoyalClient {
            access_data: access_data,
            debug_log: debug_log.unwrap_or(false),
        }
    }

    fn send(&self, command_code: u8, data: &[u8]) -> io::Result<Vec<u8>> {
        if self.debug_log {
            println!("Sending {:?} to {:?}", data, self.access_data);
        }

        let address = SocketAddr::new(self.access_data.ip, self.access_data.port);

        let mut stream = TcpStream::connect(address)?;

        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command_code,
            data
        };

        let _ = stream.write(&message.encode())?;
        let mut buffer = [0; 128];
        let size = stream.read(&mut buffer)?;

        if self.debug_log {
            println!("Received {:?}", &buffer[0..size]);
        }

        Result::Ok(buffer[0..size].to_vec())
    }

    pub fn get_reader_status(&self) -> Result<EchoResponse, ClientError> {
        let raw = self.send(0x18, &[])?;
        EchoResponse::decode(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn reader_test() {
        let access_data = AccessData {
            ip: IpAddr::from(Ipv4Addr::new(192, 168, 1, 127)),
            port: 1621,
            destination_id: 1,
            username: "SuperAdm".to_string(),
            password: "721568".to_string(),

        };
        let client = SoyalClient::new(access_data, Some(true));
        let res = client.get_reader_status();
        assert!(res.is_ok())
    }
}