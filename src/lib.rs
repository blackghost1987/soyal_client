pub mod api_types;
pub mod response;
pub mod request;

use crate::api_types::*;
use crate::request::*;
use crate::response::*;

use std::io::prelude::*;
use std::net::{IpAddr, TcpStream, SocketAddr};
use serde::Serialize;
use std::io;


#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: IpAddr,
    pub port: u16,
    pub destination_id: u8,
    pub username: String,
    pub password: String, // FIXME why is this not needed?
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

    fn send(&self, command: Command, data: &[u8]) -> io::Result<Vec<u8>> {
        if self.debug_log {
            println!("Sending command {:?} (with data {:?}) to {:?}", command, data, self.access_data);
        }

        let address = SocketAddr::new(self.access_data.ip, self.access_data.port);

        let mut stream = TcpStream::connect(address)?;

        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command_code: command as u8,
            data
        };

        let _ = stream.write(&message.encode())?;
        let mut buffer = [0; 128];
        let size = stream.read(&mut buffer)?;

        if self.debug_log {
            println!("Received {:?}", &buffer[0..size]);
        }

        io::Result::Ok(buffer[0..size].to_vec())
    }

    //*** CONTROLLER PARAMETER GETTERS

    fn get_controller_params_inner(&self, sub_code: ControllerParamSubCommand) -> io::Result<Vec<u8>> {
        self.send(Command::GetControllerParams, &[sub_code as u8])
    }

    pub fn get_controller_params<T>(&self, sub_code: ControllerParamSubCommand) -> Result<T> where T: Response<T>{
        let raw = self.get_controller_params_inner(sub_code)?;
        T::decode(&raw)
    }

    pub fn get_controller_options(&self) -> Result<ControllerOptionsResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerOptionParams)
    }

    pub fn get_reader_serial_number(&self) -> Result<SerialNumberResponse> {
        self.get_controller_params(ControllerParamSubCommand::ContorllerSerialNumber)
    }

    pub fn get_relay_delay_time(&self) -> Result<RelayDelayResponse> {
        self.get_controller_params(ControllerParamSubCommand::RelayDelayTime)
    }

    pub fn get_controller_edit_password(&self) -> Result<EditPasswordResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerEditPassword)
    }

    //*** CONTROLLER PARAMETER SETTERS

    // TODO add data
    pub fn set_controller_params(&self, sub_code: u8) -> io::Result<Vec<u8>> {
        self.send(Command::SetControllerParams, &[sub_code])
    }

    //*** GENERIC COMMANDS

    pub fn get_reader_status(&self) -> Result<EchoResponse> {
        let raw = self.send(Command::HostingPolling, &[])?;
        EchoResponse::decode(&raw)
    }

    // TODO Relay On/Off control (0x21)
    // TODO Get the oldest event log of device (0x25)
    // TODO Remove the oldest event log of device (0x37)
    // TODO Empty the event log of device (0x2D)
    // TODO Set User Parameters (0x83/0x84)
    // TODO Get User Parameters (0x87)
}
