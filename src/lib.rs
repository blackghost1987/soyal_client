#[macro_use] extern crate enum_primitive;

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

    pub fn get_remote_tcp_server_params(&self) -> Result<RemoteTCPServerParamsResponse> {
        self.get_controller_params(ControllerParamSubCommand::RemoteTCPServerParams)
    }

    pub fn get_ip_and_mac_address(&self) -> Result<IpAndMacAddressResponse> {
        self.get_controller_params(ControllerParamSubCommand::IpAndMacAddress)
    }

    pub fn get_relay_delay_time(&self) -> Result<RelayDelayResponse> {
        self.get_controller_params(ControllerParamSubCommand::RelayDelayTime)
    }

    pub fn get_controller_edit_password(&self) -> Result<EditPasswordResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerEditPassword)
    }

    pub fn get_reader_serial_number(&self) -> Result<SerialNumberResponse> {
        self.get_controller_params(ControllerParamSubCommand::ContorllerSerialNumber)
    }

    //*** CONTROLLER PARAMETER SETTERS

    // TODO try to set some data (with something more simple maybe?)
    pub fn set_controller_params(&self, sub_code: u8) -> io::Result<Vec<u8>> {
        self.send(Command::SetControllerParams, &[sub_code])
    }

    //*** GENERIC COMMANDS

    pub fn get_reader_status(&self) -> Result<ControllerStatusResponse> {
        let raw = self.send(Command::HostingPolling, &[])?;
        ControllerStatusResponse::decode(&raw)
    }

    fn get_event_log_inner(&self, data: &[u8]) -> Result<Option<EventLogResponse>> {
        let _raw = self.send(Command::GetOldestEventLog, data)?;
        // TODO handle ACK (if no log) OR DATA
        //EventLogStatusResponse::decode(raw)
        Ok(None)
    }

    pub fn get_oldest_event_log(&self) -> Result<Option<EventLogResponse>> {
        self.get_event_log_inner(&[])
    }

    /// RecordID max value is 0xFFFFFE = 16777214
    /// Version 2.07 and later
    pub fn get_specific_event_log(&self, record_id: u32) -> Result<Option<EventLogResponse>> {
        if record_id > EVENT_LOG_MAX_ID {
            return Err(ProtocolError::EventLogOutOfRange.into());
        }

        let bytes = record_id.to_be_bytes();
        self.get_event_log_inner(&[bytes[1], bytes[2], bytes[3]])
    }

    /// Version 2.07 and later
    pub fn get_event_log_status(&self) -> Result<EventLogStatusResponse> {
        let raw = self.send(Command::GetOldestEventLog, &[0xFF, 0xFF, 0xFF])?;
        EventLogStatusResponse::decode(&raw)
    }

    pub fn remove_oldest_event_log(&self) -> Result<()> {
        let _raw = self.send(Command::RemoveOldestEventLog, &[])?;
        // TODO handle ACK / NACK
        Ok(())
    }

    pub fn empty_event_log(&self) -> Result<()> {
        let _raw = self.send(Command::EmptyEventLog, &[])?;
        // TODO handle ACK / NACK
        Ok(())
    }

    pub fn get_user_parameters(&self, user_address: u16, continue_number_of_cards: u8) -> Result<UserParametersResponse> {
        let mut data = user_address.to_be_bytes().to_vec();
        data.push(continue_number_of_cards);
        let raw = self.send(Command::GetUserParams, &data)?;
        UserParametersResponse::decode(&raw)
    }

    pub fn set_user_parameters(&self, user_address: u16, user_params: UserParameters) -> Result<()> {
        let mut data: Vec<u8> = vec![0x01]; // only sending 1 user data
        data.extend_from_slice(&user_address.to_be_bytes());

        let user_data = user_params.encode();
        data.extend_from_slice(&user_data);
        let _raw = self.send(Command::SetUserParamsWithAntiPassBack, &data)?;
        // TODO handle ACK / NACK
        Ok(())
    }

    // TODO Relay On/Off control (0x21)
}
