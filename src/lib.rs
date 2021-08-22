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
use either::Either;


#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: IpAddr,
    pub port: u16,
    pub destination_id: u8,
    //pub username: String,
    //pub password: String, // FIXME why is this not needed?
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
        let command_code = command as u8;
        if self.debug_log {
            println!("Sending command {:?} ({:#X?}) (with data {:?}) to {:?}", command, command_code, data, self.access_data);
        }

        let address = SocketAddr::new(self.access_data.ip, self.access_data.port);

        let mut stream = TcpStream::connect(address)?;

        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command_code: command_code,
            data
        };

        let _ = stream.write(&message.encode())?;
        let mut buffer = [0; 128];
        let size = stream.read(&mut buffer)?;

        if self.debug_log {
            println!("Received {} bytes: {:?}", size, &buffer[0..size]);
        }

        io::Result::Ok(buffer[0..size].to_vec())
    }

    //*** CONTROLLER PARAMETER GETTERS

    fn get_controller_params_inner(&self, sub_code: ControllerParamSubCommand) -> io::Result<Vec<u8>> {
        self.send(Command::GetControllerParams, &[sub_code as u8])
    }

    pub fn get_controller_params<T>(&self, sub_code: ControllerParamSubCommand) -> Result<T> where T: Response<T>{
        let raw = self.get_controller_params_inner(sub_code)?;
        if raw.is_empty() {
            return Err(ProtocolError::NoResponse.into());
        }
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

    pub fn set_controller_params(&self, sub_code: ControllerParamSubCommand, data: &Vec<u8>) -> Result<Either<AckResponse, NackResponse>> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(sub_code as u8);
        bytes.extend_from_slice(&data);
        let raw = self.send(Command::SetControllerParams, &bytes)?;
        handle_ack_or_nack(raw)
    }

    // TODO implement and turn off that damn force_open_alarm...
    /*pub fn set_controller_options(&self) -> Result<ControllerOptionsResponse> {
        self.set_controller_params(ControllerParamSubCommand::ControllerOptionParams)
    }*/

    pub fn set_remote_tcp_server_params(&self, params: RemoteTCPServerParams) -> Result<Either<AckResponse, NackResponse>> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::RemoteTCPServerParams, &data)
    }

    pub fn set_ip_and_mac_address(&self, params: IpAndMacAddress) -> Result<Either<AckResponse, NackResponse>> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::IpAndMacAddress, &data)
    }

    //*** GENERIC COMMANDS

    pub fn get_reader_status(&self) -> Result<ControllerStatusResponse> {
        let raw = self.send(Command::HostingPolling, &[])?;
        ControllerStatusResponse::decode(&raw)
    }

    fn get_event_log_inner(&self, data: &[u8]) -> Result<Either<AckResponse, EventLogResponse>> {
        let raw = self.send(Command::GetOldestEventLog, data)?;
        match AckResponse::decode(&raw) {
            Ok(x) => Ok(Either::Left(x)),
            Err(_) => {
                if raw[7] == 0xFF {
                    return Err(ProtocolError::EventLogOutOfRange.into())
                }
                EventLogResponse::decode(&raw).map(Either::Right)
            }
        }
    }

    pub fn get_oldest_event_log(&self) -> Result<Either<AckResponse, EventLogResponse>> {
        self.get_event_log_inner(&[])
    }

    /// RecordID max value is 0xFFFFFE = 16777214
    /// Version 2.07 and later
    pub fn get_specific_event_log(&self, record_id: u32) -> Result<Either<AckResponse, EventLogResponse>> {
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

    pub fn remove_oldest_event_log(&self) -> Result<Either<AckResponse, NackResponse>> {
        let raw = self.send(Command::RemoveOldestEventLog, &[])?;
        handle_ack_or_nack(raw)
    }

    pub fn empty_event_log(&self) -> Result<Either<AckResponse, NackResponse>> {
        let raw = self.send(Command::EmptyEventLog, &[])?;
        handle_ack_or_nack(raw)
    }

    pub fn get_user_parameters(&self, user_address: u16) -> Result<UserParametersResponse> {
        let mut data = user_address.to_be_bytes().to_vec();

        // TODO make this parametric? decode multiple users
        let continue_number_of_cards: u8 = 1;

        data.push(continue_number_of_cards);
        let raw = self.send(Command::GetUserParams, &data)?;
        UserParametersResponse::decode(&raw)
    }

    pub fn set_user_parameters(&self, user_address: u16, user_params: UserParameters) -> Result<Either<AckResponse, NackResponse>> {
        let mut data: Vec<u8> = vec![0x01]; // only sending 1 user data
        data.extend_from_slice(&user_address.to_be_bytes());

        let user_data = user_params.encode();
        data.extend_from_slice(&user_data);
        let raw = self.send(Command::SetUserParamsWithAntiPassBack, &data)?;
        handle_ack_or_nack(raw)
    }

    pub fn relay_control(&self, command: RelayCommand, port: PortNumber) -> Result<RelayStatusResponse> {
        let mut data = Vec::<u8>::new();
        data.push(command as u8);

        let port = (port as u8) - (PortNumber::MainPort as u8);
        data.push(port);

        let raw = self.send(Command::RelayOnOffControl, &data)?;
        RelayStatusResponse::decode(&raw)
    }
}
