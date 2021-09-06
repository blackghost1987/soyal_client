#[macro_use]
extern crate enum_primitive;

pub mod common;
pub mod response;
pub mod request;
pub mod structs;
pub mod enums;

pub use crate::common::*;
use crate::enums::*;
use crate::structs::*;
use crate::request::*;
use crate::response::*;

use chrono::{DateTime, Local, Timelike, Datelike};
use either::Either;
use log::*;
use semver::Version;
use serde::Serialize;
use std::io;
use std::io::prelude::*;
use std::net::{Ipv4Addr, TcpStream, SocketAddr};
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub destination_id: u8,
}

pub struct SoyalClient {
    access_data: AccessData,
}

impl SoyalClient {
    pub fn new(access_data: AccessData) -> SoyalClient {
        SoyalClient {
            access_data,
        }
    }

    fn send(&self, command: Command, data: &[u8]) -> io::Result<TcpStream> {
        debug!("Sending command {:?} (with data {:?}) to {:?}", command, data, self.access_data.ip);
        let address = SocketAddr::new(self.access_data.ip.into(), self.access_data.port);

        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;

        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command,
            data,
        };

        let _ = stream.write(&message.encode())?;
        Ok(stream)
    }

    fn send_and_read_response(&self, command: Command, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = self.send(command, data)?;
        let mut buffer = [0; 128];
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let size = stream.read(&mut buffer)?;

        info!("Received {} bytes: {:?}", size, &buffer[0..size]);

        io::Result::Ok(buffer[0..size].to_vec())
    }

    //*** CONTROLLER PARAMETER GETTERS

    fn get_controller_params_inner(&self, sub_code: ControllerParamSubCommand) -> io::Result<Vec<u8>> {
        self.send_and_read_response(Command::GetControllerParams, &[sub_code as u8])
    }

    pub fn get_controller_params<T>(&self, sub_code: ControllerParamSubCommand) -> Result<T> where T: Response<T> {
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

    pub fn set_controller_params(&self, sub_code: ControllerParamSubCommand, data: &[u8]) -> Result<AckOrNack> {
        let mut bytes = vec![sub_code as u8];
        bytes.extend_from_slice(data);
        debug!("Sending SetControllerParams with sub-command {:?} to {:?}", sub_code, self.access_data.ip);
        let raw = self.send_and_read_response(Command::SetControllerParams, &bytes)?;
        AckOrNack::handle(raw)
    }

    pub fn set_controller_options(&self, new_node_id: u8, params: ControllerOptions) -> Result<AckOrNack> {
        let mut data = vec![new_node_id];
        let param_data = params.encode(Version::new(4, 3, 0))?;
        data.extend(&param_data);
        self.set_controller_params(ControllerParamSubCommand::ControllerOptionParams, &data)
    }

    pub fn set_remote_tcp_server_params(&self, params: RemoteTCPServerParams) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::RemoteTCPServerParams, &data)
    }

    pub fn set_ip_and_mac_address(&self, params: IpAndMacAddress) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::IpAndMacAddress, &data)
    }

    //*** GENERIC GETTERS

    pub fn poll_reader(&self) -> Result<PollResponse> {
        let raw = self.send_and_read_response(Command::HostingPolling, &[])?;
        PollResponse::decode(&raw)
    }

    fn get_event_log_inner(&self, data: &[u8]) -> Result<Either<AckResponse, EventLogResponse>> {
        let raw = self.send_and_read_response(Command::GetOldestEventLog, data)?;
        match AckResponse::decode(&raw) {
            Ok(x) => Ok(Either::Left(x)),
            Err(_) => {
                if raw[7] == 0xFF {
                    return Err(ProtocolError::EventLogOutOfRange.into());
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
        let raw = self.send_and_read_response(Command::GetOldestEventLog, &[0xFF, 0xFF, 0xFF])?;
        EventLogStatusResponse::decode(&raw)
    }

    pub fn get_user_parameters(&self, user_address: u16) -> Result<UserParametersResponse> {
        let mut data = user_address.to_be_bytes().to_vec();

        // TODO make this parametric? decode multiple users
        let continue_number_of_cards: u8 = 1;

        data.push(continue_number_of_cards);
        let raw = self.send_and_read_response(Command::GetUserParams, &data)?;
        UserParametersResponse::decode(&raw)
    }

    pub fn get_real_time_clock(&self) -> Result<RealTimeClockResponse> {
        let raw = self.send_and_read_response(Command::GetRealTimeClock, &[])?;
        RealTimeClockResponse::decode(&raw)
    }

    //*** GENERIC SETTERS

    pub fn prompt_accepted(&self) -> Result<()> {
        self.send(Command::PromptAcceptedMessage, &[])?;
        Ok(())
    }

    pub fn prompt_invalid(&self) -> Result<()> {
        self.send(Command::PromptAcceptedMessage, &[])?;
        Ok(())
    }

    pub fn remove_oldest_event_log(&self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::RemoveOldestEventLog, &[])?;
        AckOrNack::handle(raw)
    }

    pub fn empty_event_log(&self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::EmptyEventLog, &[])?;
        AckOrNack::handle(raw)
    }

    pub fn set_user_parameters(&self, user_address: u16, user_params: UserParameters) -> Result<AckOrNack> {
        let mut data: Vec<u8> = vec![0x01]; // only sending 1 user data
        data.extend_from_slice(&user_address.to_be_bytes());

        let user_data = user_params.encode();
        data.extend_from_slice(&user_data);
        let raw = self.send_and_read_response(Command::SetUserParamsWithAntiPassBack, &data)?;
        AckOrNack::handle(raw)
    }

    pub fn relay_control(&self, command: RelayCommand, port: RelayPortNumber) -> Result<RelayStatusResponse> {
        let data = vec![command as u8, port as u8];
        let raw = self.send_and_read_response(Command::RelayOnOffControl, &data)?;
        RelayStatusResponse::decode(&raw)
    }

    pub fn set_real_time_clock(&self, time: DateTime<Local>) -> Result<AckOrNack> {
        let data = vec![
            time.second() as u8,
            time.minute() as u8,
            time.hour() as u8,
            time.weekday().number_from_sunday() as u8,
            time.day() as u8,
            time.month() as u8,
            (time.year() - 2000) as u8,
        ];

        let raw = self.send_and_read_response(Command::SetRealTimeClock, &data)?;
        AckOrNack::handle(raw)
    }
}
