#[macro_use]
extern crate enum_primitive;

pub mod common;
pub mod enums;
pub mod request;
pub mod response;
pub mod structs;

pub use crate::common::*;
use crate::enums::*;
use crate::request::*;
use crate::response::*;
use crate::structs::*;

use chrono::{DateTime, Datelike, Local, Timelike};
use either::Either;
use log::*;
use semver::Version;
use serde::Serialize;
use std::io;
use std::io::prelude::*;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub destination_id: u8,
}

pub struct SoyalClient {
    access_data: AccessData,
    connection_timeout: Duration,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    stream: Option<TcpStream>,
}

impl SoyalClient {
    pub fn new(access_data: AccessData) -> SoyalClient {
        let default_timeout = Duration::from_secs(2);
        SoyalClient::new_with_timeout(access_data, default_timeout, Some(default_timeout), Some(default_timeout))
    }

    pub fn new_with_timeout(
        access_data: AccessData,
        connection_timeout: Duration,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> SoyalClient {
        let ip = access_data.ip;

        let mut client = SoyalClient {
            access_data,
            connection_timeout,
            read_timeout,
            write_timeout,
            stream: None,
        };

        if let Err(e) = client.open_connection() {
            warn!("Initial connection failed to {}. Error: {}", ip, e);
        }

        client
    }

    fn open_connection(&mut self) -> io::Result<()> {
        let address = SocketAddr::new(self.access_data.ip.into(), self.access_data.port);
        let new_stream = TcpStream::connect_timeout(&address, self.connection_timeout)?;
        new_stream.set_read_timeout(self.read_timeout)?;
        new_stream.set_write_timeout(self.write_timeout)?;
        self.stream = Some(new_stream);
        Ok(())
    }

    pub fn close_connection(&mut self) -> io::Result<()> {
        match self.stream.as_ref() {
            Some(st) => {
                st.shutdown(std::net::Shutdown::Both)?;
            },
            None => (),
        }
        self.stream = None;
        trace!("Connection to {} closed successfully.", self.access_data.ip);
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.stream.is_some()
    }

    fn get_stream(&mut self) -> io::Result<&TcpStream> {
        if self.stream.is_none() {
            trace!("Reconnecting to reader {}...", self.access_data.ip);
            self.open_connection()?;
        }
        let stream = self.stream.as_ref().unwrap();
        Ok(stream)
    }

    fn send(&mut self, command: Command, data: &[u8]) -> io::Result<()> {
        trace!("Sending command {:?} (with data {:?}) to {:?}", command, data, self.access_data.ip);
        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command,
            data,
        };

        let mut stream: &TcpStream = self.get_stream()?;
        let res = stream.write_all(&message.encode());

        if let Err(e) = res {
            warn!("Connection to {} closed unexpectedly! Reason: {:?}", self.access_data.ip, e);
            self.stream = None;
        }

        Ok(())
    }

    fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut stream: &TcpStream = self.get_stream()?;

        let mut buffer = [0; 128];
        let size = stream.read(&mut buffer)?;

        trace!("Received {} bytes from {}. Data: {:?}", size, self.access_data.ip, &buffer[0..size]);

        io::Result::Ok(buffer[0..size].to_vec())
    }

    fn send_and_read_response(&mut self, command: Command, data: &[u8]) -> io::Result<Vec<u8>> {
        self.send(command, data)?;
        self.read()
    }

    //*** CONTROLLER PARAMETER GETTERS

    fn get_controller_params_inner(&mut self, sub_code: ControllerParamSubCommand) -> io::Result<Vec<u8>> {
        self.send_and_read_response(Command::GetControllerParams, &[sub_code as u8])
    }

    pub fn get_controller_params<T>(&mut self, sub_code: ControllerParamSubCommand) -> Result<T>
    where
        T: Response<T>,
    {
        let raw = self.get_controller_params_inner(sub_code)?;
        if raw.is_empty() {
            return Err(ProtocolError::NoResponse.into());
        }
        T::decode(&raw)
    }

    pub fn get_controller_options(&mut self) -> Result<ControllerOptionsResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerOptionParams)
    }

    pub fn get_remote_tcp_server_params(&mut self) -> Result<RemoteTCPServerParamsResponse> {
        self.get_controller_params(ControllerParamSubCommand::RemoteTCPServerParams)
    }

    pub fn get_ip_and_mac_address(&mut self) -> Result<IpAndMacAddressResponse> {
        self.get_controller_params(ControllerParamSubCommand::IpAndMacAddress)
    }

    pub fn get_relay_delay_time(&mut self) -> Result<RelayDelayResponse> {
        self.get_controller_params(ControllerParamSubCommand::RelayDelayTime)
    }

    pub fn get_controller_edit_password(&mut self) -> Result<EditPasswordResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerEditPassword)
    }

    pub fn get_reader_serial_number(&mut self) -> Result<SerialNumberResponse> {
        self.get_controller_params(ControllerParamSubCommand::ContorllerSerialNumber)
    }

    //*** CONTROLLER PARAMETER SETTERS

    pub fn set_controller_params(&mut self, sub_code: ControllerParamSubCommand, data: &[u8]) -> Result<AckOrNack> {
        let mut bytes = vec![sub_code as u8];
        bytes.extend_from_slice(data);
        debug!("Sending SetControllerParams with sub-command {:?} to {:?}", sub_code, self.access_data.ip);
        let raw = self.send_and_read_response(Command::SetControllerParams, &bytes)?;
        AckOrNack::handle(raw)
    }

    pub fn set_controller_options(&mut self, new_node_id: u8, params: ControllerOptions) -> Result<AckOrNack> {
        let mut data = vec![new_node_id];
        let param_data = params.encode(Version::new(4, 3, 0))?;
        data.extend(&param_data);
        self.set_controller_params(ControllerParamSubCommand::ControllerOptionParams, &data)
    }

    pub fn set_remote_tcp_server_params(&mut self, params: RemoteTCPServerParams) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::RemoteTCPServerParams, &data)
    }

    pub fn set_hosting_flag(&mut self, data: HostingFlags) -> Result<AckOrNack> {
        let data = data.encode();
        self.set_controller_params(ControllerParamSubCommand::HostingFlag, &[data])
    }

    pub fn set_ip_and_mac_address(&mut self, params: IpAndMacAddress) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::IpAndMacAddress, &data)
    }

    //*** GENERIC GETTERS

    pub fn poll_reader(&mut self) -> Result<PollResponse> {
        let raw = self.send_and_read_response(Command::HostingPolling, &[])?;
        PollResponse::decode(&raw)
    }

    fn get_event_log_inner(&mut self, data: &[u8]) -> Result<Either<AckResponse, EventLogResponse>> {
        let raw = self.send_and_read_response(Command::GetOldestEventLog, data)?;
        match AckResponse::decode(&raw) {
            Ok(x) => Ok(Either::Left(x)),
            Err(_) => {
                if raw[7] == 0xFF {
                    return Err(ProtocolError::EventLogOutOfRange.into());
                }
                EventLogResponse::decode(&raw).map(Either::Right)
            },
        }
    }

    pub fn get_oldest_event_log(&mut self) -> Result<Either<AckResponse, EventLogResponse>> {
        self.get_event_log_inner(&[])
    }

    /// RecordID max value is 0xFFFFFE = 16777214
    /// Version 2.07 and later
    pub fn get_specific_event_log(&mut self, record_id: u32) -> Result<Either<AckResponse, EventLogResponse>> {
        if record_id > EVENT_LOG_MAX_ID {
            return Err(ProtocolError::EventLogOutOfRange.into());
        }

        let bytes = record_id.to_be_bytes();
        self.get_event_log_inner(&[bytes[1], bytes[2], bytes[3]])
    }

    /// Version 2.07 and later
    pub fn get_event_log_status(&mut self) -> Result<EventLogStatusResponse> {
        let raw = self.send_and_read_response(Command::GetOldestEventLog, &[0xFF, 0xFF, 0xFF])?;
        EventLogStatusResponse::decode(&raw)
    }

    pub fn get_user_parameters(&mut self, user_address: u16) -> Result<UserParametersResponse> {
        let mut data = user_address.to_be_bytes().to_vec();

        // TODO make this parametric? decode multiple users
        let continue_number_of_cards: u8 = 1;

        data.push(continue_number_of_cards);
        let raw = self.send_and_read_response(Command::GetUserParams, &data)?;
        UserParametersResponse::decode(&raw)
    }

    pub fn get_real_time_clock(&mut self) -> Result<RealTimeClockResponse> {
        let raw = self.send_and_read_response(Command::GetRealTimeClock, &[])?;
        RealTimeClockResponse::decode(&raw)
    }

    //*** GENERIC SETTERS

    pub fn prompt_accepted(&mut self) -> Result<()> {
        self.send(Command::PromptAcceptedMessage, &[])?;
        Ok(())
    }

    pub fn prompt_invalid(&mut self) -> Result<()> {
        self.send(Command::PromptInvalidMessage, &[])?;
        Ok(())
    }

    pub fn remove_oldest_event_log(&mut self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::RemoveOldestEventLog, &[])?;
        AckOrNack::handle(raw)
    }

    pub fn empty_event_log(&mut self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::EmptyEventLog, &[])?;
        AckOrNack::handle(raw)
    }

    pub fn set_user_parameters(&mut self, user_address: u16, user_params: UserParameters) -> Result<AckOrNack> {
        let mut data: Vec<u8> = vec![0x01]; // only sending 1 user data
        data.extend_from_slice(&user_address.to_be_bytes());

        let user_data = user_params.encode();
        data.extend_from_slice(&user_data);
        let raw = self.send_and_read_response(Command::SetUserParamsWithAntiPassBack, &data)?;
        AckOrNack::handle(raw)
    }

    pub fn clear_user_parameters(&mut self, user_address: u16) -> Result<AckOrNack> {
        self.set_user_parameters(user_address, UserParameters::default())
    }

    pub fn erase_user_data(&mut self, from: u16, to: u16) -> Result<AckOrNack> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&from.to_be_bytes());
        data.extend_from_slice(&to.to_be_bytes());
        let raw = self.send_and_read_response(Command::EraseUserData, &data)?;
        AckOrNack::handle(raw)
    }

    pub fn relay_control(&mut self, command: RelayCommand, port: RelayPortNumber) -> Result<RelayStatusResponse> {
        let data = vec![command as u8, port as u8];
        let raw = self.send_and_read_response(Command::RelayOnOffControl, &data)?;
        RelayStatusResponse::decode(&raw)
    }

    pub fn set_real_time_clock(&mut self, time: DateTime<Local>) -> Result<AckOrNack> {
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
