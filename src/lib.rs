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
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Debug, Serialize)]
pub struct AccessData {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub destination_id: u8,
}

pub struct SoyalClient {
    access_data: AccessData,
    #[allow(dead_code)]
    connection_timeout: Duration,
    #[allow(dead_code)]
    read_timeout: Option<Duration>,
    #[allow(dead_code)]
    write_timeout: Option<Duration>,
    stream: Option<TcpStream>,
}

impl SoyalClient {
    pub async fn new(access_data: AccessData) -> Self {
        let default_timeout = Duration::from_secs(2);
        SoyalClient::new_with_timeout(access_data, default_timeout, Some(default_timeout), Some(default_timeout)).await
    }

    pub async fn new_with_timeout(
        access_data: AccessData,
        connection_timeout: Duration,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Self {
        let ip = access_data.ip;

        let mut client = SoyalClient {
            access_data,
            connection_timeout,
            read_timeout,
            write_timeout,
            stream: None,
        };

        if let Err(e) = client.open_connection().await {
            warn!("Initial connection failed to {}. Error: {}", ip, e);
        }

        client
    }

    async fn open_connection(&mut self) -> io::Result<()> {
        let address = SocketAddr::new(self.access_data.ip.into(), self.access_data.port);
        let new_stream = timeout(self.connection_timeout, TcpStream::connect(&address)).await?;
        self.stream = Some(new_stream?);
        Ok(())
    }

    pub async fn close_connection(&mut self) -> io::Result<()> {
        match self.stream.as_mut() {
            Some(st) => {
                st.shutdown().await?;
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

    async fn get_stream(&mut self) -> io::Result<&mut TcpStream> {
        if self.stream.is_none() {
            trace!("Reconnecting to reader {}...", self.access_data.ip);
            self.open_connection().await?;
        }
        let stream = self.stream.as_mut().expect("Stream should exist after reconnection");
        Ok(stream)
    }

    async fn send(&mut self, command: Command, data: &[u8], verbose: bool) -> io::Result<()> {
        let log_msg = format!("Sending command {:?} to {:?}", command, self.access_data.ip);
        if verbose {
            debug!("{}", log_msg);
        } else {
            trace!("{}", log_msg);
        }
        trace!("Command {:?} data {:?}", command, data);
        let message = ExtendedMessage {
            destination_id: self.access_data.destination_id,
            command,
            data,
        };
        let encoded = message.encode();

        let write_timeout = self.write_timeout;
        let stream: &mut TcpStream = self.get_stream().await?;

        let res = match write_timeout {
            Some(t) => timeout(t, stream.write_all(&encoded)).await?,
            None => stream.write_all(&encoded).await,
        };

        if let Err(e) = res {
            warn!("Connection to {} closed unexpectedly during write! Reason: {:?}", self.access_data.ip, e);
            self.stream = None;
            return Err(e);
        }

        Ok(())
    }

    async fn read(&mut self) -> io::Result<Vec<u8>> {
        trace!("Waiting for response from {}...", self.access_data.ip);
        let read_timeout = self.read_timeout;
        let stream: &mut TcpStream = self.get_stream().await?;

        let mut buffer = [0; 128];
        let size = match read_timeout {
            Some(t) => timeout(t, stream.read(&mut buffer)).await?,
            None => stream.read(&mut buffer).await,
        }?;

        trace!("Received {} bytes from {}. Data: {:?}", size, self.access_data.ip, &buffer[0..size]);

        io::Result::Ok(buffer[0..size].to_vec())
    }

    async fn send_and_read_response(&mut self, command: Command, data: &[u8], verbose: bool) -> io::Result<Vec<u8>> {
        self.send(command, data, verbose).await?;
        self.read().await
    }

    //*** CONTROLLER PARAMETER GETTERS

    async fn get_controller_params_inner(&mut self, sub_code: ControllerParamSubCommand) -> io::Result<Vec<u8>> {
        self.send_and_read_response(Command::GetControllerParams, &[sub_code as u8], true).await
    }

    pub async fn get_controller_params<T>(&mut self, sub_code: ControllerParamSubCommand) -> Result<T>
    where
        T: Response<T>,
    {
        let raw = self.get_controller_params_inner(sub_code).await?;
        if raw.is_empty() {
            return Err(ProtocolError::NoResponse.into());
        }
        T::decode(&raw)
    }

    pub async fn get_controller_options(&mut self) -> Result<ControllerOptionsResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerOptionParams).await
    }

    pub async fn get_remote_tcp_server_params(&mut self) -> Result<RemoteTCPServerParamsResponse> {
        self.get_controller_params(ControllerParamSubCommand::RemoteTCPServerParams).await
    }

    pub async fn get_ip_and_mac_address(&mut self) -> Result<IpAndMacAddressResponse> {
        self.get_controller_params(ControllerParamSubCommand::IpAndMacAddress).await
    }

    pub async fn get_relay_delay_time(&mut self) -> Result<RelayDelayResponse> {
        self.get_controller_params(ControllerParamSubCommand::RelayDelayTime).await
    }

    pub async fn get_controller_edit_password(&mut self) -> Result<EditPasswordResponse> {
        self.get_controller_params(ControllerParamSubCommand::ControllerEditPassword).await
    }

    pub async fn get_reader_serial_number(&mut self) -> Result<SerialNumberResponse> {
        self.get_controller_params(ControllerParamSubCommand::ContorllerSerialNumber).await
    }

    //*** CONTROLLER PARAMETER SETTERS

    pub async fn set_controller_params(&mut self, sub_code: ControllerParamSubCommand, data: &[u8]) -> Result<AckOrNack> {
        let mut bytes = vec![sub_code as u8];
        bytes.extend_from_slice(data);
        debug!("Sending SetControllerParams with sub-command {:?} to {:?}", sub_code, self.access_data.ip);
        let raw = self.send_and_read_response(Command::SetControllerParams, &bytes, true).await?;
        AckOrNack::handle(raw)
    }

    pub async fn set_controller_options(&mut self, new_node_id: u8, params: ControllerOptions) -> Result<AckOrNack> {
        let mut data = vec![new_node_id];
        let param_data = params.encode(Version::new(4, 3, 0))?;
        data.extend(&param_data);
        self.set_controller_params(ControllerParamSubCommand::ControllerOptionParams, &data).await
    }

    pub async fn set_remote_tcp_server_params(&mut self, params: RemoteTCPServerParams) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::RemoteTCPServerParams, &data).await
    }

    pub async fn set_hosting_flag(&mut self, data: HostingFlags) -> Result<AckOrNack> {
        let data = data.encode();
        self.set_controller_params(ControllerParamSubCommand::HostingFlag, &[data]).await
    }

    pub async fn set_ip_and_mac_address(&mut self, params: IpAndMacAddress) -> Result<AckOrNack> {
        let data = params.encode();
        self.set_controller_params(ControllerParamSubCommand::IpAndMacAddress, &data).await
    }

    //*** GENERIC GETTERS

    pub async fn poll_reader(&mut self) -> Result<PollResponse> {
        let raw = self.send_and_read_response(Command::HostingPolling, &[], false).await?;
        PollResponse::decode(&raw)
    }

    async fn get_event_log_inner(&mut self, data: &[u8]) -> Result<Either<AckResponse, EventLogResponse>> {
        let raw = self.send_and_read_response(Command::GetOldestEventLog, data, false).await?;
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

    pub async fn get_oldest_event_log(&mut self) -> Result<Either<AckResponse, EventLogResponse>> {
        self.get_event_log_inner(&[]).await
    }

    /// RecordID max value is 0xFFFFFE = 16777214
    /// Version 2.07 and later
    pub async fn get_specific_event_log(&mut self, record_id: u32) -> Result<Either<AckResponse, EventLogResponse>> {
        if record_id > EVENT_LOG_MAX_ID {
            return Err(ProtocolError::EventLogOutOfRange.into());
        }

        let bytes = record_id.to_be_bytes();
        self.get_event_log_inner(&[bytes[1], bytes[2], bytes[3]]).await
    }

    /// Version 2.07 and later
    pub async fn get_event_log_status(&mut self) -> Result<EventLogStatusResponse> {
        let raw = self.send_and_read_response(Command::GetOldestEventLog, &[0xFF, 0xFF, 0xFF], true).await?;
        EventLogStatusResponse::decode(&raw)
    }

    pub async fn get_user_parameters(&mut self, user_address: u16) -> Result<UserParametersResponse> {
        let mut data = user_address.to_be_bytes().to_vec();

        // TODO make this parametric? decode multiple users
        let continue_number_of_cards: u8 = 1;

        data.push(continue_number_of_cards);
        let raw = self.send_and_read_response(Command::GetUserParams, &data, true).await?;
        UserParametersResponse::decode(&raw)
    }

    pub async fn get_real_time_clock(&mut self) -> Result<RealTimeClockResponse> {
        let raw = self.send_and_read_response(Command::GetRealTimeClock, &[], true).await?;
        RealTimeClockResponse::decode(&raw)
    }

    //*** GENERIC SETTERS

    pub async fn prompt_accepted(&mut self) -> Result<()> {
        self.send(Command::PromptAcceptedMessage, &[], true).await?;
        Ok(())
    }

    pub async fn prompt_invalid(&mut self) -> Result<()> {
        self.send(Command::PromptInvalidMessage, &[], true).await?;
        Ok(())
    }

    pub async fn remove_oldest_event_log(&mut self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::RemoveOldestEventLog, &[], false).await?;
        AckOrNack::handle(raw)
    }

    pub async fn empty_event_log(&mut self) -> Result<AckOrNack> {
        let raw = self.send_and_read_response(Command::EmptyEventLog, &[], true).await?;
        AckOrNack::handle(raw)
    }

    pub async fn set_user_parameters(&mut self, user_address: u16, user_params: UserParameters) -> Result<AckOrNack> {
        let mut data: Vec<u8> = vec![0x01]; // only sending 1 user data
        data.extend_from_slice(&user_address.to_be_bytes());

        let user_data = user_params.encode();
        data.extend_from_slice(&user_data);
        let raw = self.send_and_read_response(Command::SetUserParamsWithAntiPassBack, &data, true).await?;
        AckOrNack::handle(raw)
    }

    pub async fn clear_user_parameters(&mut self, user_address: u16) -> Result<AckOrNack> {
        self.set_user_parameters(user_address, UserParameters::default()).await
    }

    pub async fn erase_user_data(&mut self, from: u16, to: u16) -> Result<AckOrNack> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&from.to_be_bytes());
        data.extend_from_slice(&to.to_be_bytes());
        let raw = self.send_and_read_response(Command::EraseUserData, &data, true).await?;
        AckOrNack::handle(raw)
    }

    pub async fn relay_control(&mut self, command: RelayCommand, port: RelayPortNumber) -> Result<RelayStatusResponse> {
        let data = vec![command as u8, port as u8];
        let raw = self.send_and_read_response(Command::RelayOnOffControl, &data, true).await?;
        RelayStatusResponse::decode(&raw)
    }

    pub async fn set_real_time_clock(&mut self, time: DateTime<Local>) -> Result<AckOrNack> {
        let data = vec![
            time.second() as u8,
            time.minute() as u8,
            time.hour() as u8,
            time.weekday().number_from_sunday() as u8,
            time.day() as u8,
            time.month() as u8,
            (time.year() - 2000) as u8,
        ];

        let raw = self.send_and_read_response(Command::SetRealTimeClock, &data, true).await?;
        AckOrNack::handle(raw)
    }
}
