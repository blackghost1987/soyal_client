use serde::{Serialize, Deserialize};
use std::ops::BitXorAssign;

use crate::common::*;

enum_from_primitive! {
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Command {
    PromptAcceptedMessage            = 0x04,
    PromptInvalidMessage             = 0x05,
    PromptKeyingInPassword           = 0x09,
    GetControllerParams              = 0x12,
    HostingPolling                   = 0x18,
    SetControllerParams              = 0x20,
    RelayOnOffControl                = 0x21,
    SetRealTimeClock                 = 0x23,
    GetRealTimeClock                 = 0x24,
    GetOldestEventLog                = 0x25,
    BuzzerSounds                     = 0x26,
    SendTextToLCD                    = 0x28,
    DailyTimeZone                    = 0x2A,
    ReadWriteBeginDay                = 0x2B,
    AnnualHolidaySetting             = 0x2C,
    EmptyEventLog                    = 0x2D,
    ReadWriteUserAlias               = 0x2E,
    ReadWriteUserFloor               = 0x2F,
    SerialSpecificFormat             = 0x30,
    RemoveOldestEventLog             = 0x37,
    SetUserParamsWithAntiPassBack    = 0x83,
    SetUserParamsWithoutAntiPassBack = 0x84,
    EraseUserData                    = 0x85,
    InitialAntiPassback              = 0x86,
    GetUserParams                    = 0x87,
    AntiPassbackDB                   = 0x8A,
    FingerprintOrVein                = 0x8F,
    BlackUIDManagement               = 0x90,
}
}

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ControllerParamSubCommand {
    ControllerOptionParams = 0x00,
    AutoOpenTimeZone       = 0x01,
    DailyAlarmTable        = 0x02,
    AutoDutyShiftTimeTable = 0x03,
    MasterCardUID          = 0x04,
    RS485SubNodeDoorNumber = 0x05,
    CustomData             = 0x06,
    UIDBlockParams         = 0x08,
    RemoteTCPServerParams  = 0x0A,
    DutyText               = 0x0B,
    DESFireFieldAssignment = 0x12,
    HostingFlag            = 0x13,
    IpAndMacAddress        = 0x14,
    RelayDelayTime         = 0x16,
    ExtraFlag              = 0x17,
    ControllerEditPassword = 0x18,
    ControllerAccessMode   = 0x19,
    RS485ReaderStatus      = 0x81, // read-only
    ContorllerSerialNumber = 0xFE, // read-only
}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedMessage<'a> {
    pub destination_id: u8, // 0x00: bus master, 0xFF: broadcast
    pub command: Command,
    pub data: &'a [u8],
}

impl<'a> ExtendedMessage<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let length: u16 = self.data.len() as u16 + 4; // 4 extra bytes: destination_id, command_code, xor, sum

        assert!(length < 250, "Extended message data part too long!");

        let full_length: u16 = length + 4 + 2; // 4 header + 2 length bytes

        let command_code = self.command as u8;

        let mut buffer = Vec::<u8>::with_capacity(full_length as usize);
        buffer.extend_from_slice(&EXTENDED_HEADER);
        buffer.extend_from_slice(&length.to_be_bytes());
        buffer.push(self.destination_id);
        buffer.push(command_code);
        buffer.extend_from_slice(self.data);

        let mut xor_res: u8 = 0xFF;
        xor_res.bitxor_assign(self.destination_id);
        xor_res.bitxor_assign(command_code);
        for d in self.data {
            xor_res.bitxor_assign(d);
        }
        buffer.push(xor_res);

        let mut sum_res: u8 = 0;
        sum_res = sum_res.wrapping_add(self.destination_id);
        sum_res = sum_res.wrapping_add(command_code);
        for d in self.data {
            sum_res = sum_res.wrapping_add(*d);
        }
        sum_res = sum_res.wrapping_add(xor_res);
        buffer.push(sum_res);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_no_data() {
        let d = ExtendedMessage {
            destination_id: 1,
            command: Command::HostingPolling,
            data: &[],
        };
        assert_eq!(d.encode(), vec!(0xFF, 0x00, 0x5A, 0xA5, 0x00, 0x04, 0x01, 0x18, 0xE6, 0xFF))
    }

    #[test]
    fn encode_with_data() {
        let d = ExtendedMessage {
            destination_id: 1,
            command: Command::HostingPolling,
            data: &[0x01, 0x02],
        };
        assert_eq!(d.encode(), vec!(0xFF, 0x00, 0x5A, 0xA5, 0x00, 0x06, 0x01, 0x18, 0x01, 0x02, 0xE5, 0x01))
    }
}