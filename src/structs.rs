use std::fmt::Debug;
use std::convert;
use std::result;

use serde::{Serialize, Deserialize};
use chrono::{NaiveDate, Datelike};
use std::net::Ipv4Addr;
use macaddr::MacAddr6;
use enum_primitive::FromPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SlaveFlags {
    pub slave_mode_enabled: bool,
    pub keyboard_locked: bool,
    pub lcd_update_locked: bool,
    pub inhibit_125khz_tags: bool,
    pub inhibit_13_56mhz_tags: bool,
    pub fire_alarm_input_enabled: bool,
    pub alarm_on_invalid_tag: bool,
}

impl SlaveFlags {
    pub fn decode(data: u8) -> SlaveFlags {
        SlaveFlags {
            slave_mode_enabled:       data & 0b10000000 != 0,
            keyboard_locked:          data & 0b01000000 != 0,
            lcd_update_locked:        data & 0b00100000 != 0,
            inhibit_125khz_tags:      data & 0b00010000 != 0,
            inhibit_13_56mhz_tags:    data & 0b00001000 != 0,
            fire_alarm_input_enabled: data & 0b00000100 != 0,
            alarm_on_invalid_tag:     data & 0b00000010 != 0,
            // bit 0 reserved
        }
    }

    pub fn encode(&self) -> u8 {
        let mut data = 0b00000000;
        if self.slave_mode_enabled       { data += 0b10000000; }
        if self.keyboard_locked          { data += 0b01000000; }
        if self.lcd_update_locked        { data += 0b00100000; }
        if self.inhibit_125khz_tags      { data += 0b00010000; }
        if self.inhibit_13_56mhz_tags    { data += 0b00001000; }
        if self.fire_alarm_input_enabled { data += 0b00000100; }
        if self.alarm_on_invalid_tag     { data += 0b00000010; }
        data
    }
}
