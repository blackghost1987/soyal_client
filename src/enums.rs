use std::fmt::Debug;
use std::convert;
use std::result;

use serde::{Serialize, Deserialize};
use chrono::{NaiveDate, Datelike};
use std::net::Ipv4Addr;
use macaddr::MacAddr6;
use enum_primitive::FromPrimitive;

enum_from_primitive! {
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum OperationMode {
    Users16kFloors64 = 0x00,
    Users32kFloors32 = 0x01,
    Users65kFloors16 = 0x02,
}
}