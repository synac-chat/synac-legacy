extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use] extern crate serde_derive;

use std::io;
use serde::Serialize;
use rmps::Serializer;

pub const DEFAULT_PORT: u16 = 8439;

// TYPES
#[derive(Serialize, Deserialize, Debug)]
pub struct Attribute {
    id: usize,
    name: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    id: usize,
    bot: bool,
    name: String,
    nick: Option<String>,
    attributes: Vec<usize>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Channel {
    id: usize,
    condition: Option<usize>
}

// CLIENT PACKETS
#[derive(Serialize, Deserialize, Debug)]
pub struct Register {
    name: String,
    password: String,
    server_password: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Login {
    name: String,
    password: Option<String>,
    token: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelList {}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelCreate {
    channel: Channel
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelUpdate {
    channel: Channel
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelDelete {
    channel: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageList {
    around: Option<usize>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageCreate {
    author: usize,
    channel: usize,
    message: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageUpdate {
    id: usize,
    channel: usize,
    message: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageDelete {
    id: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandSend {
    author: usize,
    recipient: usize,
    command: String,
    args: Vec<String>
}

// SERVER PACKETS
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandReceive {
    author: User,
    recipient: User,
    command: String,
    args: Vec<String>
}

macro_rules! packet {
    ($($type:expr)+) {
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(tag = "type", rename_all = "snake_case")]
        pub enum Packet {
            Error(String),
            $($type($type),)+
        }
    }
}
packet! {
    Register,
    Login,
    ChannelList,
    ChannelCreate,
    ChannelUpdate,
    ChannelDelete,
    MessageList,
    MessageCreate,
    MessageUpdate,
    MessageDelete,
    CommandSend,
    CommandReceive
}

pub fn serialize(packet: Packet) -> Result<Vec<u8>, rmps::encode::Error> {
    let mut buf = Vec::new();
    packet.serialize(&mut Serializer::new(&mut buf))?;

    Ok(buf)
}
pub fn deserialize<'a>(buf: &'a [u8]) -> Result<Packet, rmps::decode::Error> {
    rmps::from_slice(buf)
}
pub fn deserialize_stream<T: io::Read>(buf: T) -> Result<Packet, rmps::decode::Error> {
    rmps::from_read(buf)
}
