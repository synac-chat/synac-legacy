extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use] extern crate serde_derive;

use std::io;
use serde::Serialize;
use rmps::Serializer;

pub const DEFAULT_PORT: u16 = 8439;

#[derive(Serialize, Deserialize, Debug)]
pub struct Login {
    name: String,
    password: Option<String>,
    token: Option<String>
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
pub struct Message {
    author: User,
    message: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandSend {
    author: usize,
    recipient: usize,
    parts: Vec<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandReceive {
    author: User,
    recipient: User,
    command: String,
    args: Vec<String>
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Packet {
    Login(Login),
    Message(Message),
    CommandSend(CommandSend),
    CommandReceive(CommandReceive),
    Error(String)
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
