extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use] extern crate serde_derive;

use std::io;

pub const DEFAULT_PORT: u16 = 8439;
pub const LIMIT_USER_NAME:    usize = 128;
pub const LIMIT_CHANNEL_NAME: usize = 128;
pub const LIMIT_ATTR_NAME:    usize = 128;
pub const LIMIT_ATTR_AMOUNT:  usize = 2048;
pub const LIMIT_MESSAGE:      usize = 16384;

pub const ERR_LOGIN_INVALID: u8 = 0;
pub const ERR_LOGIN_BANNED:  u8 = 1;
pub const ERR_LOGIN_EMPTY:   u8 = 2;
pub const ERR_LOGIN_BOT:     u8 = 3;
pub const ERR_UNKNOWN_CHANNEL: u8 = 4;
pub const ERR_LIMIT_REACHED: u8 = 5;
pub const ERR_MISSING_PERMISSION: u8 = 6;

pub const PERM_READ:  u8 = 1;
pub const PERM_WRITE: u8 = 1 << 1;
pub const PERM_NICK:  u8 = 1 << 2;
pub const PERM_MANAGE_CHANNELS:   u8 = 1 << 3;
pub const PERM_MANAGE_ATTRIBUTES: u8 = 1 << 4;

// TYPES
#[derive(Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub allow: u8,
    pub deny: u8,
    pub id: usize,
    pub name: String,
    pub pos: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub attributes: Vec<usize>,
    pub bot: bool,
    pub id: usize,
    pub name: String,
    pub nick: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Channel {
    pub allow: Vec<usize>,
    pub deny:  Vec<usize>,
    pub id: usize,
    pub name: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub author: usize,
    pub channel: usize,
    pub id: usize,
    pub text: Vec<u8>,
    pub timestamp: i64,
    pub timestamp_edit: Option<i64>
}

// CLIENT PACKETS
#[derive(Serialize, Deserialize, Debug)]
pub struct Login {
    pub bot: bool,
    pub name: String,
    pub password: Option<String>,
    pub token: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AttributeCreate {
    pub allow: u8,
    pub deny: u8,
    pub name: String,
    pub pos: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AttributeUpdate {
    pub inner: Attribute
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AttributeDelete {
    pub id: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelCreate {
    pub allow: Vec<usize>,
    pub deny:  Vec<usize>,
    pub name: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelUpdate {
    pub inner: Channel
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelDelete {
    pub channel: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageList {
    pub around: Option<usize>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageCreate {
    pub channel: usize,
    pub text: Vec<u8>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageUpdate {
    pub id: usize,
    pub text: Vec<u8>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageDelete {
    pub id: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Command {
    pub author: usize,
    pub parts: Vec<String>,
    pub recipient: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Close {}

// SERVER PACKETS
#[derive(Serialize, Deserialize, Debug)]
pub struct LoginSuccess {
    pub created: bool,
    pub id: usize,
    pub token: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AttributeReceive {
    pub inner: Attribute
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ChannelReceive {
    pub inner: Channel
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MessageReceive {
    pub author: User,
    pub channel: Channel,
    pub id: usize,
    pub text: Vec<u8>,
    pub timestamp: i64,
    pub timestamp_edit: Option<i64>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandReceive {
    pub args: Vec<String>,
    pub author: User,
    pub command: String,
    pub recipient: User
}

macro_rules! packet {
    ($($type:ident),+) => {
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(/*tag = "type",*/ rename_all = "snake_case")]
        pub enum Packet {
            Err(u8),
            Close,
            $($type($type),)+
        }
    }
}
packet! {
    Login,
    AttributeCreate,
    AttributeUpdate,
    AttributeDelete,
    ChannelCreate,
    ChannelUpdate,
    ChannelDelete,
    MessageList,
    MessageCreate,
    MessageUpdate,
    MessageDelete,
    Command,

    LoginSuccess,
    AttributeReceive,
    ChannelReceive,
    MessageReceive,
    CommandReceive
}

pub fn serialize(packet: &Packet) -> Result<Vec<u8>, rmps::encode::Error> {
    rmps::to_vec(&packet)
}
pub fn deserialize<'a>(buf: &'a [u8]) -> Result<Packet, rmps::decode::Error> {
    rmps::from_slice(buf)
}
pub fn deserialize_stream<T: io::Read>(buf: T) -> Result<Packet, rmps::decode::Error> {
    rmps::from_read(buf)
}
pub fn encode_u16(input: u16) -> [u8; 2] {
    [
        (input >> 8)  as u8,
        (input % 256) as u8
    ]
}
pub fn decode_u16(bytes: &[u8]) -> u16 {
    assert_eq!(bytes.len(), 2);

    ((bytes[0] as u16) << 8) + bytes[1] as u16
}
pub fn read<T: io::Read>(reader: &mut T) -> Result<Packet, Box<std::error::Error>> {
    let mut buf = [0; 2];
    reader.read_exact(&mut buf)?;

    let size = decode_u16(&buf) as usize;
    let mut buf = vec![0; size];
    reader.read_exact(&mut buf)?;

    Ok(deserialize(&buf)?)
}

#[derive(Debug)]
pub struct ErrPacketTooBig;

impl std::error::Error for ErrPacketTooBig {
    fn description(&self) -> &str {
        "Packet size must fit into an u16"
    }
}
impl std::fmt::Display for ErrPacketTooBig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use std::error::Error;
        write!(f, "{}", self.description())
    }
}

pub fn write<T: io::Write>(writer: &mut T, packet: &Packet) -> Result<(), Box<std::error::Error>> {
    let buf = serialize(packet)?;
    if buf.len() > std::u16::MAX as usize {
        return Err(Box::new(ErrPacketTooBig));
    }
    let size = encode_u16(buf.len() as u16);
    writer.write_all(&size)?;
    writer.write_all(&buf)?;
    writer.flush()?;

    Ok(())
}

pub fn combine<I: Iterator<Item = (u8, u8)>>(attributes: &mut I) -> u8 {
    // Expects attributes to be sorted
    let mut result = 0;
    for attribute in attributes {
        result |= attribute.0;  // allow
        result &= !attribute.1; // deny
    }
    result
}
