extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use] extern crate serde_derive;

pub const TYPE_REGISTER: u8 = 0;
pub const TYPE_LOGIN: u8    = 1;
pub const TYPE_MESSAGE: u8  = 2;
pub const TYPE_COMMAND: u8  = 3;

#[derive(Serialize, Desieralize)]
pub struct Login {
    #[serde(rename = "type")]
    kind: u8,
    name: String,
    password: String
}
#[derive(Serialize, Desieralize, Debug)]
pub struct User {
    id: usize,
    name: String,
    nick: Option<String>,
    roles: Vec<usize>
}
#[derive(Serialize, Desieralize, Debug)]
pub struct Message {
    #[serde(rename = "type")]
    kind: u8,
    author: User,
    message: String
}
#[derive(Serialize, Desieralize, Debug)]
pub struct Command {
    #[serde(rename = "type")]
    kind: u8,
    author: User,
    command: String,
    args: Vec<String>
}
