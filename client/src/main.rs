extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
extern crate termion;
extern crate common;

use common::Packet;
use openssl::ssl::{SslConnectorBuilder, SslMethod, SslStream};
use rusqlite::Connection as SqlConnection;
use std::collections::HashMap;
use std::env;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod frontend_minimal;
mod connect;
mod listener;
mod parser;

use frontend_minimal as frontend;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum LogEntryId {
    Message(usize),
    None,
    Sending
}

pub struct Session {
    addr: SocketAddr,
    attributes: HashMap<usize, common::Attribute>,
    channel: Option<usize>,
    channels: HashMap<usize, common::Channel>,
    id: usize,
    last: Option<(usize, Vec<u8>)>,
    stream: SslStream<TcpStream>,
    users: HashMap<usize, common::User>
}
impl Session {
    pub fn new(addr: SocketAddr, id: usize, stream: SslStream<TcpStream>) -> Session {
        Session {
            addr: addr,
            attributes: HashMap::new(),
            channel: None,
            channels: HashMap::new(),
            id: id,
            last: None,
            stream: stream,
            users: HashMap::new()
        }
    }
}

fn main() {
    let screen = Arc::new(frontend::Screen::new());

    // See https://github.com/rust-lang/rust/issues/35853
    macro_rules! println {
        () => { screen.log(String::new()); };
        ($($arg:expr),*) => { screen.log(format!($($arg),*)); };
    }
    macro_rules! readline {
        ($break:block) => {
            match screen.readline() {
                Ok(ok) => ok,
                Err(_) => $break
            }
        }
    }
    macro_rules! readpass {
        ($break:block) => {
            match screen.readpass() {
                Ok(ok) => ok,
                Err(_) => $break
            }
        }
    }

    let db = match SqlConnection::open("data.sqlite") {
        Ok(ok) => ok,
        Err(err) => {
            println!("Failed to open database");
            println!("{}", err);
            return;
        }
    };
    db.execute("CREATE TABLE IF NOT EXISTS servers (
                    ip      TEXT NOT NULL UNIQUE,
                    key     BLOB NOT NULL,
                    token   TEXT
                )", &[])
        .expect("Couldn't create SQLite table");

    let db = Arc::new(Mutex::new(db));

    #[cfg(unix)]
    let mut nick = env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    #[cfg(windows)]
    let mut nick = env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    #[cfg(not(any(unix, windows)))]
    let mut nick = "unknown".to_string();

    let ssl = SslConnectorBuilder::new(SslMethod::tls())
        .expect("Failed to create SSL connector D:")
        .build();
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));

    println!("Welcome, {}", nick);
    println!("To quit, type /quit");
    println!("To change your name, type");
    println!("/nick <name>");
    println!("To connect to a server, type");
    println!("/connect <ip>");
    println!();

    let (sent_sender, sent_receiver) = mpsc::sync_channel(0);
    let (stop_sender, stop_receiver) = mpsc::channel();

    let db_clone      = Arc::clone(&db);
    let screen_clone  = Arc::clone(&screen);
    let session_clone = Arc::clone(&session);
    let thread = thread::spawn(move || {
        listener::listen(db_clone, screen_clone, sent_sender, session_clone, stop_receiver);
    });

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        let input = readline!({ break; });
        if input.is_empty() {
            continue;
        }
        editor.add_history_entry(&input);

        if input.starts_with('/') {
            let mut args = parser::parse(&input[1..]);
            if args.is_empty() {
                continue;
            }
            let command = args.remove(0);

            macro_rules! usage_min {
                ($amount:expr, $usage:expr) => {
                    if args.len() < $amount {
                        println!(concat!("Usage: /", $usage));
                        continue;
                    }
                }
            }
            macro_rules! usage_max {
                ($amount:expr, $usage:expr) => {
                    if args.len() > $amount {
                        println!(concat!("Usage: /", $usage));
                        continue;
                    }
                }
            }
            macro_rules! usage {
                ($amount:expr, $usage:expr) => {
                    if args.len() != $amount {
                        println!(concat!("Usage: /", $usage));
                        continue;
                    }
                }
            }

            macro_rules! require_session {
                ($session:expr) => {
                    match *$session {
                        Some(ref mut s) => s,
                        None => {
                            println!("You're not connected to a server");
                            continue;
                        }
                    }
                }
            }

            match &*command {
                "quit" => break,
                "nick" => {
                    usage!(1, "nick <name>");
                    nick = args.remove(0);

                    let mut session = session.lock().unwrap();
                    if let Some(ref mut session) = *session {
                        let packet = Packet::LoginUpdate(common::LoginUpdate {
                            name: Some(nick.clone()),
                            password_current: None,
                            password_new: None,
                            reset_token: false
                        });
                        if let Err(err) = common::write(&mut session.stream, &packet) {
                            println!("Failed to rename you on the server");
                            println!("{}", err);
                        }
                    }

                    println!("Your name is now {}", nick);
                },
                "passwd" => {
                    usage!(0, "passwd");
                    {
                        let mut session = session.lock().unwrap();
                        let session = require_session!(session);

                        println!("Current password: ");
                        let current = readpass!({ continue; });
                        println!("New password: ");
                        let new = readpass!({ continue; });

                        let packet = Packet::LoginUpdate(common::LoginUpdate {
                            name: None,
                            password_current: Some(current),
                            password_new: Some(new),
                            reset_token: true // Doesn't actually matter in this case
                        });
                        if let Err(err) = common::write(&mut session.stream, &packet) {
                            println!("Failed to send password update");
                            println!("{}", err);
                            continue;
                        }
                    }
                    let _ = sent_receiver.recv_timeout(Duration::from_secs(10));
                },
                "connect" => {
                    usage!(1, "connect <ip[:port]>");
                    let mut session = session.lock().unwrap();
                    if session.is_some() {
                        println!("Please disconnect first");
                        continue;
                    }
                    *session = connect::connect(&db.lock().unwrap(), &args[0], &nick, &screen, &ssl);
                },
                "disconnect" => {
                    usage!(0, "disconnect");
                    let mut session = session.lock().unwrap();
                    {
                        let session = require_session!(session);
                        let _ = common::write(&mut session.stream, &Packet::Close);
                    }
                    *session = None;
                },
                "forget" => {
                    usage!(1, "forget <ip>");
                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            println!("Not a valid IP");
                            continue;
                        }
                    };
                    db.lock().unwrap().execute("DELETE FROM servers WHERE ip = ?", &[&addr.to_string()]).unwrap();
                },
                "create" => {
                    usage_min!(2, "create <\"attribute\"/\"channel\"> <name> [data]");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let packet = match &*args[0] {
                        "channel" => {
                            usage_max!(2, "create channel <name>");
                            let mut name = args.remove(1);
                            if name.starts_with('#') {
                                name.drain(..1);
                            }
                            Packet::ChannelCreate(common::ChannelCreate {
                                overrides: Vec::new(),
                                name: name
                            })
                        },
                        "attribute" => {
                            usage_max!(3, "create attribute <name> [data]");
                            let (mut allow, mut deny) = (0, 0);
                            if args.len() == 3 && !from_perm_string(&*args[2], &mut allow, &mut deny) {
                                println!("Invalid permission string");
                                continue;
                            }
                            let max = session.attributes.values().max_by_key(|item| item.pos);
                            Packet::AttributeCreate(common::AttributeCreate {
                                allow: allow,
                                deny: deny,
                                name: args.remove(1),
                                pos: max.map_or(1, |item| item.pos+1),
                                unassignable: false
                            })
                        },
                        _ => { println!("Can't create that"); continue; }
                    };
                    if let Err(err) = common::write(&mut session.stream, &packet) {
                        println!("Failed to send packet");
                        println!("{}", err);
                    }
                },
                "update" => {
                    usage!(2, "update <\"attribute\"/\"channel\"> <id>");

                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let id = match args[1].parse() {
                        Ok(ok) => ok,
                        Err(_) => {
                            println!("Not a valid number");
                            continue;
                        }
                    };

                    let packet = match &*args[0] {
                        "attribute" => if let Some(attribute) = session.attributes.get(&id) {
                            let (mut allow, mut deny) = (attribute.allow, attribute.deny);

                            println!("Editing: {}", attribute.name);
                            println!("(Press enter to keep current value)");
                            println!();
                            println!("Name [{}]: ", attribute.name);

                            let name = readline!({ continue; });
                            let mut name = name.trim();
                            if name.is_empty() { name = &attribute.name };

                            println!("Permission [{}]: ", to_perm_string(allow, deny));
                            let perms = readline!({ continue; });
                            if !from_perm_string(&perms, &mut allow, &mut deny) {
                                println!("Invalid permission string");
                                continue;
                            }

                            println!("Position [{}]: ", attribute.pos);
                            let pos = readline!({ continue; });
                            let pos = pos.trim();
                            let pos = if pos.is_empty() {
                                attribute.pos
                            } else {
                                match pos.parse() {
                                    Ok(ok) => ok,
                                    Err(_) => {
                                        println!("Not a valid number");
                                        continue;
                                    }
                                }
                            };

                            Some(Packet::AttributeUpdate(common::AttributeUpdate {
                                inner: common::Attribute {
                                    allow: allow,
                                    deny: deny,
                                    id: attribute.id,
                                    name: name.to_string(),
                                    pos: pos,
                                    unassignable: attribute.unassignable
                                }
                            }))
                        } else { None },
                        "channel" => if let Some(channel) = session.channels.get(&id) {
                            println!("Editing: #{}", channel.name);
                            println!("(Press enter to keep current value)");
                            println!();

                            println!("Name [{}]: ", channel.name);
                            let name = readline!({ continue; });
                            let mut name = name.trim();
                            if name.is_empty() { name = &channel.name }
                            Some(Packet::ChannelUpdate(common::ChannelUpdate {
                                inner: common::Channel {
                                    id: channel.id,
                                    name: name.to_string(),
                                    overrides: Vec::new()
                                },
                                keep_overrides: true
                            }))
                        } else { None },
                        "user" => if let Some(user) = session.users.get(&id) {
                            let mut attributes = user.attributes.clone();
                            loop {
                                let result = attributes.iter().fold(String::new(), |mut acc, item| {
                                    if !acc.is_empty() { acc.push_str(", "); }
                                    acc.push_str(&item.to_string());
                                    acc
                                });
                                println!("Attributes: [{}]", result);
                                println!("Commands: add, remove, quit");

                                let line = readline!({ break; });

                                let parts = parser::parse(&line);
                                if parts.is_empty() { continue; }
                                let add = match &*parts[0] {
                                    "add" => true,
                                    "remove" => false,
                                    "quit" => break,
                                    _ => {
                                        println!("Unknown command");
                                        continue;
                                    }
                                };

                                if parts.len() != 2 {
                                    println!("Usage: add/remove <id>");
                                    break;
                                }
                                let id = match parts[1].parse() {
                                    Ok(ok) => ok,
                                    Err(_) => {
                                        println!("Invalid ID");
                                        continue;
                                    }
                                };
                                if let Some(attribute) = session.attributes.get(&id) {
                                    if attribute.pos == 0 {
                                        println!("Can't assign that attribute");
                                        continue;
                                    }
                                    if add {
                                        println!("Added: {}", attribute.name);
                                        attributes.push(id);
                                    } else {
                                        println!("Removed: {}", attribute.name);
                                        let pos = attributes.iter().position(|item| *item == id);
                                        if let Some(pos) = pos {
                                            attributes.remove(pos);
                                        }
                                        // TODO remove_item once stable
                                    }
                                } else {
                                    println!("Couldn't find attribute");
                                }
                            }
                            Some(Packet::UserUpdate(common::UserUpdate {
                                attributes: attributes,
                                id: id
                            }))
                        } else { None },
                        _ => {
                            println!("Can't delete that");
                            continue;
                        }
                    };
                    if let Some(packet) = packet {
                        if let Err(err) = common::write(&mut session.stream, &packet) {
                            println!("Oh no could not delete");
                            println!("{}", err);
                        }
                    } else {
                        println!("Nothing with that ID");
                    }
                },
                "delete" => {
                    usage!(2, "delete <\"attribute\"/\"channel\"/\"message\"> <id>");

                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let id = match args[1].parse() {
                        Ok(ok) => ok,
                        Err(_) => {
                            println!("Failed to parse ID");
                            continue;
                        }
                    };

                    let packet = match &*args[0] {
                        "attribute" => if session.attributes.contains_key(&id) {
                            Some(Packet::AttributeDelete(common::AttributeDelete {
                                id: id
                            }))
                        } else { None },
                        "channel" => if session.channels.contains_key(&id) {
                            Some(Packet::ChannelDelete(common::ChannelDelete {
                                id: id
                            }))
                        } else { None },
                        "message" =>
                            Some(Packet::MessageDelete(common::MessageDelete {
                                id: id
                            })),
                        _ => {
                            println!("Can't delete that");
                            continue;
                        }
                    };
                    if let Some(packet) = packet {
                        if let Err(err) = common::write(&mut session.stream, &packet) {
                            println!("Oh no could not delete");
                            println!("{}", err);
                        }
                    } else {
                        println!("Nothing with that ID");
                    }
                },
                "list" => {
                    usage!(1, "list <\"attributes\"/\"channels\"/\"users\">");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    match &*args[0] {
                        "channels" => {
                            // Yeah, cloning this is bad... But what can I do? I need to sort!
                            // Though, I suspect this might be a shallow copy.
                            let mut channels: Vec<_> = session.channels.values().collect();
                            channels.sort_by_key(|item| &item.name);

                            let result = channels.iter().fold(String::new(), |mut acc, channel| {
                                if !acc.is_empty() { acc.push_str(", "); }
                                acc.push('#');
                                acc.push_str(&channel.name);
                                acc
                            });
                            println!("{}", result);
                        },
                        "attributes" => {
                            // Read the above comment, thank you ---------------------------^
                            let mut attributes: Vec<_> = session.attributes.values().collect();
                            attributes.sort_by_key(|item| &item.pos);

                            let result = attributes.iter().fold(String::new(), |mut acc, attribute| {
                                if !acc.is_empty() { acc.push_str(", "); }
                                acc.push_str(&attribute.name);
                                acc
                            });
                            println!("{}", result);
                        },
                        "users" => {
                            let mut result = String::new();
                            // something something above comment
                            let mut users: Vec<_> = session.users.values().collect();
                            users.sort_by_key(|item| &item.name);

                            for banned in &[false, true] {
                                if *banned {
                                    result.push_str("\nBanned:\n");
                                }
                                result = users.iter().fold(result, |mut acc, user| {
                                    if user.ban == *banned {
                                        if !acc.is_empty() { acc.push_str(", "); }
                                        acc.push_str(&user.name);
                                    }
                                    acc
                                });
                            }
                            println!("{}", result);
                        },
                        _ => println!("Can't list that")
                    }
                },
                "info" => {
                    usage!(1, "info <attribute or channel name>");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let mut name = &*args[0];
                    if name.starts_with('#') {
                        name = &name[1..];
                    }

                    let id = name.parse();

                    println!();
                    for channel in session.channels.values() {
                        if name == channel.name
                            || (name.starts_with('#') && name[1..] == channel.name)
                            || Ok(channel.id) == id {
                            println!("Channel #{}", channel.name);
                            println!("ID: #{}", channel.id);
                            for &(id, (allow, deny)) in &channel.overrides {
                                println!("Permission override: Role #{} = {}", id, to_perm_string(allow, deny));
                            }
                        }
                    }
                    for attribute in session.attributes.values() {
                        if name == attribute.name || Ok(attribute.id) == id {
                            println!("Attribute {}", attribute.name);
                            println!("Permission: {}", to_perm_string(attribute.allow, attribute.deny));
                            println!("ID: #{}", attribute.id);
                            println!("Position: {}", attribute.pos);
                        }
                    }
                    for user in session.users.values() {
                        if name == user.name || Ok(user.id) == id {
                            println!("User {}", user.name);
                            println!(
                                "Attributes: [{}]",
                                user.attributes.iter()
                                    .fold(String::new(), |mut acc, id| {
                                        if !acc.is_empty() {
                                            acc.push_str(", ");
                                        }
                                        acc.push_str(&id.to_string());
                                        acc
                                    })
                            );
                            if user.ban {
                                println!("Banned.");
                            }
                            println!("Bot: {}", if user.bot { "true" } else { "false" });
                            println!("ID: #{}", user.id);
                        }
                    }
                },
                "join" => {
                    usage!(1, "join <channel name>");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let mut name = &*args[0];
                    if name.starts_with('#') {
                        name = &name[1..];
                    }

                    let mut found = false;
                    for channel in session.channels.values() {
                        if channel.name == name {
                            session.channel = Some(channel.id);
                            screen.clear();
                            println!("Joined channel #{}", channel.name);
                            let packet = Packet::MessageList(common::MessageList {
                                after: None,
                                before: None,
                                channel: channel.id,
                                limit: common::LIMIT_MESSAGE_LIST
                            });
                            if let Err(err) = common::write(&mut session.stream, &packet) {
                                println!("Failed to send message_list packet");
                                println!("{}", err);
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        println!("No channel found with that name");
                    }
                },
                _ => {
                    println!("Unknown command");
                }
            }
            continue;
        }

        match *session.lock().unwrap() {
            None => {
                println!("You're not connected to a server");
                continue;
            },
            Some(ref mut session) => {
                if let Some(channel) = session.channel {
                    let packet = if input.starts_with("s/") && session.last.is_some() {
                        let mut parts = input[2..].splitn(2, '/');
                        let find = match parts.next() {
                            Some(some) => some,
                            None => continue
                        };
                        let replace = match parts.next() {
                            Some(some) => some,
                            None => continue
                        };
                        let last = session.last.as_ref().unwrap();
                        Packet::MessageUpdate(common::MessageUpdate {
                            id: last.0,
                            text: String::from_utf8_lossy(&last.1).replace(find, replace).into_bytes()
                        })
                    } else {
                        screen.log_with_id(format!("{}: {}", nick, input), LogEntryId::Sending);
                        Packet::MessageCreate(common::MessageCreate {
                            channel: channel,
                            text: input.into_bytes()
                        })
                    };

                    if let Err(err) = common::write(&mut session.stream, &packet) {
                        println!("Failed to deliver message");
                        println!("{}", err);
                        continue;
                    }
                } else {
                    println!("No channel specified. See /create channel, /list channels and /join");
                    continue;
                }
            }
        }
    }
    stop_sender.send(()).unwrap();
    if let Some(ref mut session) = *session.lock().unwrap() {
        let _ = common::write(&mut session.stream, &Packet::Close);
    }
    thread.join().unwrap();
}

fn to_perm_string(allow: u8, deny: u8) -> String {
    let mut result = String::with_capacity(10);

    if allow != 0 {
        result.push('+');
        result.push_str(&to_single_perm_string(allow));
    }
    if deny != 0 {
        result.push('-');
        result.push_str(&to_single_perm_string(deny));
    }

    result.shrink_to_fit();
    result
}
fn to_single_perm_string(bitmask: u8) -> String {
    let mut result = String::with_capacity(4);

    if bitmask & common::PERM_READ == common::PERM_READ {
        result.push('r');
    }
    if bitmask & common::PERM_WRITE == common::PERM_WRITE {
        result.push('w');
    }
    if bitmask & common::PERM_ASSIGN_ATTRIBUTES == common::PERM_ASSIGN_ATTRIBUTES {
        result.push('s');
    }
    if bitmask & common::PERM_MANAGE_ATTRIBUTES == common::PERM_MANAGE_ATTRIBUTES {
        result.push('a');
    }
    if bitmask & common::PERM_MANAGE_CHANNELS == common::PERM_MANAGE_CHANNELS {
        result.push('c');
    }
    if bitmask & common::PERM_MANAGE_MESSAGES == common::PERM_MANAGE_MESSAGES {
        result.push('m');
    }

    result
}
fn from_perm_string(input: &str, allow: &mut u8, deny: &mut u8) -> bool {
    let mut mode = '+';

    for c in input.chars() {
        if c == '+' || c == '-' || c == '=' {
            mode = c;
            continue;
        }
        let perm = match c {
            'r' => common::PERM_READ,
            'w' => common::PERM_WRITE,
            's' => common::PERM_ASSIGN_ATTRIBUTES,
            'a' => common::PERM_MANAGE_ATTRIBUTES,
            'c' => common::PERM_MANAGE_CHANNELS,
            'm' => common::PERM_MANAGE_MESSAGES,
            ' ' => continue,
            _   => return false
        };
        match mode {
            '+' => { *allow |= perm; *deny &= !perm; },
            '-' => { *allow &= !perm; *deny |= perm },
            '=' => { *allow &= !perm; *deny &= !perm }
            _   => unreachable!()
        }
    }

    true
}

fn parse_ip(input: &str) -> Option<SocketAddr> {
    let mut parts = input.split(':');
    let ip = match parts.next() {
        Some(some) => some,
        None => return None
    };
    let port = match parts.next() {
        Some(some) => match some.parse() {
            Ok(ok) => ok,
            Err(_) => return None
        },
        None => common::DEFAULT_PORT
    };
    if parts.next().is_some() {
        return None;
    }

    use std::net::ToSocketAddrs;
    match (ip, port).to_socket_addrs() {
        Ok(mut ok) => ok.next(),
        Err(_) => { eprintln!(":("); None }
    }
}
