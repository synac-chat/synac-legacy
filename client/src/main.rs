#![cfg_attr(feature = "cursive", feature(fnbox))]

extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
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
use std::time::{Duration, Instant};

#[cfg(feature = "termion")]
mod frontend_minimal;
#[cfg(feature = "cursive")]
mod frontend_cursive;
mod connect;
mod listener;
mod parser;

#[cfg(feature = "termion")]
use frontend_minimal as frontend;
#[cfg(feature = "cursive")]
use frontend_cursive as frontend;

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum LogEntryId {
    Message(usize),
    None,
    Sending
}

pub struct Session {
    addr: SocketAddr,
    channel: Option<usize>,
    channels: HashMap<usize, common::Channel>,
    groups: HashMap<usize, common::Group>,
    id: usize,
    last: Option<(usize, Vec<u8>)>,
    stream: SslStream<TcpStream>,
    typing: HashMap<(usize, usize), Instant>,
    users: HashMap<usize, common::User>
}
impl Session {
    pub fn new(addr: SocketAddr, id: usize, stream: SslStream<TcpStream>) -> Session {
        Session {
            addr: addr,
            channel: None,
            channels: HashMap::new(),
            groups: HashMap::new(),
            id: id,
            last: None,
            stream: stream,
            typing: HashMap::new(),
            users: HashMap::new()
        }
    }
}

fn main() {
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
    let screen = Arc::new(frontend::Screen::new());

    // See https://github.com/rust-lang/rust/issues/35853
    macro_rules! println {
        () => { screen.log(String::new()); };
        ($($arg:expr),*) => { screen.log(format!($($arg),*)); };
    }
    macro_rules! readline {
        ($break:block) => {
            match screen.readline(None) {
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
    db.execute("CREATE TABLE IF NOT EXISTS data (
                    key     TEXT NOT NULL UNIQUE,
                    value   TEXT NOT NULL
                )", &[])
        .expect("Couldn't create SQLite table");

    let mut nick = {
        let mut stmt = db.prepare("SELECT value FROM data WHERE key = 'nick'").unwrap();
        let mut rows = stmt.query(&[]).unwrap();
        if let Some(row) = rows.next() {
            row.unwrap().get(0)
        } else {
            #[cfg(unix)]
            { env::var("USER").unwrap_or_else(|_| "unknown".to_string()) }
            #[cfg(windows)]
            { env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string()) }
            #[cfg(not(any(unix, windows)))]
            { String::from("unknown") }
        }
    };

    let db = Arc::new(Mutex::new(db));

    let ssl = SslConnectorBuilder::new(SslMethod::tls())
        .expect("Failed to create SSL connector D:")
        .build();

    macro_rules! write {
        ($session:expr, $packet:expr, $break:block) => {
            if connect::write(&db.lock().unwrap(), &nick, &$packet, &*screen, $session, &ssl) {
                $break
            }
        }
    }

    println!("Welcome, {}", nick);
    println!("To quit, type /quit");
    println!("To change your name, type");
    println!("/nick <name>");
    println!("To connect to a server, type");
    println!("/connect <ip>");
    println!();

    let (tx_sent, rx_sent) = mpsc::sync_channel(0);
    let (tx_stop, rx_stop) = mpsc::channel();

    let db_clone      = Arc::clone(&db);
    let screen_clone  = Arc::clone(&screen);
    let session_clone = Arc::clone(&session);
    let thread = thread::spawn(move || {
        listener::listen(db_clone, screen_clone, tx_sent, session_clone, rx_stop);
    });

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        screen.repaint();
        let input = {
            let session_clone = Arc::clone(&session);
            let mut last: Option<Instant> = None;
            let timeout = Duration::from_secs(common::TYPING_TIMEOUT as u64 / 2);
            match screen.readline(Some(Box::new(move |_| {
                if let Some(ref mut session) = *session_clone.lock().unwrap() {
                    if let Some(channel) = session.channel {
                        if last.is_none() || last.unwrap().elapsed() >= timeout {
                            let packet = Packet::Typing(common::Typing {
                                channel: channel
                            });
                            let _ = common::write(&mut session.stream, &packet);
                            last = Some(Instant::now());
                        }
                    }
                }
            }))) {
                Ok(ok) => ok,
                Err(_) => break
            }
        };
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
                "ban" | "unban" => {
                    usage!(1, "ban/unban <user id>");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let id = match args[0].parse() {
                        Ok(ok) => ok,
                        Err(_) => {
                            println!("Failed to parse ID");
                            continue;
                        }
                    };

                    if !session.users.contains_key(&id) {
                        println!("No such user");
                        continue;
                    }

                    let packet = Packet::UserUpdate(common::UserUpdate {
                        ban: Some(command == "ban"),
                        groups: None,
                        id: id
                    });
                    write!(session, packet, { continue; })
                },
                "connect" => {
                    usage!(1, "connect <ip[:port]>");
                    let mut session = session.lock().unwrap();
                    if session.is_some() {
                        println!("You have to disconnect before doing that.");
                        continue;
                    }

                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            println!("Could not parse IP");
                            continue;
                        }
                    };
                    *session = connect::connect(addr, &db.lock().unwrap(), &nick, &screen, &ssl);
                },
                "create" => {
                    usage_min!(2, "create <\"group\"/\"channel\"> <name> [data]");
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
                                overrides: HashMap::new(),
                                name: name
                            })
                        },
                        "group" => {
                            usage_max!(3, "create group <name> [data]");
                            let (mut allow, mut deny) = (0, 0);
                            if args.len() == 3 && !from_perm_string(&*args[2], &mut allow, &mut deny) {
                                println!("Invalid permission string");
                                continue;
                            }
                            let max = session.groups.values().max_by_key(|item| item.pos);
                            Packet::GroupCreate(common::GroupCreate {
                                allow: allow,
                                deny: deny,
                                name: args.remove(1),
                                pos: max.map_or(1, |item| item.pos+1),
                                unassignable: false
                            })
                        },
                        _ => { println!("Unable to create that"); continue; }
                    };
                    write!(session, packet, { continue; })
                },
                "delete" => {
                    usage!(2, "delete <\"group\"/\"channel\"/\"message\"> <id>");

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
                        "group" => if session.groups.contains_key(&id) {
                            Some(Packet::GroupDelete(common::GroupDelete {
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
                            println!("Unable to delete that");
                            continue;
                        }
                    };
                    if let Some(packet) = packet {
                        write!(session, packet, { continue; })
                    } else {
                        println!("Nothing with that ID exists");
                    }
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
                            println!("Invalid IP");
                            continue;
                        }
                    };
                    db.lock().unwrap().execute("DELETE FROM servers WHERE ip = ?", &[&addr.to_string()]).unwrap();
                },
                "info" => {
                    usage!(1, "info <group or channel name>");
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
                            for (id, &(allow, deny)) in &channel.overrides {
                                println!("Permission override: Role #{} = {}", id, to_perm_string(allow, deny));
                            }
                        }
                    }
                    for group in session.groups.values() {
                        if name == group.name || Ok(group.id) == id {
                            println!("Group {}", group.name);
                            println!("Permission: {}", to_perm_string(group.allow, group.deny));
                            println!("ID: #{}", group.id);
                            println!("Position: {}", group.pos);
                        }
                    }
                    for user in session.users.values() {
                        if name == user.name || Ok(user.id) == id {
                            println!("User {}", user.name);
                            println!(
                                "Groups: [{}]",
                                user.groups.iter()
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

                    let mut packet = None;
                    for channel in session.channels.values() {
                        if channel.name == name {
                            session.channel = Some(channel.id);
                            screen.clear();
                            println!("Joined channel #{}", channel.name);
                            packet = Some(Packet::MessageList(common::MessageList {
                                after: None,
                                before: None,
                                channel: channel.id,
                                limit: common::LIMIT_MESSAGE_LIST
                            }));
                            break;
                        }
                    }
                    if let Some(packet) = packet {
                        write!(session, packet, { continue; });
                    } else {
                        println!("No channel found with that name");
                    }
                },
                "list" => {
                    usage!(1, "list <\"groups\"/\"channels\"/\"users\">");
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
                        "groups" => {
                            // Read the above comment, thank you ---------------------------^
                            let mut groups: Vec<_> = session.groups.values().collect();
                            groups.sort_by_key(|item| &item.pos);

                            let result = groups.iter().fold(String::new(), |mut acc, group| {
                                if !acc.is_empty() { acc.push_str(", "); }
                                acc.push_str(&group.name);
                                acc
                            });
                            println!("{}", result);
                        },
                        "users" => {
                            // something something above comment
                            let mut users: Vec<_> = session.users.values().collect();
                            users.sort_by_key(|item| &item.name);

                            for banned in &[false, true] {
                                if *banned {
                                    println!("Banned:");
                                }
                                println!("{}", users.iter().fold(String::new(), |mut acc, user| {
                                    if user.ban == *banned {
                                        if !acc.is_empty() { acc.push_str(", "); }
                                        acc.push_str(&user.name);
                                    }
                                    acc
                                }));
                            }
                        },
                        _ => println!("Unable to list that")
                    }
                },
                "nick" => {
                    usage!(1, "nick <name>");
                    nick = args.remove(0);

                    db.lock().unwrap().execute(
                        "REPLACE INTO data (key, value) VALUES ('nick', ?)",
                        &[&nick]
                    ).unwrap();

                    let mut session = session.lock().unwrap();
                    if let Some(ref mut session) = *session {
                        let packet = Packet::LoginUpdate(common::LoginUpdate {
                            name: Some(nick.clone()),
                            password_current: None,
                            password_new: None,
                            reset_token: false
                        });
                        write!(session, packet, { continue; })
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
                        write!(session, packet, { continue; })
                    }
                    let _ = rx_sent.recv_timeout(Duration::from_secs(10));
                },
                "quit" => break,
                "update" => {
                    usage!(2, "update <\"group\"/\"channel\"> <id>");

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
                        "group" => if let Some(group) = session.groups.get(&id) {
                            let (mut allow, mut deny) = (group.allow, group.deny);

                            println!("Editing: {}", group.name);
                            println!("(Press enter to keep current value)");
                            println!();
                            println!("Name [{}]: ", group.name);

                            let name = readline!({ continue; });
                            let mut name = name.trim();
                            if name.is_empty() { name = &group.name };

                            println!("Permission [{}]: ", to_perm_string(allow, deny));
                            let perms = readline!({ continue; });
                            if !from_perm_string(&perms, &mut allow, &mut deny) {
                                println!("Invalid permission string");
                                continue;
                            }

                            println!("Position [{}]: ", group.pos);
                            let pos = readline!({ continue; });
                            let pos = pos.trim();
                            let pos = if pos.is_empty() {
                                group.pos
                            } else {
                                match pos.parse() {
                                    Ok(ok) => ok,
                                    Err(_) => {
                                        println!("Not a valid number");
                                        continue;
                                    }
                                }
                            };

                            Some(Packet::GroupUpdate(common::GroupUpdate {
                                inner: common::Group {
                                    allow: allow,
                                    deny: deny,
                                    id: group.id,
                                    name: name.to_string(),
                                    pos: pos,
                                    unassignable: group.unassignable
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

                            let overrides = match screen.get_channel_overrides(channel.overrides.clone(), &session) {
                                Ok(ok) => ok,
                                Err(_) => continue
                            };

                            Some(Packet::ChannelUpdate(common::ChannelUpdate {
                                inner: common::Channel {
                                    id: channel.id,
                                    name: name.to_string(),
                                    overrides: overrides
                                },
                                keep_overrides: false
                            }))
                        } else { None },
                        "user" => if let Some(user) = session.users.get(&id) {
                            let groups = match screen.get_user_groups(user.groups.clone(), &session) {
                                Ok(ok) => ok,
                                Err(_) => continue
                            };
                            Some(Packet::UserUpdate(common::UserUpdate {
                                ban: None,
                                groups: Some(groups),
                                id: id
                            }))
                        } else { None },
                        _ => {
                            println!("Unable to delete that");
                            continue;
                        }
                    };
                    if let Some(packet) = packet {
                        write!(session, packet, { continue; })
                    } else {
                        println!("Nothing with that ID exists");
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
                println!("You are not connected to a server");
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

                    write!(session, packet, { continue; })
                } else {
                    println!("No channel specified. See /create channel, /list channels and /join");
                    continue;
                }
            }
        }
    }
    tx_stop.send(()).unwrap();
    if let Some(ref mut session) = *session.lock().unwrap() {
        let _ = common::write(&mut session.stream, &Packet::Close);
    }
    thread.join().unwrap();
    screen.stop();
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
    if bitmask & common::PERM_ASSIGN_GROUPS == common::PERM_ASSIGN_GROUPS {
        result.push('s');
    }
    if bitmask & common::PERM_MANAGE_GROUPS == common::PERM_MANAGE_GROUPS {
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

            's' => common::PERM_ASSIGN_GROUPS,
            'c' => common::PERM_MANAGE_CHANNELS,
            'a' => common::PERM_MANAGE_GROUPS,
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
        Err(_) => { println!(":("); None }
    }
}

fn get_typing_string<I, V>(mut people: I, len: usize) -> String
    where I: Iterator<Item = V>,
          V: AsRef<str> {
    macro_rules! next {
        () => { people.next().unwrap().as_ref() }
    }
    match len {
        n if n > 500 => format!("(╯°□°）╯︵ ┻━┻"),
        n if n > 100 => format!("A crap ton of people are typing"),
        n if n > 50 => format!("Over 50 people are typing"),
        n if n > 10 => format!("Over 10 people are typing"),
        n if n > 3 => format!("Several people are typing"),
        3 => format!("{}, {} and {} are typing", next!(), next!(), next!()),
        2 => format!("{} and {} are typing", next!(), next!()),
        1 => format!("{} is typing", next!()),
        _ => String::new()
    }
}
