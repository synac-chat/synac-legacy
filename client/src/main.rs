extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
extern crate termion;
extern crate common;

mod parser;

use common::Packet;
use openssl::ssl::{SslConnectorBuilder, SslMethod, SslStream, SSL_VERIFY_PEER};
use rusqlite::Connection as SqlConnection;
use rustyline::error::ReadlineError;
use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use termion::color;
use termion::cursor;
use termion::screen::AlternateScreen;

macro_rules! flush {
    () => {
        io::stdout().flush().unwrap();
    }
}

pub struct Session {
    attributes: HashMap<usize, common::Attribute>,
    channel: Option<usize>,
    channels: HashMap<usize, common::Channel>,
    id: usize,
    stream: SslStream<TcpStream>,
    users: HashMap<usize, common::User>
}
impl Session {
    pub fn new(id: usize, stream: SslStream<TcpStream>) -> Session {
        Session {
            attributes: HashMap::new(),
            channel: None,
            channels: HashMap::new(),
            id: id,
            stream: stream,
            users: HashMap::new()
        }
    }
}

fn main() {
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

    #[cfg(unix)]
    let mut nick = env::var("USER").unwrap_or("unknown".to_string());
    #[cfg(windows)]
    let mut nick = env::var("USERNAME").unwrap_or("unknown".to_string());
    #[cfg(not(any(unix, windows)))]
    let mut nick = "unknown".to_string();

    let ssl = SslConnectorBuilder::new(SslMethod::tls())
        .expect("Failed to create SSL connector D:")
        .build();
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
    let session_clone = session.clone();

    let _screen = AlternateScreen::from(io::stdout());

    println!("{}Welcome, {}", cursor::Goto(1, 1), nick);
    println!("To change your name, type");
    println!("/nick <name>");
    println!("To connect to a server, type");
    println!("/connect <ip>");
    println!();

    let (sent_sender, sent_receiver) = mpsc::sync_channel(0);

    thread::spawn(move || {
        let mut size = true;
        let mut buf = vec![0; 2];
        let mut i = 0;
        loop {
            if let Some(ref mut session) = *session_clone.lock().unwrap() {
                match session.stream.read(&mut buf[i..]) {
                    Ok(0) => break,
                    Ok(read) => {
                        i += read;
                        if i >= buf.len() {
                            if size {
                                size = false;
                                let size = common::decode_u16(&buf) as usize;
                                buf = vec![0; size];
                                i = 0;
                            } else {
                                match common::deserialize(&buf) {
                                    Ok(Packet::MessageReceive(msg)) => {
                                        if session.channel == Some(msg.channel.id) {
                                            println!("{}\r{}: {}", cursor::Restore, msg.author.name,
                                                     String::from_utf8_lossy(&msg.text));
                                            to_terminal_bottom();
                                            flush!();
                                        }
                                    },
                                    Ok(Packet::ChannelReceive(event)) => {
                                        session.channels.insert(event.inner.id, event.inner);
                                    },
                                    Ok(Packet::ChannelDeleteReceive(event)) => {
                                        session.channels.remove(&event.inner.id);
                                    },
                                    Ok(Packet::AttributeReceive(event)) => {
                                        if event.new {
                                            let pos = if let Some(old) = session.attributes.get(&event.inner.id) {
                                                Some(old.pos)
                                            } else { None };
                                            if let Some(pos) = pos {
                                                if event.inner.pos > pos {
                                                    for attr in session.attributes.values_mut() {
                                                        if attr.pos > pos && attr.pos <= event.inner.pos {
                                                            attr.pos -= 1;
                                                        }
                                                    }
                                                } else if event.inner.pos < pos {
                                                    for attr in session.attributes.values_mut() {
                                                        if attr.pos >= event.inner.pos && attr.pos < pos {
                                                            attr.pos += 1;
                                                        }
                                                    }
                                                }
                                            } else {
                                                for attr in session.attributes.values_mut() {
                                                    if attr.pos >= event.inner.pos {
                                                        attr.pos += 1;
                                                    }
                                                }
                                            }
                                        }
                                        session.attributes.insert(event.inner.id, event.inner);
                                    },
                                    Ok(Packet::AttributeDeleteReceive(event)) => {
                                        for attr in session.attributes.values_mut() {
                                            if attr.pos > event.inner.pos {
                                                attr.pos -= 1;
                                            }
                                        }
                                        session.attributes.remove(&event.inner.id);
                                    },
                                    Ok(Packet::UserReceive(event)) => {
                                        session.users.insert(event.inner.id, event.inner);
                                    },
                                    Ok(Packet::Err(common::ERR_UNKNOWN_CHANNEL)) => {
                                        println!("{}It appears this channel was deleted", cursor::Restore);
                                        to_terminal_bottom();
                                        flush!();
                                    },
                                    Ok(Packet::Err(common::ERR_UNKNOWN_ATTRIBUTE)) => {
                                        println!("{}It appears this attribute was deleted", cursor::Restore);
                                        to_terminal_bottom();
                                        flush!();
                                    },
                                    Ok(Packet::Err(common::ERR_LIMIT_REACHED)) => {
                                        println!("{}Too short or too long. No idea which", cursor::Restore);
                                        to_terminal_bottom();
                                        flush!();
                                    },
                                    Ok(Packet::Err(common::ERR_MISSING_PERMISSION)) => {
                                        println!("{}\rMissing permission", cursor::Restore);
                                        to_terminal_bottom();
                                        flush!();
                                    },
                                    Ok(Packet::Err(common::ERR_ATTR_INVALID_POS)) => {
                                        println!("{}Invalid attribute position", cursor::Restore);
                                        to_terminal_bottom();
                                        flush!();
                                    },
                                    Ok(_) => {
                                        unimplemented!();
                                    },
                                    Err(err) => {
                                        println!("Failed to deserialize message!");
                                        println!("{}", err);
                                        continue;
                                    }
                                };
                                size = true;
                                buf = vec![0; 2];
                                i = 0;
                            }
                            let _ = sent_sender.try_send(());
                        }
                    },
                    Err(_) => {}
                }
            }
            thread::sleep(Duration::from_millis(1));
            // thread::sleep(Duration::from_millis(250));
        }
    });

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        to_terminal_bottom();
        let input = match editor.readline("> ") {
            Ok(ok) => ok,
            Err(ReadlineError::Eof) |
            Err(ReadlineError::Interrupted) => break,
            Err(err) => {
                println!("Couldn't read line: {}", err);
                break;
            }
        };
        print!("{}", cursor::Restore);
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
                "nick" => {
                    usage!(1, "nick <name>");
                    nick = args.remove(0);
                    println!("Your name is now {}", nick);
                },
                "connect" => {
                    usage!(1, "connect <ip[:port]>");
                    let mut session = session.lock().unwrap();
                    if session.is_some() {
                        println!("Please disconnect first");
                        continue;
                    }

                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            println!("Could not parse IP");
                            continue;
                        }
                    };

                    let mut stmt = db.prepare("SELECT key, token FROM servers WHERE ip = ?").unwrap();
                    let mut rows = stmt.query(&[&addr.to_string()]).unwrap();

                    let public_key;
                    let mut token: Option<String> = None;
                    if let Some(row) = rows.next() {
                        let row = row.unwrap();
                        public_key = row.get(0);
                        token = row.get(1);
                    } else {
                        println!("To securely connect, we need some data from the server (\"public key\").");
                        println!("The server owner should have given you this.");
                        println!("Once you have it, enter it here:");
                        flush!();
                        let result = editor.readline("");
                        public_key = match result {
                            Err(ReadlineError::Eof) |
                            Err(ReadlineError::Interrupted) => break,
                            Ok(ok) => ok,
                            Err(err) => {
                                println!("Couldn't read line: {}", err);
                                break;
                            }
                        };

                        db.execute(
                            "INSERT INTO servers (ip, key) VALUES (?, ?)",
                            &[&addr.to_string(), &public_key]
                        ).unwrap();
                    }
                    let stream = match TcpStream::connect(addr) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!("Could not connect!");
                            println!("{}", err);
                            continue;
                        }
                    };
                    let mut stream = {
                        let mut config = ssl.configure().expect("Failed to configure SSL connector");
                        config.ssl_mut().set_verify_callback(SSL_VERIFY_PEER, move |_, cert| {
                            match cert.current_cert() {
                                Some(cert) => match cert.public_key() {
                                    Ok(pkey) => match pkey.public_key_to_pem() {
                                        Ok(pem) => {
                                            let digest = openssl::sha::sha256(&pem);
                                            let mut digest_str = String::with_capacity(64);
                                            for byte in &digest {
                                                digest_str.push_str(&format!("{:X}", byte));
                                            }
                                            use std::ascii::AsciiExt;
                                            public_key.trim().eq_ignore_ascii_case(&digest_str)
                                        },
                                        Err(_) => false
                                    },
                                    Err(_) => false
                                },
                                None => false
                            }
                        });

                        match
config.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
                        {
                            Ok(ok) => ok,
                            Err(_) => {
                                println!("Faild to validate certificate");
                                continue;
                            }
                        }
                    };

                    let mut id = None;
                    if let Some(token) = token {
                        let packet = Packet::Login(common::Login {
                            bot: false,
                            name: nick.clone(),
                            password: None,
                            token: Some(token.clone())
                        });

                        if let Err(err) = common::write(&mut stream, &packet) {
                            println!("Could not request login");
                            println!("{}", err);
                            continue;
                        }

                        match common::read(&mut stream) {
                            Ok(Packet::LoginSuccess(login)) => {
                                id = Some(login.id);
                                if login.created {
                                    println!("Tried to log in with your token: Apparently an account was created.");
                                    println!("I think you should stay away from this server. It's weird.");
                                    continue;
                                }
                                println!("Logged in as user #{}", login.id);
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID |
                                common::ERR_LOGIN_EMPTY => {},
                                common::ERR_LOGIN_BANNED => {
                                    println!("Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    println!("This account is a bot account");
                                    continue;
                                },
                                common::ERR_LIMIT_REACHED => {
                                    println!("Username too long");
                                    continue;
                                },
                                _ => {
                                    println!("The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                println!("The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                println!("Failed to read from server");
                                println!("{}", err);
                                continue;
                            }
                        }
                    }

                    if id.is_none() {
                        print!("Password: ");
                        flush!();
                        use termion::input::TermRead;
                        let pass = match io::stdin().read_passwd(&mut io::stdout()) {
                            Ok(Some(some)) => some,
                            Ok(None) => continue,
                            Err(err) => {
                                println!("Failed to read password");
                                println!("{}", err);
                                continue;
                            }
                        };
                        println!();

                        let packet = Packet::Login(common::Login {
                            bot: false,
                            name: nick.clone(),
                            password: Some(pass),
                            token: None
                        });

                        if let Err(err) = common::write(&mut stream, &packet) {
                            println!("Could not request login");
                            println!("{}", err);
                            continue;
                        }

                        match common::read(&mut stream) {
                            Ok(Packet::LoginSuccess(login)) => {
                                db.execute(
                                    "UPDATE servers SET token = ? WHERE ip = ?",
                                    &[&login.token, &addr.to_string()]
                                ).unwrap();
                                if login.created {
                                    println!("Account created");
                                }
                                id = Some(login.id);
                                println!("Logged in as user #{}", login.id);
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID => {
                                    println!("Invalid credentials");
                                    continue;
                                },
                                common::ERR_LOGIN_BANNED => {
                                    println!("Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    println!("This account is a bot account");
                                    continue;
                                },
                                common::ERR_LIMIT_REACHED => {
                                    println!("Username too long");
                                    continue;
                                },
                                _ => {
                                    println!("The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                println!("The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                println!("Failed to read from server");
                                println!("{}", err);
                                continue;
                            }
                        }
                    }
                    stream.get_ref().set_nonblocking(true).expect("Failed to make stream non-blocking");
                    *session = Some(Session::new(id.unwrap(), stream));
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
                    db.execute("DELETE FROM servers WHERE ip = ?", &[&addr.to_string()]).unwrap();
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
                            if args.len() == 3 {
                                from_perm_string(&*args[2], &mut allow, &mut deny);
                            }
                            let max = session.attributes.values().max_by_key(|item| item.pos);
                            Packet::AttributeCreate(common::AttributeCreate {
                                allow: allow,
                                deny: deny,
                                name: args.remove(1),
                                pos: max.map_or(1, |item| item.pos+1)
                            })
                        },
                        _ => { println!("Can't create that"); continue; }
                    };
                    if let Err(err) = common::write(&mut session.stream, &packet) {
                        println!("Failed to send packet");
                        println!("{}", err);
                    }
                },
                "list" => {
                    usage!(1, "list <\"attributes\"/\"channels\"/\"users\">");
                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    match &*args[0] {
                        "channels" => {
                            let mut result = String::new();
                            // Yeah, cloning this is bad... But what can I do? I need to sort!
                            // Though, I suspect this might be a shallow copy.
                            let mut channels: Vec<_> = session.channels.values().collect();
                            channels.sort_by_key(|item| &item.name);
                            for channel in channels {
                                if !result.is_empty() { result.push_str(", "); }
                                result.push('#');
                                result.push_str(&channel.name);
                            }
                            println!("{}", result);
                        },
                        "attributes" => {
                            let mut result = String::new();
                            // Read the above comment, thank you ---------------------------^
                            let mut attributes: Vec<_> = session.attributes.values().collect();
                            attributes.sort_by_key(|item| &item.pos);
                            for user in attributes {
                                if !result.is_empty() { result.push_str(", "); }
                                result.push_str(&user.name);
                            }
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
                                for attribute in &users {
                                    if attribute.ban != *banned { continue; }
                                    if !result.is_empty() { result.push_str(", "); }
                                    result.push_str(&attribute.name);
                                }
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
                            || (name.starts_with('#') && &name[1..] == channel.name)
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
                                        } else {
                                            acc.push_str(&id.to_string());
                                        }
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
                            println!("{}{}Joined channel #{}", termion::clear::All, cursor::Goto(1, 1), channel.name);
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
                "delete" => {
                    usage!(2, "delete <\"attribute\"/\"channel\"> <name>");

                    let mut session = session.lock().unwrap();
                    let session = require_session!(session);
                    let mut name = &*args[1];

                    let mut packet = None;
                    match &*args[0] {
                        "attribute" => for attribute in session.attributes.values() {
                            if attribute.name == name {
                                packet = Some(Packet::AttributeDelete(common::AttributeDelete {
                                    id: attribute.id
                                }));
                                break;
                            }
                        },
                        "channel" => {
                            if name.starts_with('#') {
                                name = &name[1..];
                            }
                            for channel in session.channels.values() {
                                if channel.name == name {
                                    packet = Some(Packet::ChannelDelete(common::ChannelDelete {
                                        id: channel.id
                                    }));
                                    break;
                                }
                            }
                        },
                        _ => {
                            println!("Can't delete that");
                            continue;
                        }
                    }
                    match packet {
                        None => println!("Nothing found with that name"),
                        Some(packet) => {
                            if let Err(err) = common::write(&mut session.stream, &packet) {
                                println!("Oh no could not delete");
                                println!("{}", err);
                            }
                        }
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
                    print!("{}{}: {}{}", color::Fg(color::LightBlack), nick, input, color::Fg(color::Reset));
                    flush!();
                    let packet = Packet::MessageCreate(common::MessageCreate {
                        channel: channel,
                        text: input.into_bytes()
                    });

                    if let Err(err) = common::write(&mut session.stream, &packet) {
                        println!("\rFailed to deliver message");
                        println!("{}", err);
                        continue;
                    }
                } else {
                    println!("No channel specified. See /create channel, /list channels and /join");
                    continue;
                }
            }
        }
        // Could only happen if message was sent
        if let Err(mpsc::RecvTimeoutError::Timeout) = sent_receiver.recv_timeout(Duration::from_secs(2)) {
            println!("Failed to verify message was received...");
        }
    }
}

fn to_terminal_bottom() {
    match termion::terminal_size() {
        Ok((_, height)) => {
            print!("{}{}", cursor::Save, cursor::Goto(0, height-1));
        },
        Err(_) => {}
    }
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
    if bitmask & common::PERM_MANAGE_CHANNELS == common::PERM_MANAGE_CHANNELS {
        result.push('c');
    }
    if bitmask & common::PERM_MANAGE_ATTRIBUTES == common::PERM_MANAGE_ATTRIBUTES {
        result.push('a');
    }

    result
}
fn from_perm_string(input: &str, allow: &mut u8, deny: &mut u8) -> bool {
    let mut mode = '+';

    for c in input.chars() {
        if c == '+' || c == '-' || c == '=' {
            mode = c;
        }
        let perm = match c {
            'r' => common::PERM_READ,
            'w' => common::PERM_WRITE,
            'c' => common::PERM_MANAGE_CHANNELS,
            'a' => common::PERM_MANAGE_ATTRIBUTES,
            _   => return false
        };
        match mode {
            '+' => *allow |= perm,
            '-' => *deny |= perm,
            '=' => { *allow &= !perm; *deny &= !perm }
            _   => unreachable!()
        }
    }

    true
}

fn parse_ip(input: &str) -> Option<SocketAddr> {
    let mut parts = input.split(":");
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
        Ok(ok) => ok,
        Err(_) => return None
    }.next()
}
