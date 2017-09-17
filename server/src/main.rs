extern crate bcrypt;
extern crate chrono;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;

use common::Packet;
use futures::{Future, Stream};
use openssl::pkcs12::Pkcs12;
use openssl::rand;
use openssl::ssl::{SslMethod, SslAcceptorBuilder};
use rusqlite::{Connection as SqlConnection, Row as SqlRow};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use chrono::Utc;
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use tokio_io::io;
use tokio_openssl::{SslAcceptorExt, SslStream};

macro_rules! attempt_or {
    ($result:expr, $fail:block) => {
        match $result {
            Ok(ok) => ok,
            Err(_) => {
                $fail
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    limit_user_name_min: usize,
    limit_user_name_max: usize,
    limit_channel_name_min: usize,
    limit_channel_name_max: usize,
    limit_attribute_name_min: usize,
    limit_attribute_name_max: usize,
    limit_attribute_amount_max: usize,
    limit_message_min: usize,
    limit_message_max: usize
}

fn main() {
    let db = attempt_or!(SqlConnection::open("data.sqlite"), {
        eprintln!("SQLite initialization failed.");
        eprintln!("Is the file corrupt?");
        eprintln!("Is the file permissions badly configured?");
        eprintln!("Just guessing here ¯\\_(ツ)_/¯");
        return;
    });
    db.execute("CREATE TABLE IF NOT EXISTS users (
                    attributes  TEXT NOT NULL DEFAULT '',
                    bot         INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    nick        TEXT,
                    password    TEXT NOT NULL,
                    token       TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS channels (
                    allow   TEXT NOT NULL DEFAULT '',
                    deny    TEXT NOT NULL DEFAULT '',
                    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name    TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS messages (
                    author      INTEGER NOT NULL,
                    channel     INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    text        BLOB NOT NULL,
                    timestamp   INTEGER NOT NULL,
                    timestamp_edit  INTEGER
                )", &[])
        .expect("SQLite table creation failed");

    let mut args = env::args();
    args.next();
    let port = args.next().map(|val| match val.parse() {
        Ok(ok) => ok,
        Err(_) => {
            eprintln!("Warning: Supplied port is not a valid number.");
            eprintln!("Using default.");
            common::DEFAULT_PORT
        }
    }).unwrap_or_else(|| {
        println!("TIP: You can change port by putting it as a command line argument.");
        common::DEFAULT_PORT
    });

    println!("Setting up...");

    let identity = {
        let mut file = attempt_or!(File::open("cert.pfx"), {
            eprintln!("Failed to open certificate file.");
            eprintln!("Are you in the right directory?");
            eprintln!("Do I have the required permission to read that file?");
            return;
        });
        let mut data = Vec::new();
        attempt_or!(file.read_to_end(&mut data), {
            eprintln!("Failed to read from certificate file.");
            eprintln!("I have no idea how this could happen...");
            return;
        });
        let identity = attempt_or!(Pkcs12::from_der(&data), {
            eprintln!("Failed to deserialize certificate file.");
            eprintln!("Is the it corrupt?");
            return;
        });
        attempt_or!(identity.parse(""), {
            eprintln!("Failed to parse certificate file.");
            eprintln!("Is the it corrupt?");
            eprintln!("Did you password protect it?");
            return;
        })
    };
    let ssl = SslAcceptorBuilder::mozilla_intermediate(
        SslMethod::tls(),
        &identity.pkey,
        &identity.cert,
        &identity.chain
    ).expect("Creating SSL acceptor failed D:").build();

    {
        let pem = openssl::sha::sha256(&identity.pkey.public_key_to_pem().unwrap());
        let mut pem_str = String::with_capacity(64);
        for byte in &pem {
            pem_str.push_str(&format!("{:X}", byte));
        }
        println!("Almost there! To secure your users' connection,");
        println!("you will have to send a piece of data manually.");
        println!("The text is as follows:");
        println!("{}", pem_str);
    }

    let config: Config;
    {
        let path = Path::new("optional-config.json");
        if path.exists() {
            let mut file = attempt_or!(File::open(path), {
                eprintln!("Failed to open config");
                return;
            });
            config = attempt_or!(serde_json::from_reader(&mut file), {
                eprintln!("Failed to deserialize config");
                return;
            });
            macro_rules! is_invalid {
                ($min:ident, $max:ident, $hard_max:expr) => {
                    config.$min > config.$max || config.$min == 0 || config.$max > $hard_max
                }
            }
            if is_invalid!(limit_user_name_min, limit_user_name_max, common::LIMIT_USER_NAME)
                || is_invalid!(limit_channel_name_min, limit_channel_name_max, common::LIMIT_CHANNEL_NAME)
                || is_invalid!(limit_attribute_name_min, limit_attribute_name_max, common::LIMIT_ATTR_NAME)
                || config.limit_attribute_amount_max > common::LIMIT_ATTR_AMOUNT
                || is_invalid!(limit_message_min, limit_message_max, common::LIMIT_MESSAGE) {

                eprintln!("Your config is exceeding a hard limit");
                return;
            }
        } else {
            config = Config {
                limit_user_name_min: 1,
                limit_user_name_max: 32,
                limit_channel_name_min: 1,
                limit_channel_name_max: 32,
                limit_attribute_name_min: 1,
                limit_attribute_name_max: 32,
                limit_attribute_amount_max: 128,
                limit_message_min: 1,
                limit_message_max: 1024
            };

            match File::create(path) {
                Ok(mut file) => if let Err(err) = serde_json::to_writer(&mut file, &config) {
                    eprintln!("Failed to generate default config: {}", err);
                },
                Err(err) => eprintln!("Failed to create default config: {}", err)
            }
        }
    }

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });

    let config = Rc::new(config);
    let conn_id = Rc::new(RefCell::new(0usize));
    let db = Rc::new(db);
    let handle = Rc::new(handle);
    let sessions = Rc::new(RefCell::new(HashMap::new()));

    println!("I'm alive!");

    let server = listener.incoming().for_each(|(conn, _)| {
        use tokio_io::AsyncRead;

        let config_clone = config.clone();
        let conn_id_clone = conn_id.clone();
        let db_clone = db.clone();
        let handle_clone = handle.clone();
        let sessions_clone = sessions.clone();

        let accept = ssl.accept_async(conn).map_err(|_| ()).and_then(move |conn| {
            let (reader, writer) = conn.split();
            let reader = BufReader::new(reader);
            let writer = BufWriter::new(writer);

            let my_conn_id = *conn_id_clone.borrow();
            *conn_id_clone.borrow_mut() += 1;

            sessions_clone.borrow_mut().insert(my_conn_id, Session {
                id: None,
                writer: writer
            });

            handle_client(
                config_clone,
                my_conn_id,
                db_clone,
                handle_clone,
                reader,
                sessions_clone
            );

            Ok(())
        });
        handle.spawn(accept);
        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn gen_token() -> Result<String, openssl::error::ErrorStack> {
    let mut token = vec![0; 64];
    rand::rand_bytes(&mut token)?;
    for byte in token.iter_mut() {
        *byte = TOKEN_CHARS[*byte as usize % TOKEN_CHARS.len()];
    }

    Ok(unsafe { String::from_utf8_unchecked(token) })
}
fn get_list(input: &str) -> Vec<usize> {
    input.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("The database is broken. Congratz. You made me crash."))
        .collect()
}
fn to_list(input: &[usize]) -> String {
    let mut result = String::new();
    let mut first = true;
    for i in input {
        if first {
            first = false;
        } else {
            result.push(',');
        }
        result.push_str(&i.to_string());
    }
    result
}
fn get_user(db: &SqlConnection, id: usize) -> Option<common::User> {
    let mut stmt = db.prepare("SELECT attributes, bot, id, name, nick FROM users WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();

        Some(common::User {
            attributes: get_list(&row.get::<_, String>(0)),
            bot: row.get(1),
            id: row.get::<_, i64>(2) as usize,
            name: row.get(3),
            nick: row.get(4)
        })
    } else {
        None
    }
}
fn get_channel(db: &SqlConnection, id: usize) -> Option<common::Channel> {
    let mut stmt = db.prepare("SELECT * FROM channels WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();

        Some(get_channel_by_fields(row))
    } else {
        None
    }
}
fn get_channel_by_fields(row: SqlRow) -> common::Channel {
    common::Channel {
        allow: get_list(&row.get::<_, String>(0)),
        deny:  get_list(&row.get::<_, String>(1)),
        id: row.get::<_, i64>(2) as usize,
        name: row.get(3)
    }
}
// TODO These will probably be useful some time
// fn get_message(db: &SqlConnection, id: usize) -> Option<common::Message> {
//     let mut stmt = db.prepare("SELECT author, channel, id, text, timestamp, timestamp_edit FROM messages WHERE id = ?")
//         .unwrap();
//     let mut rows = stmt.query(&[&(id as i64)]).unwrap();
//     if let Some(row) = rows.next() {
//         let row = row.unwrap();
//         get_message_by_fields(row)
//     } else {
//         None
//     }
// }
// fn get_message_by_fields(row: SqlRow) -> Option<common::Message> {
//     Some(common::Message {
//         author: row.get::<_, i64>(0) as usize,
//         channel: row.get::<_, i64>(1) as usize,
//         id: row.get::<_, i64>(2) as usize,
//         text: row.get(3),
//         timestamp: row.get(4),
//         timestamp_edit: row.get(5)
//     })
// }

pub const TOKEN_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Session {
    id: Option<usize>,
    writer: BufWriter<tokio_io::io::WriteHalf<SslStream<TcpStream>>>
}

fn handle_client(
        config: Rc<Config>,
        conn_id: usize,
        db: Rc<SqlConnection>,
        handle: Rc<Handle>,
        reader: BufReader<tokio_io::io::ReadHalf<SslStream<TcpStream>>>,
        sessions: Rc<RefCell<HashMap<usize, Session>>>
    ) {
    macro_rules! close {
        () => {
            println!("Closing connection");
            sessions.borrow_mut().remove(&conn_id);
            return Ok(());
        }
    }

    let handle_clone = handle.clone();
    let length = io::read_exact(reader, [0; 2])
        .map_err(|_| ())
        .and_then(move |(reader, bytes)| {
            let size = common::decode_u16(&bytes) as usize;

            if size == 0 {
                close!();
            }

            let handle_clone_clone_ugh = handle_clone.clone();
            let lines = io::read_exact(reader, vec![0; size])
                .map_err(|_| ())
                .and_then(move |(reader, bytes)| {
                    let packet = match common::deserialize(&bytes) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Failed to deserialize message from client: {}", err);
                            close!();
                        }
                    };

                    macro_rules! get_id {
                        () => {
                            match sessions.borrow()[&conn_id].id {
                                Some(some) => some,
                                None => { close!(); }
                            }
                        }
                    }

                    let mut broadcast = false;
                    let mut reply = None;

                    match packet {
                        Packet::Close => { close!(); }
                        Packet::Login(login) => {
                            let mut stmt = db.prepare("SELECT id, bot, token, password FROM users WHERE name = ?").unwrap();
                            let mut rows = stmt.query(&[&login.name]).unwrap();

                            if let Some(row) = rows.next() {
                                let row = row.unwrap();

                                let row_id = row.get::<_, i64>(0) as usize;
                                let row_bot: bool = row.get(1);
                                let row_token:    String = row.get(2);
                                let row_password: String = row.get(3);

                                if row_bot == login.bot {
                                     if let Some(password) = login.password {
                                        let valid = attempt_or!(bcrypt::verify(&password, &row_password), {
                                            close!();
                                        });
                                        if valid {
                                            let token = attempt_or!(gen_token(), {
                                                eprintln!("Failed to generate random token");
                                                close!();
                                            });
                                            db.execute(
                                                "UPDATE users SET token = ? WHERE id = ?",
                                                &[&token, &(row_id as i64)]
                                            ).unwrap();
                                            reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                                created: false,
                                                id: row_id,
                                                token: token
                                            }));
                                            sessions.borrow_mut().get_mut(&conn_id).unwrap().id = Some(row_id);
                                        } else {
                                            reply = Some(Packet::Err(common::ERR_LOGIN_INVALID));
                                        }
                                    } else if let Some(token) = login.token {
                                        if token == row_token {
                                            reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                                created: false,
                                                id: row_id,
                                                token: token
                                            }));
                                            sessions.borrow_mut().get_mut(&conn_id).unwrap().id = Some(row_id);
                                        } else {
                                            reply = Some(Packet::Err(common::ERR_LOGIN_INVALID));
                                        }
                                    } else {
                                        reply = Some(Packet::Err(common::ERR_LOGIN_EMPTY));
                                    }
                               } else {
                                    reply = Some(Packet::Err(common::ERR_LOGIN_BOT));
                                }
                            } else if let Some(password) = login.password {
                                if login.name.len() < config.limit_user_name_min
                                    || login.name.len() > config.limit_user_name_min {
                                    reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                                } else {
                                    let password = attempt_or!(bcrypt::hash(&password, bcrypt::DEFAULT_COST), {
                                        eprintln!("Failed to hash password");
                                        close!();
                                    });
                                    let token = attempt_or!(gen_token(), {
                                        eprintln!("Failed to generate random token");
                                        close!();
                                    });
                                    db.execute(
                                        "INSERT INTO users (bot, name, password, token) VALUES (?, ?, ?, ?)",
                                        &[&login.bot, &login.name, &password, &token]
                                    ).unwrap();
                                    let id = db.last_insert_rowid() as usize;
                                    reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                        created: true,
                                        id: id,
                                        token: token
                                    }));
                                    sessions.borrow_mut().get_mut(&conn_id).unwrap().id = Some(id);
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_LOGIN_EMPTY));
                            }
                        },
                        Packet::MessageCreate(msg) => {
                            let timestamp = Utc::now().timestamp();
                            let id = get_id!();
                            let user = get_user(&db, id).unwrap();
                            if msg.text.len() < config.limit_message_min
                                || msg.text.len() > config.limit_message_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else if let Some(channel) = get_channel(&db, msg.channel) {
                                db.execute(
                                    "INSERT INTO messages (author, channel, text, timestamp) VALUES (?, ?, ?, ?)",
                                    &[&(id as i64), &(msg.channel as i64), &msg.text, &timestamp]
                                ).unwrap();
                                reply = Some(Packet::MessageReceive(common::MessageReceive {
                                    author: user,
                                    channel: channel,
                                    id: db.last_insert_rowid() as usize,
                                    text: msg.text,
                                    timestamp: timestamp,
                                    timestamp_edit: None
                                }));
                                broadcast = true;
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_CHANNEL));
                            }
                        },
                        Packet::ChannelCreate(channel) => {
                            db.execute(
                                "INSERT INTO channels (allow, deny, name) VALUES (?, ?, ?)",
                                &[&to_list(&channel.allow), &to_list(&channel.deny), &channel.name]
                            ).unwrap();

                            if channel.name.len() < config.limit_channel_name_min
                                || channel.name.len() > config.limit_channel_name_max
                                || channel.allow.len() > config.limit_attribute_amount_max
                                || channel.deny.len() > config.limit_attribute_amount_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else {
                                reply = Some(Packet::ChannelReceive(common::ChannelReceive {
                                    inner: common::Channel {
                                        allow: channel.allow,
                                        deny:  channel.deny,
                                        id: db.last_insert_rowid() as usize,
                                        name: channel.name
                                    }
                                }));
                            }
                            broadcast = true;
                        },
                        _ => unimplemented!(),
                    }

                    let reply = match reply {
                        Some(some) => some,
                        None => {
                            handle_client(
                                config,
                                conn_id,
                                db,
                                handle_clone_clone_ugh,
                                reader,
                                sessions
                            );
                            return Ok(());
                        }
                    };

                    // Yes, I should be using io::write_all here - I very much agree.
                    // However, io::write_all takes a writer, not a reference to one (understandable).
                    // Sure, I could solve that with an Option (which I used to do).
                    // However, if two things would try to write at once we'd have issues...

                    if broadcast {
                        let encoded = attempt_or!(common::serialize(&reply), {
                            eprintln!("Failed to serialize message");
                            close!();
                        });
                        assert!(encoded.len() <= std::u16::MAX as usize);
                        let size = common::encode_u16(encoded.len() as u16);
                        sessions.borrow_mut().retain(|i, s| {
                            match s.writer.write_all(&size)
                                .and_then(|_| s.writer.write_all(&encoded))
                                .and_then(|_| s.writer.flush()) {
                                Ok(ok) => ok,
                                Err(err) => {
                                    if err.kind() == std::io::ErrorKind::BrokenPipe {
                                        return false;
                                    } else {
                                        eprintln!("Failed to deliver message to User #{}", i);
                                        eprintln!("Error kind: {}", err);
                                    }
                                }
                            }
                            true
                        });
                    } else {
                        let mut sessions = sessions.borrow_mut();
                        let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

                        attempt_or!(common::write(writer, &reply), {
                            eprintln!("Failed to send reply");
                            close!();
                        });
                    }

                    handle_client(
                        config,
                        conn_id,
                        db,
                        handle_clone_clone_ugh,
                        reader,
                        sessions
                    );

                    Ok(())
                });

            handle_clone.spawn(lines);
            Ok(())
        });

    handle.spawn(length);
}
