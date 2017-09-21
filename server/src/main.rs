extern crate bcrypt;
extern crate chrono;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
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
    owner_id: usize,
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
                    ban         INTEGER NOT NULL DEFAULT 0,
                    bot         INTEGER NOT NULL,
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    password    TEXT NOT NULL,
                    token       TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS bans (
                    ip  TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS attributes (
                    allow   INTEGER NOT NULL,
                    deny    INTEGER NOT NULL,
                    id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name    TEXT NOT NULL,
                    pos     INTEGER NOT NULL,
                    unassignable    INTEGER NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("INSERT OR IGNORE INTO attributes VALUES (3, 0, 1, '@humans', 0, 1)", &[]).unwrap();
    db.execute("INSERT OR IGNORE INTO attributes VALUES (3, 0, 2, '@bots',   0, 1)", &[]).unwrap();
    db.execute("CREATE TABLE IF NOT EXISTS channels (
                    id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
    db.execute("CREATE TABLE IF NOT EXISTS overrides (
                    allow       INTEGER NOT NULL,
                    attribute   INTEGER NOT NULL,
                    channel     INTEGER NOT NULL,
                    deny        INTEGER NOT NULL
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
            pem_str.push_str(&format!("{:0X}", byte));
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
                owner_id: 1,
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
                Ok(mut file) => if let Err(err) = serde_json::to_writer_pretty(&mut file, &config) {
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

    let server = listener.incoming().for_each(|(conn, addr)| {
        use tokio_io::AsyncRead;

        let config_clone = Rc::clone(&config);
        let conn_id_clone = Rc::clone(&conn_id);
        let db_clone = Rc::clone(&db);
        let handle_clone = Rc::clone(&handle);
        let sessions_clone = Rc::clone(&sessions);

        let accept = ssl.accept_async(conn).map_err(|_| ()).and_then(move |conn| {
            let (reader, writer) = conn.split();
            let reader = BufReader::new(reader);
            let mut writer = BufWriter::new(writer);

            {
                let mut stmt = db_clone.prepare_cached("SELECT ip FROM bans").unwrap();
                let mut rows = stmt.query(&[]).unwrap();

                while let Some(row) = rows.next() {
                    let ban = row.unwrap().get::<_, String>(0).parse();

                    if Ok(addr.ip()) == ban {
                        write(&mut writer, Packet::Err(common::ERR_LOGIN_BANNED));
                        return Ok(());
                    }
                }
            }

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

pub const TOKEN_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const RESERVED_ROLES: usize = 2;

fn gen_token() -> Result<String, openssl::error::ErrorStack> {
    let mut token = vec![0; 64];
    rand::rand_bytes(&mut token)?;
    for byte in &mut token {
        *byte = TOKEN_CHARS[*byte as usize % TOKEN_CHARS.len()];
    }

    Ok(unsafe { String::from_utf8_unchecked(token) })
}
fn has_perm(config: &Config, user: usize, bitmask: u8, perm: u8) -> bool {
    config.owner_id == user || bitmask & perm == perm
}
fn get_list(input: &str) -> Vec<usize> {
    input.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("The database is broken. Congratz. You made me crash."))
        .collect()
}
fn from_list(input: &[usize]) -> String {
    input.iter().fold(String::new(), |mut acc, item| {
        if !acc.is_empty() { acc.push(','); }
        acc.push_str(&item.to_string());
        acc
    })
}
fn get_user(db: &SqlConnection, id: usize) -> Option<common::User> {
    let mut stmt = db.prepare_cached("SELECT * FROM users WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    if let Some(row) = rows.next() {
        Some(get_user_by_fields(&row.unwrap()))
    } else {
        None
    }
}
fn get_user_by_fields(row: &SqlRow) -> common::User {
    common::User {
        attributes: get_list(&row.get::<_, String>(0)),
        ban: row.get(1),
        bot: row.get(2),
        id: row.get::<_, i64>(3) as usize,
        name: row.get(4)
    }
}
fn get_attribute(db: &SqlConnection, id: usize) -> Option<common::Attribute> {
    let mut stmt = db.prepare_cached("SELECT * FROM attributes WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        Some(get_attribute_by_fields(&row))
    } else {
        None
    }
}
fn get_attribute_by_fields(row: &SqlRow) -> common::Attribute {
    common::Attribute {
        allow: row.get(0),
        deny: row.get(1),
        id: row.get::<_, i64>(2) as usize,
        name: row.get(3),
        pos:  row.get::<_, i64>(4) as usize,
        unassignable: row.get(5)
    }
}
fn calculate_permissions(db: &SqlConnection, bot: bool, ids: &[usize], chan_overrides: &[(usize, (u8, u8))]) -> u8 {
    let mut query = String::with_capacity(48+3+1+14);
    query.push_str("SELECT allow, deny FROM attributes WHERE id IN (");
    query.push_str(if bot { "2" } else { "1" });
    if !ids.is_empty() { query.push_str(", "); }
    query.push_str(&from_list(ids));
    query.push_str(") ORDER BY pos");

    let mut stmt = db.prepare(&query).unwrap();
    let rows = stmt.query_map(&[], |row| (row.get(0), row.get(1))).unwrap();
    let mut rows = rows.map(|row| row.unwrap());

    let mut perms = 0;
    common::perm_apply_iter(&mut perms, &mut rows);

    for &(role, chan_perms) in chan_overrides {
        if role <= RESERVED_ROLES || ids.contains(&role) {
            common::perm_apply(&mut perms, chan_perms);
        }
    }

    perms
}
fn calculate_permissions_by_user(db: &SqlConnection, id: usize, chan_overrides: &[(usize, (u8, u8))]) -> Option<u8> {
    let mut stmt = db.prepare_cached("SELECT attributes, bot FROM users WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();

    if let Some(row) = rows.next() {
        let row = row.unwrap();
        // Yes I realize I could pass row.get(0) directly.
        // However, what about SQL injections?
        Some(calculate_permissions(db, row.get(1), &get_list(&row.get::<_, String>(0)), chan_overrides))
    } else {
        None
    }
}
fn get_channel(db: &SqlConnection, id: usize) -> Option<common::Channel> {
    let mut stmt = db.prepare_cached("SELECT * FROM channels WHERE id = ?").unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        Some(get_channel_by_fields(db, &row))
    } else {
        None
    }
}
fn get_channel_by_fields(db: &SqlConnection, row: &SqlRow) -> common::Channel {
    let id = row.get::<_, i64>(0);

    let mut stmt = db.prepare_cached("SELECT allow, attribute, deny FROM overrides WHERE channel = ?").unwrap();
    let mut rows = stmt.query(&[&id]).unwrap();

    let mut overrides = Vec::new();

    while let Some(row) = rows.next() {
        let row = row.unwrap();
        overrides.push((row.get::<_, i64>(1) as usize, (row.get(0), row.get(2))));
    }

    common::Channel {
        overrides: overrides,
        id: id as usize,
        name: row.get(1)
    }
}
fn insert_channel_overrides(db: &SqlConnection, channel: usize, overrides: &[(usize, (u8, u8))]) {
    db.execute("DELETE FROM overrides WHERE channel = ?", &[&(channel as i64)]).unwrap();

    let mut stmt_exists = db.prepare_cached("SELECT COUNT(*) FROM attributes WHERE id = ?") .unwrap();
    let mut stmt_insert = db.prepare_cached("INSERT INTO overrides (allow, attribute, channel, deny) VALUES (?, ?, ?, ?)")
        .unwrap();

    for &(id, (allow, deny)) in overrides {
        let count: i64 = stmt_exists.query_row(
            &[&(id as i64)],
            |row| row.get(0)
        ).unwrap();
        if count as usize > 0 {
            stmt_insert.execute(&[&allow, &(id as i64), &(channel as i64), &deny]).unwrap();
        }
    }
}
fn get_message(db: &SqlConnection, id: usize) -> Option<common::Message> {
    let mut stmt = db.prepare_cached("SELECT * FROM messages WHERE id = ?")
        .unwrap();
    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        Some(get_message_by_fields(&row))
    } else {
        None
    }
}
fn get_message_by_fields(row: &SqlRow) -> common::Message {
    common::Message {
        author: row.get::<_, i64>(0) as usize,
        channel: row.get::<_, i64>(1) as usize,
        id: row.get::<_, i64>(2) as usize,
        text: row.get(3),
        timestamp: row.get(4),
        timestamp_edit: row.get(5)
    }
}

fn write<T: std::io::Write>(writer: &mut T, packet: Packet) {
    attempt_or!(common::write(writer, &packet), {
        eprintln!("Failed to send reply");
    });
}

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
            sessions.borrow_mut().remove(&conn_id);
            return Ok(());
        }
    }

    let handle_clone = Rc::clone(&handle);
    let length = io::read_exact(reader, [0; 2])
        .map_err(|_| ())
        .and_then(move |(reader, bytes)| {
            let size = common::decode_u16(&bytes) as usize;

            if size == 0 {
                close!();
            }

            let handle_clone_clone_ugh = Rc::clone(&handle_clone);
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
                    let mut send_init = false;

                    match packet {
                        Packet::Close => { close!(); }
                        Packet::Login(login) => {
                            let mut stmt = db.prepare_cached(
                                "SELECT id, ban, bot, token, password FROM users WHERE name = ?"
                            ).unwrap();
                            let mut rows = stmt.query(&[&login.name]).unwrap();

                            if let Some(row) = rows.next() {
                                let row = row.unwrap();

                                let row_id = row.get::<_, i64>(0) as usize;
                                let row_ban: bool = row.get(1);
                                let row_bot: bool = row.get(2);
                                let row_token:    String = row.get(3);
                                let row_password: String = row.get(4);

                                if row_ban {
                                    reply = Some(Packet::Err(common::ERR_LOGIN_BANNED));
                                } else if row_bot == login.bot {
                                     if let Some(password) = login.password {
                                        let valid = attempt_or!(bcrypt::verify(&password, &row_password), {
                                            eprintln!("Failed to verify password");
                                            close!();
                                        });
                                        if valid {
                                            reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                                created: false,
                                                id: row_id,
                                                token: row_token
                                            }));
                                            sessions.borrow_mut()
                                                .get_mut(&conn_id).unwrap()
                                                .id = Some(row_id);
                                            send_init = true;
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
                                            sessions.borrow_mut()
                                                .get_mut(&conn_id).unwrap()
                                                .id = Some(row_id);
                                            send_init = true;
                                        } else {
                                            reply = Some(Packet::Err(common::ERR_LOGIN_INVALID));
                                        }
                                    } else {
                                        reply = Some(Packet::Err(common::ERR_MISSING_FIELD));
                                    }
                               } else {
                                    reply = Some(Packet::Err(common::ERR_LOGIN_BOT));
                                }
                            } else if let Some(password) = login.password {
                                if login.name.len() < config.limit_user_name_min
                                    || login.name.len() > config.limit_user_name_max {
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
                                    let mut sessions = sessions.borrow_mut();
                                    let session = sessions.get_mut(&conn_id).unwrap();
                                    session.id = Some(id);
                                    write(&mut session.writer, Packet::LoginSuccess(common::LoginSuccess {
                                        created: true,
                                        id: id,
                                        token: token
                                    }));
                                    send_init = true;

                                    reply = Some(Packet::UserReceive(common::UserReceive {
                                        inner: common::User {
                                            attributes: Vec::new(),
                                            ban: false,
                                            bot: login.bot,
                                            id: id,
                                            name: login.name
                                        }
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_MISSING_FIELD));
                            }
                        },
                        Packet::AttributeCreate(attr) => {
                            if attr.name.len() < config.limit_attribute_name_min
                                || attr.name.len() > config.limit_attribute_name_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else {
                                let id = get_id!();
                                if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions_by_user(&db, id, &[]).unwrap(),
                                    common::PERM_MANAGE_ATTRIBUTES
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    let (count, max): (i64, i64) = db.query_row(
                                        "SELECT COUNT(*), MAX(pos) FROM attributes",
                                        &[],
                                        |row| (row.get(0), row.get(1))
                                    ).unwrap();

                                    if count as usize + 1 > config.limit_attribute_amount_max {
                                        reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                                    } else if attr.pos == 0 || attr.pos > max as usize + 1 {
                                        reply = Some(Packet::Err(common::ERR_ATTR_INVALID_POS));
                                    } else {
                                        db.execute(
                                            "UPDATE attributes SET pos = pos + 1 WHERE pos >= ?",
                                            &[&(attr.pos as i64)]
                                        ).unwrap();
                                        db.execute(
                                            "INSERT INTO attributes (allow, deny, name, pos, unassignable)
                                            VALUES (?, ?, ?, ?, ?)",
                                            &[&attr.allow, &attr.deny, &attr.name, &(attr.pos as i64),
                                            &attr.unassignable]
                                        ).unwrap();

                                        reply = Some(Packet::AttributeReceive(common::AttributeReceive {
                                            inner: common::Attribute {
                                                allow: attr.allow,
                                                deny: attr.deny,
                                                id: db.last_insert_rowid() as usize,
                                                name: attr.name,
                                                pos: attr.pos,
                                                unassignable: attr.unassignable
                                            },
                                            new: true
                                        }));
                                        broadcast = true;
                                    }
                                }
                            }
                        },
                        Packet::AttributeUpdate(event) => {
                            let attr = event.inner;
                            if attr.name.len() < config.limit_attribute_name_min
                                || attr.name.len() > config.limit_attribute_name_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else {
                                let id = get_id!();
                                if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions_by_user(&db, id, &[]).unwrap(),
                                    common::PERM_MANAGE_ATTRIBUTES
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else if let Some(old) = get_attribute(&db, attr.id) {
                                    let max: i64 = db.query_row(
                                        "SELECT MAX(pos) FROM attributes",
                                        &[],
                                        |row| row.get(0)
                                    ).unwrap();

                                    if (attr.pos == 0 && old.pos != 0) || attr.pos > max as usize {
                                        reply = Some(Packet::Err(common::ERR_ATTR_INVALID_POS));
                                    } else if attr.pos == 0 && attr.name != old.name {
                                        reply = Some(Packet::Err(common::ERR_ATTR_LOCKED_NAME));
                                    } else {
                                        if attr.pos > old.pos {
                                            db.execute(
                                                "UPDATE attributes SET pos = pos - 1 WHERE pos > ? AND pos <= ?",
                                                &[&(old.pos as i64), &(attr.pos as i64)]
                                            ).unwrap();
                                        } else if attr.pos < old.pos {
                                            db.execute(
                                                "UPDATE attributes SET pos = pos + 1 WHERE pos >= ? AND pos < ?",
                                                &[&(attr.pos as i64), &(old.pos as i64)]
                                            ).unwrap();
                                        }
                                        db.execute(
                                            "UPDATE attributes SET
                                            allow = ?, deny = ?, name = ?, pos = ?, unassignable = ?
                                            WHERE id = ?",
                                            &[&attr.allow, &attr.deny, &attr.name, &(attr.pos as i64), &attr.unassignable,
                                            &(attr.id as i64)]
                                        ).unwrap();

                                        reply = Some(Packet::AttributeReceive(common::AttributeReceive {
                                            inner: common::Attribute {
                                                allow: attr.allow,
                                                deny: attr.deny,
                                                id: attr.id,
                                                name: attr.name,
                                                pos: attr.pos,
                                                unassignable: attr.unassignable
                                            },
                                            new: true
                                        }));
                                        broadcast = true;
                                    }
                                }
                            }
                        },
                        Packet::AttributeDelete(event) => {
                            let id = get_id!();
                            if !has_perm(
                                &config,
                                id,
                                calculate_permissions_by_user(&db, id, &[]).unwrap(),
                                common::PERM_MANAGE_ATTRIBUTES
                            ) {
                                reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                            } else if let Some(attr) = get_attribute(&db, event.id) {
                                if attr.pos == 0 {
                                    reply = Some(Packet::Err(common::ERR_ATTR_INVALID_POS));
                                } else {
                                    db.execute(
                                        "DELETE FROM overrides WHERE attribute = ?",
                                        &[&(attr.id as i64)]
                                    ).unwrap();
                                    db.execute(
                                        "UPDATE attributes SET pos = pos - 1 WHERE pos > ?",
                                        &[&(attr.pos as i64)]
                                    ).unwrap();
                                    db.execute(
                                        "DELETE FROM attributes WHERE id = ?",
                                        &[&(attr.id as i64)]
                                    ).unwrap();

                                    reply = Some(Packet::AttributeDeleteReceive(common::AttributeDeleteReceive {
                                        inner: common::Attribute {
                                            allow: attr.allow,
                                            deny: attr.deny,
                                            id: attr.id,
                                            name: attr.name,
                                            pos: attr.pos,
                                            unassignable: attr.unassignable
                                        }
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_ATTRIBUTE));
                            }
                        },
                        Packet::ChannelCreate(channel) => {
                            if channel.name.len() < config.limit_channel_name_min
                                || channel.name.len() > config.limit_channel_name_max
                                || channel.overrides.len() > config.limit_attribute_amount_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else {
                                let id = get_id!();
                                if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions_by_user(&db, id, &[]).unwrap(),
                                    common::PERM_MANAGE_CHANNELS
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    db.execute(
                                        "INSERT INTO channels (name) VALUES (?)",
                                        &[&channel.name]
                                    ).unwrap();
                                    let channel_id = db.last_insert_rowid() as usize;
                                    insert_channel_overrides(&db, channel_id, &channel.overrides);

                                    reply = Some(Packet::ChannelReceive(common::ChannelReceive {
                                        inner: common::Channel {
                                            overrides:  channel.overrides,
                                            id: channel_id,
                                            name: channel.name
                                        }
                                    }));
                                    broadcast = true;
                                }
                            }
                        },
                        Packet::ChannelUpdate(event) => {
                            let channel = event.inner;
                            if channel.name.len() < config.limit_channel_name_min
                                || channel.name.len() > config.limit_channel_name_max
                                || channel.overrides.len() > config.limit_attribute_amount_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else {
                                let id = get_id!();
                                if let Some(old) = get_channel(&db, channel.id) {
                                    if !has_perm(
                                        &config,
                                        id,
                                        calculate_permissions_by_user(&db, id, &old.overrides).unwrap(),
                                        common::PERM_MANAGE_CHANNELS
                                    ) {
                                        reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                    } else {
                                        db.execute(
                                            "UPDATE channels SET name = ? WHERE id = ?",
                                            &[&channel.name, &(channel.id as i64)]
                                        ).unwrap();
                                        if !event.keep_overrides {
                                            insert_channel_overrides(&db, channel.id, &channel.overrides);
                                        }

                                        reply = Some(Packet::ChannelReceive(common::ChannelReceive {
                                            inner: common::Channel {
                                                overrides:  channel.overrides,
                                                id: channel.id,
                                                name: channel.name
                                            }
                                        }));
                                        broadcast = true;
                                    }
                                }
                            }
                        },
                        Packet::ChannelDelete(event) => {
                            let id = get_id!();
                            if let Some(channel) = get_channel(&db, event.id) {
                                if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions_by_user(&db, id, &channel.overrides).unwrap(),
                                    common::PERM_MANAGE_CHANNELS
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    db.execute("DELETE FROM messages WHERE channel = ?", &[&(event.id as i64)]).unwrap();
                                    db.execute("DELETE FROM overrides WHERE channel = ?", &[&(event.id as i64)]).unwrap();
                                    db.execute("DELETE FROM channels WHERE id = ?", &[&(event.id as i64)]).unwrap();

                                    reply = Some(Packet::ChannelDeleteReceive(common::ChannelDeleteReceive {
                                        inner: common::Channel {
                                            id: channel.id,
                                            name: channel.name,
                                            overrides: channel.overrides
                                        }
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_CHANNEL));
                            }
                        },
                        Packet::MessageList(params) => {
                            // Cheap trick to break out at any time.
                            let id = get_id!();
                            let channel = get_channel(&db, params.channel);
                            loop {
                                let mut stmt;
                                let mut rows;
                                if channel.is_none() {
                                    reply = Some(Packet::Err(common::ERR_UNKNOWN_CHANNEL));
                                    break;
                                } else if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions_by_user(&db, id, &channel.unwrap().overrides).unwrap(),
                                    common::PERM_READ
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                    break;
                                } else if params.limit > common::LIMIT_MESSAGE_LIST {
                                    reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                                    break;
                                } else if let Some(after) = params.after {
                                    stmt = db.prepare_cached(
                                        "SELECT * FROM messages
                                        WHERE channel = ? AND timestamp >=
                                        (SELECT timestamp FROM messages WHERE id = ?)
                                        ORDER BY timestamp
                                        LIMIT ?",
                                    ).unwrap();
                                    rows = stmt.query(&[
                                        &(params.channel as i64),
                                        &(after as i64),
                                        &(params.limit as i64)
                                    ]).unwrap();
                                } else if let Some(before) = params.before {
                                    stmt = db.prepare_cached(
                                        "SELECT * FROM messages
                                        WHERE channel = ? AND timestamp <=
                                        (SELECT timestamp FROM messages WHERE id = ?)
                                        ORDER BY timestamp
                                        LIMIT ?",
                                    ).unwrap();
                                    rows = stmt.query(&[
                                        &(params.channel as i64),
                                        &(before as i64),
                                        &(params.limit as i64)
                                    ]).unwrap();
                                } else {
                                    stmt = db.prepare_cached(
                                        "SELECT * FROM
                                        (SELECT * FROM messages WHERE channel = ? ORDER BY timestamp DESC LIMIT ?)
                                        ORDER BY timestamp",
                                    ).unwrap();
                                    rows = stmt.query(&[
                                        &(params.channel as i64),
                                        &(params.limit as i64)
                                    ]).unwrap();
                                };


                                let mut sessions = sessions.borrow_mut();
                                let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

                                while let Some(row) = rows.next() {
                                    let msg = get_message_by_fields(&row.unwrap());
                                    let author = get_user(&db, msg.author).unwrap_or(common::User {
                                        id: msg.author,
                                        ..Default::default()
                                    });
                                    write(writer, Packet::MessageReceive(common::MessageReceive {
                                        author: author,
                                        channel: common::Channel {
                                            id: msg.channel,
                                            ..Default::default()
                                        },
                                        id: msg.id,
                                        new: false,
                                        text: msg.text,
                                        timestamp: msg.timestamp,
                                        timestamp_edit: msg.timestamp_edit
                                    }));
                                }
                                break;
                            }
                        },
                        Packet::MessageCreate(msg) => {
                            if msg.text.len() < config.limit_message_min
                                || msg.text.len() > config.limit_message_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else if let Some(channel) = get_channel(&db, msg.channel) {
                                let timestamp = Utc::now().timestamp();
                                let id = get_id!();
                                let user = get_user(&db, id).unwrap();

                                if !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions(&db, user.bot, &user.attributes, &channel.overrides),
                                    common::PERM_WRITE
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    db.execute(
                                        "INSERT INTO messages (author, channel, text, timestamp) VALUES (?, ?, ?, ?)",
                                        &[&(id as i64), &(msg.channel as i64), &msg.text, &timestamp]
                                    ).unwrap();

                                    reply = Some(Packet::MessageReceive(common::MessageReceive {
                                        author: user,
                                        channel: channel,
                                        id: db.last_insert_rowid() as usize,
                                        new: true,
                                        text: msg.text,
                                        timestamp: timestamp,
                                        timestamp_edit: None
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_CHANNEL));
                            }
                        },
                        Packet::MessageUpdate(event) => {
                            if event.text.len() < config.limit_message_min
                                || event.text.len() > config.limit_message_max {
                                reply = Some(Packet::Err(common::ERR_LIMIT_REACHED));
                            } else if let Some(msg) = get_message(&db, event.id) {
                                let timestamp = Utc::now().timestamp();
                                let id = get_id!();

                                if msg.author != id {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    let channel = get_channel(&db, id).unwrap();
                                    let user = get_user(&db, id).unwrap();

                                    db.execute(
                                        "UPDATE messages SET text = ? WHERE id = ?",
                                        &[&event.text, &(event.id as i64)]
                                    ).unwrap();

                                    reply = Some(Packet::MessageReceive(common::MessageReceive {
                                        author: user,
                                        channel: channel,
                                        id: event.id,
                                        new: true,
                                        text: event.text,
                                        timestamp: msg.timestamp,
                                        timestamp_edit: Some(timestamp)
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_MESSAGE));
                            }
                        },
                        Packet::MessageDelete(event) => {
                            if let Some(msg) = get_message(&db, event.id) {
                                let id = get_id!();
                                let user = get_user(&db, id).unwrap();
                                let channel = get_channel(&db, id).unwrap();

                                if msg.author != id && !has_perm(
                                    &config,
                                    id,
                                    calculate_permissions(&db, user.bot, &user.attributes, &channel.overrides),
                                    common::PERM_MANAGE_MESSAGES
                                ) {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                } else {
                                    db.execute(
                                        "DELETE FROM messages WHERE id = ?",
                                        &[&(event.id as i64)]
                                    ).unwrap();

                                    reply = Some(Packet::MessageDeleteReceive(common::MessageDeleteReceive {
                                        id: event.id
                                    }));
                                    broadcast = true;
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_MESSAGE));
                            }
                        },
                        Packet::UserUpdate(user) => {
                            let id = get_id!();
                            if !has_perm(
                                &config,
                                id,
                                calculate_permissions_by_user(&db, id, &[]).unwrap(),
                                common::PERM_ASSIGN_ATTRIBUTES
                            ) {
                                reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION))
                            } else if let Some(old) = get_user(&db, user.id) {
                                let mut changed = Vec::new();

                                for attr in &user.attributes {
                                    if !old.attributes.contains(&attr) {
                                        changed.push(*attr);
                                    }
                                }
                                for attr in &old.attributes {
                                    if !user.attributes.contains(&attr) {
                                        changed.push(*attr);
                                    }
                                }

                                let correct = if id == config.owner_id {
                                    let mut ok = true;
                                    for attr in changed {
                                        if attr <= RESERVED_ROLES {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    ok
                                } else if !changed.is_empty() {
                                    let mut query = String::with_capacity(45+1+35);

                                    query.push_str("SELECT COUNT(*) FROM attributes WHERE id IN (");
                                    query.push_str(&from_list(&changed));
                                    query.push_str(") AND unassignable = 0 AND pos != 0");
                                    if !old.attributes.is_empty() {
                                        query.push_str(" AND pos < (SELECT MAX(pos) FROM attributes WHERE id IN (");
                                        query.push_str(&from_list(&old.attributes));
                                        query.push_str("))");
                                    }

                                    let count: i64 = db.query_row(&query, &[], |row| row.get(0)).unwrap();
                                    changed.len() == count as usize
                                } else { false };

                                if correct {
                                    db.execute(
                                        "UPDATE users SET attributes = ? WHERE id = ?",
                                        &[&from_list(&user.attributes), &(user.id as i64)]
                                    ).unwrap();
                                    reply = Some(Packet::UserReceive(common::UserReceive {
                                        inner: common::User {
                                            attributes: user.attributes,
                                            ban: old.ban,
                                            bot: old.bot,
                                            id: user.id,
                                            name: old.name
                                        }
                                    }));
                                    broadcast = true;
                                } else {
                                    reply = Some(Packet::Err(common::ERR_MISSING_PERMISSION));
                                }
                            } else {
                                reply = Some(Packet::Err(common::ERR_UNKNOWN_USER));
                            }

                        },
                        Packet::LoginUpdate(login) => {
                            let id = get_id!();

                            if let Some(name) = login.name {
                                db.execute("UPDATE users SET name = ? WHERE id = ?", &[&name, &(id as i64)]).unwrap();
                            }
                            let mut reset_token = login.reset_token;
                            if let Some(current) = login.password_current {
                                if let Some(new) = login.password_new {
                                    let mut stmt = db.prepare_cached("SELECT password FROM users WHERE id = ?").unwrap();
                                    let mut rows = stmt.query(&[&(id as i64)]).unwrap();
                                    let password: String = rows.next().unwrap().unwrap().get(0);
                                    let valid = attempt_or!(bcrypt::verify(&current, &password), {
                                        eprintln!("Failed to verify password");
                                        close!();
                                    });
                                    if valid {
                                        let hash = attempt_or!(bcrypt::hash(&new, bcrypt::DEFAULT_COST), {
                                            eprintln!("Failed to hash password");
                                            close!();
                                        });
                                        db.execute("UPDATE users SET password = ? WHERE id = ?", &[&hash, &(id as i64)])
                                            .unwrap();
                                        reset_token = true;
                                    } else {
                                        reply = Some(Packet::Err(common::ERR_LOGIN_INVALID));
                                        reset_token = false;
                                    }
                                } else {
                                    reply = Some(Packet::Err(common::ERR_MISSING_FIELD));
                                    reset_token = false;
                                }
                            }
                            if reset_token {
                                let token = attempt_or!(gen_token(), {
                                    eprintln!("Failed to generate random token");
                                    close!();
                                });
                                db.execute("UPDATE users SET token = ? WHERE id = ?", &[&token, &(id as i64)]).unwrap();
                                reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                    created: false,
                                    id: id,
                                    token: token
                                }));
                            }
                        },
                        _ => unimplemented!()
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

                        write(writer, reply);
                    }
                    if send_init {
                        let mut sessions = sessions.borrow_mut();
                        let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;
                        {
                            let mut stmt = db.prepare_cached("SELECT * FROM attributes").unwrap();
                            let mut rows = stmt.query(&[]).unwrap();

                            while let Some(row) = rows.next() {
                                let row = row.unwrap();

                                write(writer, Packet::AttributeReceive(common::AttributeReceive {
                                    inner: get_attribute_by_fields(&row),
                                    new: false,
                                }));
                            }
                        } {
                            let mut stmt = db.prepare_cached("SELECT * FROM channels").unwrap();
                            let mut rows = stmt.query(&[]).unwrap();

                            while let Some(row) = rows.next() {
                                let row = row.unwrap();

                                write(writer, Packet::ChannelReceive(common::ChannelReceive {
                                    inner: get_channel_by_fields(&db, &row),
                                }));
                            }
                        } {
                            let mut stmt = db.prepare_cached("SELECT * FROM users").unwrap();
                            let mut rows = stmt.query(&[]).unwrap();

                            while let Some(row) = rows.next() {
                                let row = row.unwrap();

                                write(writer, Packet::UserReceive(common::UserReceive {
                                    inner: get_user_by_fields(&row)
                                }));
                            }
                        }
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
