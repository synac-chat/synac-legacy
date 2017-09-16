extern crate bcrypt;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;

use common::Packet;
use futures::{Future, Stream};
use openssl::pkcs12::Pkcs12;
use openssl::rand;
use openssl::ssl::{SslMethod, SslAcceptorBuilder};
use rusqlite::Connection as SqlConnection;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
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

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });

    let handle = Rc::new(handle);
    let db = Rc::new(db);

    println!("I'm alive!");

    let sessions = Rc::new(RefCell::new(HashMap::new()));
    let conn_id = Rc::new(RefCell::new(0usize));

    let server = listener.incoming().for_each(|(conn, _)| {
        use tokio_io::AsyncRead;

        let handle_clone = handle.clone();
        let db_clone = db.clone();
        let sessions_clone = sessions.clone();
        let conn_id_clone = conn_id.clone();

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
                handle_clone,
                db_clone,
                sessions_clone,
                my_conn_id,
                reader
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

pub const TOKEN_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Session {
    id: Option<usize>,
    writer: BufWriter<tokio_io::io::WriteHalf<SslStream<TcpStream>>>
}

fn handle_client(
        handle: Rc<Handle>,
        db: Rc<SqlConnection>,
        sessions: Rc<RefCell<HashMap<usize, Session>>>,
        conn_id: usize,
        reader: BufReader<tokio_io::io::ReadHalf<SslStream<TcpStream>>>,
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

                    let mut reply = None;

                    match packet {
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
                                                &[&token, &row_id.to_string()]
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
                                    &[&if login.bot { "1" } else { "0" }, &login.name, &password, &token]
                                ).unwrap();
                                let id = db.last_insert_rowid() as usize;
                                reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                    created: true,
                                    id: id,
                                    token: token
                                }));
                                sessions.borrow_mut().get_mut(&conn_id).unwrap().id = Some(id);
                            } else {
                                reply = Some(Packet::Err(common::ERR_LOGIN_EMPTY));
                            }
                        },
                        Packet::MessageCreate(msg) => {
                            let id = get_id!();
                            let user = get_user(&db, id).unwrap();
                            let packet = Packet::MessageReceive(common::MessageReceive {
                                author: user,
                                channel: msg.channel,
                                id: 0,
                                text: msg.text
                            });
                            let encoded = attempt_or!(common::serialize(&packet), {
                                eprintln!("Failed to serialize message");
                                close!();
                            });
                            assert!(encoded.len() < std::u16::MAX as usize);
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
                        },
                        Packet::Close => { close!(); }
                        _ => unimplemented!(),
                    }

                    let reply = match reply {
                        Some(some) => some,
                        None => {
                            handle_client(
                                handle_clone_clone_ugh,
                                db,
                                sessions,
                                conn_id,
                                reader
                            );
                            return Ok(());
                        }
                    };

                    // Yes, I should be using io::write_all here - I very much agree.
                    // However, io::write_all takes a writer, not a reference to one (understandable).
                    // Sure, I could solve that with an Option (which I used to do).
                    // However, if two things would try to write at once we'd have issues...

                    {
                        let mut sessions = sessions.borrow_mut();
                        let writer = &mut sessions.get_mut(&conn_id).unwrap().writer;

                        attempt_or!(common::write(writer, &reply), {
                            eprintln!("Failed to send reply");
                            close!();
                        });
                    }

                    handle_client(
                        handle_clone_clone_ugh,
                        db,
                        sessions,
                        conn_id,
                        reader
                    );

                    Ok(())
                });

            handle_clone.spawn(lines);
            Ok(())
        });

    handle.spawn(length);
}
