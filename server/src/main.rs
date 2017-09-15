extern crate bcrypt;
extern crate common;
extern crate futures;
extern crate openssl;
extern crate rusqlite;
extern crate tokio_core;
extern crate tokio_io;

use common::Packet;
use futures::{Future, Stream};
use openssl::rand;
use openssl::rsa::Rsa;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::io::{BufReader, BufWriter};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use tokio_io::io;

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

pub const TOKEN_CHARS: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Session {
    id: usize,
    rsa: Rsa
}

fn main() {
    let db = attempt_or!(rusqlite::Connection::open("data.sqlite"), {
        eprintln!("SQLite initialization failed.");
        eprintln!("Is the file corrupt?");
        eprintln!("Is the file permissions badly configured?");
        eprintln!("Just guessing here ¯\\_(ツ)_/¯");
        return;
    });
    db.execute("CREATE TABLE IF NOT EXISTS data (
                    type    INTEGER NOT NULL,
                    value   BLOB NOT NULL
                )", &[])
        .expect("SQLite table creation failed");
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
    match args.next().as_ref().map(|s| &**s) {
        Some("start") => {},
        Some("reset-keys") => {
            db.execute("DELETE FROM data WHERE type=0", &[]).unwrap();
            println!("Public & Private keys reset.");
            return;
        },
        _ => {
            println!("Usage: ./unnamed start [port] OR ./unnamed reset-keys");
            return;
        }
    };
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

    let rsa;
    {
        let mut stmt = db.prepare("SELECT value FROM data WHERE type = 0").unwrap();
        let mut rows = stmt.query(&[]).unwrap();

        if let Some(row) = rows.next() {
            let row = row.unwrap();
            rsa = attempt_or!(Rsa::private_key_from_pem(&row.get::<_, Vec<_>>(0)), {
                eprintln!("Could not use private key.");
                eprintln!("Is it invalid? D:");
                return;
            });
            let public = rsa.public_key_to_pem().unwrap();
            let string = attempt_or!(std::str::from_utf8(&public), {
                eprintln!("Oh no! Text isn't valid UTF-8!");
                eprintln!("Please contact my developer!");
                return;
            });
            println!("In case you forgot your public key, it's:");
            println!();
            println!("{}", string);
        } else {
            // Generate new public and private keys.
            rsa = Rsa::generate(common::RSA_KEY_BIT_LEN).expect("Failed to generate public/private key");
            let private = rsa.private_key_to_pem().unwrap();
            let public = rsa.public_key_to_pem().unwrap();
            db.execute("INSERT INTO data (type, value) VALUES (0, ?)", &[&private]).unwrap();
            // be friendly
            let string = attempt_or!(std::str::from_utf8(&public), {
                eprintln!("Oh no! Text isn't valid UTF-8!");
                eprintln!("Please contact my developer!");
                return;
            });
            println!("Almost there! To secure your users' connection,");
            println!("you will have to *securely* send a piece of data manually.");
            println!("Example #1: Write it down and give it to them IRL.");
            println!("Example #2: Send it in *parts* over multiple applications.");
            println!("The text is as follows: ");
            println!();
            println!("{}", string);
        }
    }

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });

    let rsa = Rc::new(rsa);
    let handle = Rc::new(handle);
    let db = Rc::new(db);

    println!("I'm alive!");

    let sessions = Rc::new(RefCell::new(HashMap::new()));

    let server = listener.incoming().for_each(|(conn, ip)| {
        use tokio_io::AsyncRead;
        let (reader, writer) = conn.split();
        let bufreader = BufReader::new(reader);
        let bufwriter = BufWriter::new(writer);

        handle_client(
            rsa.clone(),
            handle.clone(),
            db.clone(),
            sessions.clone(),
            ip.ip(),
            bufreader,
            bufwriter,
        );

        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn handle_client(
        rsa: Rc<Rsa>,
        handle: Rc<Handle>,
        db: Rc<rusqlite::Connection>,
        sessions: Rc<RefCell<HashMap<IpAddr, Session>>>,
        ip: IpAddr,
        bufreader: BufReader<tokio_io::io::ReadHalf<TcpStream>>,
        bufwriter: BufWriter<tokio_io::io::WriteHalf<TcpStream>>
    ) {
    macro_rules! close {
        () => {
            println!("Closing connection");
            sessions.borrow_mut().remove(&ip);
            return Ok(());
        }
    }

    let handle_clone = handle.clone();
    let rsa_clone = rsa.clone();
    let length = io::read_exact(bufreader, [0; 4])
        .map_err(|_| ())
        .and_then(move |(bufreader, bytes)| {
            let (size_rsa, size_aes) = common::decode_size(&bytes);
            let (size_rsa, size_aes) = (size_rsa as usize, size_aes as usize);

            if size_rsa == 0 || size_aes == 0 {
                close!();
            }

            let handle_clone_clone_ugh = handle_clone.clone();
            let lines = io::read_exact(bufreader, vec![0; size_rsa+size_aes])
                .map_err(|_| ())
                .and_then(move |(bufreader, bytes)| {
                    let packet = match common::decrypt(&bytes, &rsa_clone, size_rsa) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Failed to decrypt message from client: {}", err);
                            close!();
                        }
                    };

                    let mut reply = None;
                    let mut public_key = None;

                    macro_rules! rsa {
                        ($public_key:expr) => {
                            match Rsa::public_key_from_pem($public_key) {
                                Ok(ok) => ok,
                                Err(_) => { close!(); }
                            }
                        }
                    }

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
                                                println!("Failed to generate random token");
                                                close!();
                                            });
                                            db.execute(
                                                "UPDATE users SET token = ? WHERE id = ?",
                                                &[&token, &row_id.to_string()]
                                            ).unwrap();
                                            reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                                id: Some(row_id),
                                                token: token
                                            }));
                                            sessions.borrow_mut().insert(ip, Session {
                                                id: row_id,
                                                rsa: rsa!(&login.public_key)
                                            });
                                        } else {
                                            reply = Some(Packet::Err(common::ERR_LOGIN_INVALID));
                                        }
                                    } else if let Some(token) = login.token {
                                        if token == row_token {
                                            reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                                id: Some(row_id),
                                                token: token
                                            }));
                                            sessions.borrow_mut().insert(ip, Session {
                                                id: row_id,
                                                rsa: rsa!(&login.public_key)
                                            });
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
                                    println!("Failed to hash password");
                                    close!();
                                });
                                let token = attempt_or!(gen_token(), {
                                    println!("Failed to generate random token");
                                    close!();
                                });
                                db.execute(
                                    "INSERT INTO users (bot, name, password, token) VALUES (?, ?, ?, ?)",
                                    &[&if login.bot { "1" } else { "0" }, &login.name, &password, &token]
                                ).unwrap();
                                reply = Some(Packet::LoginSuccess(common::LoginSuccess {
                                    id: None,
                                    token: token
                                }));
                                sessions.borrow_mut().insert(ip, Session {
                                    id: db.last_insert_rowid() as usize,
                                    rsa: rsa!(&login.public_key)
                                });
                            }

                            public_key = Some(login.public_key);
                        },
                        Packet::MessageCreate(msg) => {
                            println!(
                                "User #{} sent {}", sessions.borrow().get(&ip).unwrap().id, String::from_utf8_lossy(&msg.text)
                            );
                        },
                        Packet::Close => { close!(); }
                        _ => unimplemented!(),
                    }

                    let reply = match reply {
                        Some(some) => some,
                        None => {
                            handle_client(
                                rsa_clone,
                                handle_clone_clone_ugh,
                                db,
                                sessions,
                                ip,
                                bufreader,
                                bufwriter
                            );
                            return Ok(());
                        }
                    };

                    let _rsa: Rsa;
                    let encrypted = {
                        let sessions = sessions.borrow();
                        let rsa = match sessions.get(&ip) {
                            Some(ref some) => &some.rsa,
                            None => match public_key {
                                Some(some) => {
                                    _rsa = rsa!(&some);
                                    &_rsa
                                },
                                None => { close!(); }
                            }
                        };
                        attempt_or!(common::encrypt(&reply, &rsa), {
                            println!("Failed to encrypt reply");
                            close!();
                        })
                    };
                    let handle_clone_clone_clone_uugghh = handle_clone_clone_ugh.clone();
                    let write = io::write_all(bufwriter, encrypted)
                        .map_err(|_| ())
                        .and_then(move |(mut bufwriter, _)| {
                            use std::io::Write;
                            let _ = bufwriter.flush();
                            handle_client(
                                rsa_clone,
                                handle_clone_clone_clone_uugghh,
                                db,
                                sessions,
                                ip,
                                bufreader,
                                bufwriter
                            );
                            Ok(())
                        });

                    handle_clone_clone_ugh.spawn(write);
                    Ok(())
                });

            handle_clone.spawn(lines);
            Ok(())
        });

    handle.spawn(length);
}

fn gen_token() -> Result<String, openssl::error::ErrorStack> {
    let mut token = vec![0; 64];
    rand::rand_bytes(&mut token)?;
    for byte in token.iter_mut() {
        *byte = TOKEN_CHARS[*byte as usize % TOKEN_CHARS.len()];
    }

    Ok(unsafe { String::from_utf8_unchecked(token) })
}
