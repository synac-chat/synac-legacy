extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
extern crate termion;
extern crate common;

mod parser;

use common::Packet;
use openssl::ssl::{SslMethod, SslConnectorBuilder, SSL_VERIFY_PEER};
use rustyline::error::ReadlineError;
use std::env;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use termion::screen::AlternateScreen;

macro_rules! print {
    ($($arg:tt)+) => {
        write!($($arg)+).unwrap();
    }
}
macro_rules! println {
    ($($arg:tt)+) => {
        writeln!($($arg)+).unwrap();
    }
}
macro_rules! flush {
    ($stdout:expr) => {
        $stdout.flush().unwrap();
    }
}

fn main() {
    let db = match rusqlite::Connection::open("data.sqlite") {
        Ok(ok) => ok,
        Err(err) => {
            eprintln!("Failed to open database");
            eprintln!("{}", err);
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
    let mut stream = None;

    let mut stdin = io::stdin();
    let mut stdout = AlternateScreen::from(io::stdout());
    println!(stdout, "{}Welcome, {}", termion::cursor::Goto(1, 1), nick);
    println!(stdout, "To change your name, type");
    println!(stdout, "/nick <name>");
    println!(stdout, "To connect to a server, type");
    println!(stdout, "/connect <ip>");
    println!(stdout);
    flush!(stdout);

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        flush!(stdout);
        let input = match editor.readline("> ") {
            Ok(ok) => ok,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("Couldn't read line: {}", err);
                break;
            }
        };
        editor.add_history_entry(&input);

        if input.starts_with('/') {
            let mut args = parser::parse(&input[1..]);
            if args.is_empty() {
                continue;
            }
            let command = args.remove(0);

            macro_rules! usage {
                ($amount:expr, $usage:expr) => {
                    if args.len() != $amount {
                        println!(stdout, concat!("Usage: /", $usage));
                        continue;
                    }
                }
            }

            match &*command {
                "nick" => {
                    usage!(1, "nick <name>");
                    nick = args.remove(0);
                    println!(stdout, "Your name is now {}", nick);
                },
                "connect" => {
                    usage!(1, "connect <ip[:port]>");
                    if stream.is_some() {
                        println!(stdout, "Please disconnect first.");
                        continue;
                    }

                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            println!(stdout, "Could not parse IP");
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
                        println!(stdout, "To securely connect, we need some data from the server (\"public key\").");
                        println!(stdout, "The server owner should have given you this.");
                        println!(stdout, "Once you have it, enter it here:");
                        flush!(stdout);
                        let result = editor.readline("");
                        public_key = match result {
                            Err(ReadlineError::Eof) |
                            Err(ReadlineError::Interrupted) => break,
                            Ok(ok) => ok,
                            Err(err) => {
                                eprintln!("Couldn't read line: {}", err);
                                break;
                            }
                        };

                        db.execute(
                            "INSERT INTO servers (ip, key) VALUES (?, ?)",
                            &[&addr.to_string(), &public_key]
                        ).unwrap();
                    }
                    // TODO use public_key
                    let stream_ = match TcpStream::connect(addr) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!(stdout, "Could not connect!");
                            println!(stdout, "{}", err);
                            continue;
                        }
                    };
                    let mut stream_ = {
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
config.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream_)
                        {
                            Ok(ok) => ok,
                            Err(_) => {
                                println!(stdout, "Faild to validate certificate");
                                continue;
                            }
                        }
                    };

                    let mut success = false;
                    if let Some(token) = token {
                        let packet = Packet::Login(common::Login {
                            bot: false,
                            name: nick.clone(),
                            password: None,
                            token: Some(token.clone())
                        });

                        if let Err(err) = common::write(&mut stream_, &packet) {
                            println!(stdout, "Could not request login");
                            println!(stdout, "{}", err);
                            continue;
                        }

                        match common::read(&mut stream_) {
                            Ok(Packet::LoginSuccess(login)) => {
                                success = true;
                                if let Some(id) = login.id {
                                    println!(stdout, "Logged in as user #{}", id);
                                } else {
                                    println!(stdout, "Tried to log in with your token: Apparently an account was created.");
                                    println!(stdout, "I think you should stay away from this server. It's weird.");
                                    continue;
                                }
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID |
                                common::ERR_LOGIN_EMPTY => {},
                                common::ERR_LOGIN_BANNED => {
                                    println!(stdout, "Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    println!(stdout, "This account is a bot account.");
                                    continue;
                                },
                                _ => {
                                    println!(stdout, "The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                println!(stdout, "The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                println!(stdout, "Failed to read from server");
                                println!(stdout, "{}", err);
                                continue;
                            }
                        }
                    }

                    if !success {
                        print!(stdout, "Password: ");
                        flush!(stdout);
                        use termion::input::TermRead;
                        let pass = match stdin.read_passwd(&mut stdout) {
                            Ok(Some(some)) => some,
                            Ok(None) => continue,
                            Err(err) => {
                                println!(stdout, "Failed to read password");
                                println!(stdout, "{}", err);
                                continue;
                            }
                        };
                        println!(stdout);

                        let packet = Packet::Login(common::Login {
                            bot: false,
                            name: nick.clone(),
                            password: Some(pass),
                            token: None
                        });

                        if let Err(err) = common::write(&mut stream_, &packet) {
                            println!(stdout, "Could not request login");
                            println!(stdout, "{}", err);
                            continue;
                        }

                        match common::read(&mut stream_) {
                            Ok(Packet::LoginSuccess(login)) => {
                                db.execute(
                                    "UPDATE servers SET token = ? WHERE ip = ?",
                                    &[&login.token, &addr.to_string()]
                                ).unwrap();
                                if let Some(id) = login.id {
                                    println!(stdout, "Logged in as user #{}", id);
                                } else {
                                    println!(stdout, "Account created");
                                }
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID => {},
                                common::ERR_LOGIN_BANNED => {
                                    println!(stdout, "Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    println!(stdout, "This account is a bot account.");
                                    continue;
                                },
                                _ => {
                                    println!(stdout, "The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                println!(stdout, "The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                println!(stdout, "Failed to read from server");
                                println!(stdout, "{}", err);
                                continue;
                            }
                        }
                    }
                    stream = Some(stream_);
                },
                "disconnect" => {
                    usage!(0, "disconnect");
                    if let Some(ref mut stream) = stream {
                        let _ = common::write(stream, &Packet::Close);
                    } else {
                        println!(stdout, "You're not connected to a server");
                        continue;
                    }
                    stream = None;
                },
                "forget" => {
                    usage!(1, "forget <ip>");
                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            println!(stdout, "Not a valid IP");
                            continue;
                        }
                    };
                    db.execute("DELETE FROM servers WHERE ip = ?", &[&addr.to_string()]).unwrap();
                },
                _ => {
                    println!(stdout, "Unknown command");
                }
            }
            continue;
        }

        match stream {
            None => {
                println!(stdout, "You're not connected to a server");
                continue;
            },
            Some(ref mut stream) => {
                let packet = Packet::MessageCreate(common::MessageCreate {
                    channel: 0,
                    text: input.into_bytes()
                });

                if let Err(err) = common::write(stream, &packet) {
                    println!(stdout, "Failed to deliver message");
                    println!(stdout, "{}", err);
                }
            }
        }
    }
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
