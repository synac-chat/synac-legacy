extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
extern crate termion;
extern crate common;

mod parser;

use common::Packet;
use openssl::rsa::Rsa;
use rustyline::error::ReadlineError;
use std::env;
use std::io::{self, Write};
use std::net::TcpStream;
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
            eprintln!("Failed to open database.");
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
                    let mut parts = args[0].split(":");
                    let ip = parts.next().unwrap();
                    let port = parts.next().map(|val| match val.parse() {
                        Ok(ok) => ok,
                        Err(_) => {
                            println!(stdout, "Not a valid port, using default.");
                            common::DEFAULT_PORT
                        }
                    }).unwrap_or(common::DEFAULT_PORT);
                    if parts.next().is_some() {
                        println!(stdout, "Still going? It's <ip[:port]>, not <ip[:port[:foo[:bar[:whatever]]]]>...");
                        continue;
                    }
                    use std::net::ToSocketAddrs;
                    let addr = match (ip, port).to_socket_addrs().ok().and_then(|mut iter| iter.next()) {
                        Some(some) => some,
                        None => {
                            println!(stdout, "Not a valid socket address.");
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
                        println!(stdout, "Once you have it, enter it here and end it by typing \"END\" on a new line.");
                        println!(stdout);
                        flush!(stdout);
                        let mut public_key_string = String::new();
                        loop {
                            let result = editor.readline("");
                            let input = match result.as_ref().map(|s| &**s) {
                                Ok("END") |
                                Err(&ReadlineError::Eof) => break,
                                Ok(ok) => ok,
                                Err(err) => {
                                    eprintln!("Couldn't read line: {}", err);
                                    break;
                                }
                            };

                            public_key_string.push_str(&input);
                            public_key_string.push('\n');
                        }
                        public_key = public_key_string.into_bytes();
                        db.execute(
                            "INSERT INTO servers (ip, key) VALUES (?, ?)",
                            &[&addr.to_string(), &public_key]
                        ).unwrap();
                    }
                    let rsa_encrypt = match Rsa::public_key_from_pem(&public_key) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Could not initiate RSA.");
                            eprintln!("Is that weird thing you entered invalid? Just a guess.");
                            eprintln!("Scary debug details: {}", err);
                            continue;
                        }
                    };
                    let rsa_decrypt = match Rsa::generate(common::RSA_KEY_BIT_LEN) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Could not initiate RSA.");
                            eprintln!("Try again?");
                            eprintln!("{}", err);
                            continue;
                        }
                    };
                    let mut tcp = match TcpStream::connect(addr) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!(stdout, "Could not connect!");
                            println!(stdout, "{}", err);
                            continue;
                        }
                    };
                    let public_key = rsa_decrypt.public_key_to_pem().unwrap();

                    let mut success = false;
                    if let Some(token) = token {
                        let packet = Packet::Login(common::Login {
                            bot: false,
                            name: nick.clone(),
                            password: None,
                            public_key: public_key.clone(),
                            token: Some(token.clone())
                        });

                        if let Err(err) = common::write(&mut tcp, &rsa_encrypt, &packet) {
                            println!(stdout, "Could not request login");
                            println!(stdout, "{}", err);
                            continue;
                        }

                        match common::read(&mut tcp, &rsa_decrypt) {
                            Ok(Packet::LoginSuccess(_)) => success = true,
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID => {},
                                common::ERR_LOGIN_BANNED => {
                                    println!(stdout, "Oh noes, you have been banned from this server :(");
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
                            public_key: public_key,
                            token: None
                        });

                        if let Err(err) = common::write(&mut tcp, &rsa_encrypt, &packet) {
                            println!(stdout, "Could not request login");
                            println!(stdout, "{}", err);
                            continue;
                        }

                        match common::read(&mut tcp, &rsa_decrypt) {
                            Ok(Packet::LoginSuccess(login)) => {
                                db.execute(
                                    "UPDATE servers SET token = ? WHERE ip = ?",
                                    &[&login.token, &addr.to_string()]
                                ).unwrap();
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID => {},
                                common::ERR_LOGIN_BANNED => {
                                    println!(stdout, "Oh noes, you have been banned from this server :(");
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
                    stream = Some((rsa_encrypt, rsa_decrypt, tcp));
                },
                "disconnect" => {
                    usage!(0, "disconnect");
                    if stream.is_none() {
                        println!(stdout, "You're not connected to a server.");
                        continue;
                    }
                    stream = None;
                }
                _ => {
                    println!(stdout, "Unknown command");
                }
            }
            continue;
        }

        match stream {
            None => {
                println!(stdout, "You're not connected to a server.");
                continue;
            },
            Some((ref mut rsa_encrypt, _, ref mut stream)) => {
                let packet = Packet::MessageCreate(common::MessageCreate {
                    channel: 0,
                    text: input.into_bytes()
                });

                if let Err(err) = common::write(stream, rsa_encrypt, &packet) {
                    println!(stdout, "Failed to deliver message.");
                    println!(stdout, "{}", err);
                }
            }
        }
    }
}
