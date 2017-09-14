extern crate openssl;
extern crate rusqlite;
extern crate rustyline;
extern crate termion;
extern crate common;

mod parser;

use openssl::rsa::Rsa;
use rustyline::error::ReadlineError;
use std::env;
use std::io::{self, Write};
use std::net::TcpStream;
use termion::screen::AlternateScreen;

macro_rules! println {
    ($($arg:tt)+) => {
        writeln!($($arg)+).unwrap();
    }
}
macro_rules! flush {
    ($screen:expr) => {
        $screen.flush().unwrap();
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
                    ip      TEXT NOT NULL,
                    key     BLOB NOT NULL
                )", &[])
        .expect("Couldn't create SQLite table");

    #[cfg(unix)]
    let mut nick = env::var("USER").unwrap_or("unknown".to_string());
    #[cfg(windows)]
    let mut nick = env::var("USERNAME").unwrap_or("unknown".to_string());
    #[cfg(not(any(unix, windows)))]
    let mut nick = "unknown".to_string();

    let mut stream = None;

    let mut screen = AlternateScreen::from(io::stdout());
    println!(screen, "{}Welcome, {}", termion::cursor::Goto(1, 1), nick);
    println!(screen, "To change your name, type");
    println!(screen, "/nick <name>");
    println!(screen, "To connect to a server, type");
    println!(screen, "/connect <ip>");
    println!(screen);
    flush!(screen);

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        flush!(screen);
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
                        println!(screen, concat!("Usage: /", $usage));
                        continue;
                    }
                }
            }

            match &*command {
                "nick" => {
                    usage!(1, "nick <name>");
                    nick = args.remove(0);
                    println!(screen, "Your name is now {}", nick);
                },
                "connect" => {
                    usage!(1, "connect <ip[:port]>");
                    let mut parts = args[0].split(":");
                    let ip = parts.next().unwrap();
                    let port = parts.next().map(|val| match val.parse() {
                        Ok(ok) => ok,
                        Err(_) => {
                            println!(screen, "Not a valid port, using default.");
                            common::DEFAULT_PORT
                        }
                    }).unwrap_or(common::DEFAULT_PORT);
                    if parts.next().is_some() {
                        println!(screen, "Still going? It's <ip[:port]>, not <ip[:port[:foo[:bar[:whatever]]]]>...");
                        continue;
                    }
                    use std::net::ToSocketAddrs;
                    let addr = match (ip, port).to_socket_addrs().ok().and_then(|mut iter| iter.next()) {
                        Some(some) => some,
                        None => {
                            println!(screen, "Not a valid socket address.");
                            continue;
                        }
                    };

                    let mut stmt = db.prepare("SELECT key FROM servers WHERE ip = ?").unwrap();
                    let mut rows = stmt.query(&[&addr.to_string()]).unwrap();

                    let public_key;
                    if let Some(row) = rows.next() {
                        let row = row.unwrap();
                        public_key = row.get(0);
                    } else {
                        println!(screen, "To securely connect, we need some data from the server (\"public key\").");
                        println!(screen, "The server owner should have given you this.");
                        println!(screen, "Once you have it, enter it here and end it by typing \"END\" on a new line.");
                        println!(screen);
                        flush!(screen);
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
                    let rsa = match Rsa::public_key_from_pem(&public_key) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Could not initiate RSA.");
                            eprintln!("Is that weird thing you entered invalid? Just a guess.");
                            eprintln!("Scary debug details: {}", err);
                            continue;
                        }
                    };
                    stream = Some((rsa, match TcpStream::connect(addr) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!(screen, "Could not connect!");
                            println!(screen, "{}", err);
                            continue;
                        }
                    }));
                },
                "disconnect" => {
                    usage!(0, "disconnect");
                    if stream.is_none() {
                        println!(screen, "You're not connected to a server.");
                        continue;
                    }
                    stream = None;
                }
                _ => {
                    println!(screen, "Unknown command");
                }
            }
            continue;
        }

        match stream {
            None => {
                println!(screen, "You're not connected to a server.");
                continue;
            },
            Some((ref mut rsa, ref mut stream)) => {
                let packet = common::Packet::MessageCreate(common::MessageCreate {
                    channel: 0,
                    text: input.into_bytes()
                });

                let encrypted = match common::encrypt(rsa, &packet) {
                    Ok(ok) => ok,
                    Err(err) => {
                        println!(screen, "Sending failed");
                        println!(screen, "{}", err);
                        continue;
                    }
                };

                if let Err(err) = stream.write_all(&encrypted).and_then(|_| stream.flush()) {
                    println!(screen, "Could not send message.");
                    println!(screen, "{}", err);
                    continue;
                };
            }
        }
    }
}
