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

fn main() {
    let db = match SqlConnection::open("data.sqlite") {
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
    let stream: Arc<Mutex<Option<(usize, SslStream<TcpStream>)>>> = Arc::new(Mutex::new(None));
    let stream_clone = stream.clone();

    let _screen = AlternateScreen::from(io::stdout());

    println!("{}Welcome, {}", cursor::Goto(1, 1), nick);
    println!("To change your name, type");
    println!("/nick <name>");
    println!("To connect to a server, type");
    println!("/connect <ip>");
    println!();

    let (sent_sender, sent_receiver) = mpsc::channel();

    thread::spawn(move || {
        let mut size = true;
        let mut buf = vec![0; 2];
        let mut i = 0;
        loop {
            if let Some((id, ref mut stream)) = *stream_clone.lock().unwrap() {
                match stream.read(&mut buf[i..]) {
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
                                        println!("{}\r{}: {}", cursor::Restore, msg.author.name,
                                                 String::from_utf8_lossy(&msg.text));
                                        if msg.author.id == id {
                                            sent_sender.send(()).unwrap();
                                        } else {
                                            to_terminal_bottom();
                                        }
                                        flush!();
                                    },
                                    Ok(_) => {
                                        unimplemented!();
                                    },
                                    Err(err) => {
                                        eprintln!("Failed to deserialize message!");
                                        eprintln!("{}", err);
                                        continue;
                                    }
                                };
                                size = true;
                                buf = vec![0; 2];
                                i = 0;
                            }
                        }
                    },
                    Err(_) => {}
                }
            }
            // thread::sleep(Duration::from_secs(1));
            thread::sleep(Duration::from_millis(250));
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
                eprintln!("Couldn't read line: {}", err);
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

            macro_rules! usage {
                ($amount:expr, $usage:expr) => {
                    if args.len() != $amount {
                        println!(concat!("Usage: /", $usage));
                        continue;
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
                    let mut stream = stream.lock().unwrap();
                    if stream.is_some() {
                        println!("Please disconnect first.");
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
                                eprintln!("Couldn't read line: {}", err);
                                break;
                            }
                        };

                        db.execute(
                            "INSERT INTO servers (ip, key) VALUES (?, ?)",
                            &[&addr.to_string(), &public_key]
                        ).unwrap();
                    }
                    let stream_ = match TcpStream::connect(addr) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!("Could not connect!");
                            println!("{}", err);
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

                        if let Err(err) = common::write(&mut stream_, &packet) {
                            println!("Could not request login");
                            println!("{}", err);
                            continue;
                        }

                        match common::read(&mut stream_) {
                            Ok(Packet::LoginSuccess(login)) => {
                                id = Some(login.id);
                                if login.created {
                                    eprintln!("Tried to log in with your token: Apparently an account was created.");
                                    eprintln!("I think you should stay away from this server. It's weird.");
                                    continue;
                                }
                                println!("Logged in as user #{}", login.id);
                            },
                            Ok(Packet::Err(code)) => match code {
                                common::ERR_LOGIN_INVALID |
                                common::ERR_LOGIN_EMPTY => {},
                                common::ERR_LOGIN_BANNED => {
                                    eprintln!("Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    eprintln!("This account is a bot account.");
                                    continue;
                                },
                                _ => {
                                    eprintln!("The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                eprintln!("The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                eprintln!("Failed to read from server");
                                eprintln!("{}", err);
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
                                eprintln!("Failed to read password");
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

                        if let Err(err) = common::write(&mut stream_, &packet) {
                            println!("Could not request login");
                            println!("{}", err);
                            continue;
                        }

                        match common::read(&mut stream_) {
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
                                common::ERR_LOGIN_INVALID => {},
                                common::ERR_LOGIN_BANNED => {
                                    eprintln!("Oh noes, you have been banned from this server :(");
                                    continue;
                                },
                                common::ERR_LOGIN_BOT => {
                                    eprintln!("This account is a bot account.");
                                    continue;
                                },
                                _ => {
                                    eprintln!("The server responded with an invalid error :/");
                                    continue;
                                }
                            },
                            Ok(_) => {
                                eprintln!("The server responded with an invalid packet :/");
                                continue;
                            }
                            Err(err) => {
                                eprintln!("Failed to read from server");
                                eprintln!("{}", err);
                                continue;
                            }
                        }
                    }
                    stream_.get_ref().set_nonblocking(true).expect("Failed to make stream non-blocking");
                    *stream = Some((id.unwrap(), stream_));
                },
                "disconnect" => {
                    usage!(0, "disconnect");
                    let mut stream = stream.lock().unwrap();
                    if let Some((_, ref mut stream)) = *stream {
                        let _ = common::write(stream, &Packet::Close);
                    } else {
                        eprintln!("You're not connected to a server");
                        continue;
                    }
                    *stream = None;
                },
                "forget" => {
                    usage!(1, "forget <ip>");
                    let addr = match parse_ip(&args[0]) {
                        Some(some) => some,
                        None => {
                            eprintln!("Not a valid IP");
                            continue;
                        }
                    };
                    db.execute("DELETE FROM servers WHERE ip = ?", &[&addr.to_string()]).unwrap();
                },
                _ => {
                    println!("Unknown command");
                }
            }
            continue;
        }

        match *stream.lock().unwrap() {
            None => {
                println!("You're not connected to a server");
                continue;
            },
            Some((_, ref mut stream)) => {
                print!("{}{}: {}{}", color::Fg(color::LightBlack), nick, input, color::Fg(color::Reset));
                flush!();
                let packet = Packet::MessageCreate(common::MessageCreate {
                    channel: 0,
                    text: input.into_bytes()
                });

                if let Err(err) = common::write(stream, &packet) {
                    println!("\rFailed to deliver message");
                    println!("{}", err);
                    continue;
                }
            }
        }
        // Could only happen if message was sent
        sent_receiver.recv().unwrap();
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
