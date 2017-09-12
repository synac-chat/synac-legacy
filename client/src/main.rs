extern crate rustyline;
extern crate termion;
extern crate common;

mod parser;

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
        let mut input = match editor.readline("> ") {
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
                    stream = Some(match TcpStream::connect((ip, port)) {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!(screen, "Could not connect!");
                            println!(screen, "Scary debug details: {}", err);
                            continue;
                        }
                    });
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
            Some(ref mut stream) => {
                input.push('\n');
                let encoded = common::serialize(common::Packet::MessageCreate(common::MessageCreate {
                    channel: 0,
                    message: input
                })).expect("Serializing failed! Oh no! PANIC!");
                if let Err(err) = stream.write_all(&encoded) {
                    eprintln!("Could not send message.");
                    eprintln!("{}", err);
                    continue;
                };
            }
        }
    }
}
