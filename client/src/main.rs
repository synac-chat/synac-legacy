extern crate rustyline;
extern crate termion;

mod parser;

use rustyline::error::ReadlineError;
use std::io::{self, Write};
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
    let mut screen = AlternateScreen::from(io::stdout());
    println!(screen, "{}Welcome to unnamed.", termion::cursor::Goto(1, 1));
    println!(screen, "To set your name, type");
    println!(screen, "/nick <name>");
    println!(screen, "To connect to a server, type");
    println!(screen, "/connect <ip>");
    println!(screen);
    flush!(screen);

    let mut editor = rustyline::Editor::<()>::new();
    loop {
        let input = match editor.readline("> ") {
            Ok(ok) => ok,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("Couldn't read line: {}", err);
                break;
            }
        };
    }
}
