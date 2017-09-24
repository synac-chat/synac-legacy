use *;
use rustyline::error::ReadlineError;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Mutex, RwLock};
use termion::{cursor, color};
use termion::screen::AlternateScreen;
use {termion, rustyline};

pub struct MuteGuard<'a>(&'a Screen);
impl<'a> Drop for MuteGuard<'a> {
    fn drop(&mut self) {
        self.0.mute.store(false, AtomicOrdering::Relaxed);
        self.0.repaint();
    }
}

pub struct Screen {
    editor: Mutex<rustyline::Editor<()>>,
    log:    RwLock<Vec<(String, LogEntryId)>>,
    mute:   AtomicBool,
    stdin:  Mutex<io::Stdin>,
    stdout: Mutex<AlternateScreen<io::Stdout>>
}
impl Screen {
    pub fn new() -> Screen {
        let stdin = io::stdin();
        stdin.lock();
        let stdout = io::stdout();
        stdout.lock();
        Screen {
            editor: Mutex::new(rustyline::Editor::<()>::new()),
            log:    RwLock::new(Vec::new()),
            mute:   AtomicBool::new(false),
            stdin:  Mutex::new(stdin),
            stdout: Mutex::new(AlternateScreen::from(stdout))
        }
    }

    pub fn clear(&self) {
        self.log.write().unwrap().clear();
        self.repaint();
    }

    pub fn log(&self, text: String) {
        self.log_with_id(text, LogEntryId::None);
    }
    pub fn log_with_id(&self, mut text: String, id: LogEntryId) {
        if let LogEntryId::Message(_) = id {
            if let Some(text2) = self.edit(text, id) {
                text = text2;
            } else {
                self.repaint();
                return;
            }
        }
        self.log.write().unwrap().push((text, id));
        self.repaint();
    }
    pub fn edit(&self, text: String, id: LogEntryId) -> Option<String> {
        let mut log = self.log.write().unwrap();
        for &mut (ref mut entry_text, entry_id) in &mut *log {
            if entry_id == id {
                *entry_text = text;
                return None;
            }
        }
        Some(text)
    }
    pub fn delete(&self, id: LogEntryId) {
        let mut log = self.log.write().unwrap();
        let pos = log.iter().position(|&(_, entry_id)| entry_id == id);
        if let Some(pos) = pos {
            log.remove(pos);
        }
        // TODO: remove_item once stable
    }

    pub fn repaint(&self) {
        if self.mute.load(AtomicOrdering::Relaxed) {
            return;
        }
        self.repaint_(&**self.log.read().unwrap());
    }
    fn repaint_(&self, log: &[(String, LogEntryId)]) {
        let mut stdout = self.stdout.lock().unwrap();

        let (_, height) = termion::terminal_size().unwrap_or((50, 50));

        let log = &log[log.len().saturating_sub(height as usize - 3)..];
        // TODO: Add a way to scroll...

        write!(stdout, "{}{}", termion::clear::All, cursor::Goto(1, 1)).unwrap();

        for &(ref text, id) in log {
            if let LogEntryId::Sending = id {
                writeln!(stdout, "{}{}{}", color::Fg(color::LightBlack), text, color::Fg(color::Reset)).unwrap();
            } else {
                writeln!(stdout, "{}", text).unwrap();
            }
        }

        write!(stdout, "{}", cursor::Goto(1, height-1)).unwrap();
        write!(stdout, "> ").unwrap();
        stdout.flush().unwrap();
    }
    pub fn mute(&self) -> MuteGuard {
        self.mute.store(true, AtomicOrdering::Relaxed);
        MuteGuard(self)
    }

    pub fn readline(&self) -> Result<String, ()> {
        let mut error = None;
        let ret = {
            let mut editor = self.editor.lock().unwrap();
            match editor.readline("> ") {
                Ok(some) => { editor.add_history_entry(&some); Ok(some) },
                Err(ReadlineError::Interrupted) |
                Err(ReadlineError::Eof) => Err(()),
                Err(err) => {
                    error = Some(err);
                    Err(())
                }
            }
        };
        if let Some(err) = error {
            self.log(format!("Failed to read line: {}", err));
        }
        ret
    }
    pub fn readpass(&self) -> Result<String, ()> {
        use termion::input::TermRead;
        let mut error = None;
        let ret = {
            match self.stdin.lock().unwrap().read_passwd(&mut *self.stdout.lock().unwrap()) {
                Ok(Some(some)) => Ok(some),
                Ok(None) => Err(()),
                Err(err) => {
                    error = Some(err);
                    Err(())
                }
            }
        };
        if let Some(err) = error {
            self.log(format!("Failed to read password: {}", err));
        }
        ret
    }

    pub fn get_user_attributes(&self, mut attributes: Vec<usize>, session: &Session) -> Result<Vec<usize>, ()> {
        let _guard = self.mute();
        let mut log = Vec::with_capacity(2);

        macro_rules! println {
            ($($arg:expr),+) => { log.push((format!($($arg),+), LogEntryId::None)) }
        }

        loop {
            let result = attributes.iter().fold(String::new(), |mut acc, item| {
                if !acc.is_empty() { acc.push_str(", "); }
                acc.push_str(&item.to_string());
                acc
            });
            println!("Attributes: [{}]", result);
            println!("Commands: add, remove, quit");
            self.repaint_(&log);

            let line = self.readline()?;

            let parts = parser::parse(&line);
            if parts.is_empty() { continue; }
            let add = match &*parts[0] {
                "add" => true,
                "remove" => false,
                "quit" => break,
                _ => {
                    println!("Unknown command");
                    continue;
                }
            };

            if parts.len() != 2 {
                println!("Usage: add/remove <id>");
                continue;
            }
            let id = match parts[1].parse() {
                Ok(ok) => ok,
                Err(_) => {
                    println!("Invalid ID");
                    continue;
                }
            };
            if let Some(attribute) = session.attributes.get(&id) {
                if attribute.pos == 0 {
                    println!("Unable to assign that attribute");
                    continue;
                }
                if add {
                    println!("Added: {}", attribute.name);
                    attributes.push(id);
                } else {
                    println!("Removed: {}", attribute.name);
                    let pos = attributes.iter().position(|item| *item == id);
                    if let Some(pos) = pos {
                        attributes.remove(pos);
                    }
                    // TODO remove_item once stable
                }
            } else {
                println!("Could not find attribute");
            }
        }
        Ok(attributes)
    }
}
