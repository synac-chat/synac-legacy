extern crate termion;

use *;
use rustyline::completion::{extract_word, Completer as RustyCompleter};
use rustyline::error::ReadlineError;
use rustyline;
use self::termion::screen::AlternateScreen;
use self::termion::{cursor, color};
use std::cmp;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Mutex, RwLock};

pub struct MuteGuard<'a>(&'a Screen);
impl<'a> Drop for MuteGuard<'a> {
    fn drop(&mut self) {
        self.0.mute.store(false, AtomicOrdering::Relaxed);
        self.0.repaint();
    }
}

pub fn sanitize(text: String) -> String {
    // text.retain(|c| {
    //     !c.is_control() || c == '\n' || c == '\t'
    // });
    // YES, that's right. Until that's stabilized, I'd rather clone the entire string
    // than using difficult workarounds.
    // TODO: Use `retain` to avoid allocation.
    text.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect()
}

struct Completer {
    session: Arc<Mutex<Option<Session>>>
}

impl RustyCompleter for Completer {
    fn complete(&self, line: &str, pos: usize) -> Result<(usize, Vec<String>), ReadlineError> {
        let break_chars = &[' ', '"', '\''].into_iter().cloned().collect();
        let (start, word) = extract_word(line, pos, &break_chars);

        let mut output = Vec::new();

        if let Some(ref session) = *self.session.lock().unwrap() {
            output.extend(session.state.users.values()
                .map(|user| user.name.clone())
                .filter(|name| name.starts_with(word)));
            output.extend(session.state.channels.values()
                .map(|channel| {
                    let mut name = String::with_capacity(channel.name.len() + 1);
                    name.push('#');
                    name.push_str(&channel.name);
                    name
                })
                .filter(|name| name.starts_with(word)));
        }

        Ok((start, output))
    }
}

pub struct Screen {
    editor: Mutex<rustyline::Editor<Completer>>,
    log:    RwLock<Vec<(String, LogEntryId)>>,
    mute:   AtomicBool,
    stdin:  Mutex<io::Stdin>,
    stdout: Mutex<AlternateScreen<io::Stdout>>,
    typing: RwLock<String>
}
impl Screen {
    pub fn new(session: &Arc<Mutex<Option<Session>>>) -> Screen {
        let stdin = io::stdin();
        stdin.lock();
        let stdout = io::stdout();
        stdout.lock();

        let mut editor = rustyline::Editor::<Completer>::new();
        editor.set_completer(Some(Completer {
            session: Arc::clone(session),
        }));

        Screen {
            editor: Mutex::new(editor),
            log:    RwLock::new(Vec::new()),
            mute:   AtomicBool::new(false),
            stdin:  Mutex::new(stdin),
            stdout: Mutex::new(AlternateScreen::from(stdout)),
            typing: RwLock::new(String::new())
        }
    }
    pub fn stop(&self) {}

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
    fn repaint_(&self, mut log: &[(String, LogEntryId)]) {
        let mut stdout = self.stdout.lock().unwrap();
        let (width, height) = termion::terminal_size().unwrap_or((50, 50));
        let cw =  width.saturating_sub(3) as usize;
        let ch = height.saturating_sub(3) as usize;
        loop {
            let mut lines = 0;
            for msg in log {
                lines += 1;

                let mut i = 0;
                for c in msg.0.chars() {
                    if (i != 0 && i == cw) || c == '\n' {
                        i = 0;
                        lines += 1;
                    } else {
                        i += 1;
                    }
                }
            }

            if lines <= ch {
                break;
            }
            log = &log[1..];
        }

        write!(stdout, "{}{}", termion::clear::All, cursor::Goto(1, 1)).unwrap();

        for &(ref text, id) in log {
            let indent_amount = text.find(": ").map(|i| i+2).unwrap_or_default();

            let mut first  = true;
            let mut indent = String::new();
            let mut skip   = 0;
            let mut text   = &**text;

            if text.is_empty() {
                writeln!(stdout).unwrap();
            }
            while !text.is_empty() {
                let indent_amount = if !first && indent.is_empty() {
                    indent = " ".repeat(indent_amount);
                    indent_amount
                } else { 0 };
                first = false;

                text = &text[skip..];
                skip = 0;

                let newline = text.find('\n').unwrap_or(std::usize::MAX);
                let width = cmp::min(newline, cmp::min(cw.saturating_sub(indent_amount), text.len()));
                if let LogEntryId::Sending = id {
                    writeln!(
                        stdout,
                        "{}{}{}{}",
                        indent,
                        color::Fg(color::LightBlack),
                        &text[..width],
                        color::Fg(color::Reset)
                    ).unwrap();
                } else {
                    writeln!(stdout, "{}{}", indent, &text[..width]).unwrap();
                }
                text = &text[width..];
                if width == newline {
                    skip += 1;
                }
            }
        }

        write!(stdout, "{}{}", cursor::Goto(1, height), self.typing.read().unwrap()).unwrap();
        write!(stdout, "{}> ", cursor::Goto(1, height-1)).unwrap();
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
        use self::termion::input::TermRead;
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

    pub fn typing_set(&self, typing: String) {
        if *self.typing.read().unwrap() == typing {
            return;
        }
        *self.typing.write().unwrap() = typing;
        self.repaint();
    }
    pub fn update(&self, _: &Session) {}

    pub fn get_channel_overrides(&self, mut overrides: HashMap<usize, (u8, u8)>, session: &Session)
            -> Result<HashMap<usize, (u8, u8)>, ()> {
        let _guard = self.mute();
        let log = Vec::with_capacity(2);

        macro_rules! println {
            () => { self.log(String::new()); };
            ($arg:expr) => { self.log(String::from($arg)); };
            ($($arg:expr),*) => { self.log(format!($($arg),*)); };
        }

        loop {
            let result = overrides.iter().fold(String::new(), |mut acc, (role, &(allow, deny))| {
                if !acc.is_empty() { acc.push_str(", "); }
                acc.push_str(&role.to_string());
                acc.push_str(": ");
                acc.push_str(&to_perm_string(allow, deny));
                acc
            });
            println!("Overrides: [{}]", result);
            println!("Commands: set, unset, quit");
            self.repaint_(&log);

            let line = self.readline()?;

            let parts = parser::parse(&line);
            if parts.is_empty() { continue; }
            let set = match &*parts[0] {
                "set" => true,
                "unset" => false,
                "quit" => break,
                _ => {
                    println!("Unknown command");
                    continue;
                }
            };

            if set && parts.len() != 3 {
                println!("Usage: set <id> [perms]");
                continue;
            } else if !set && parts.len() != 2 {
                println!("Usage: unset <id>");
                continue;
            }
            let id = match parts[1].parse() {
                Ok(ok) => ok,
                Err(_) => {
                    println!("Invalid ID");
                    continue;
                }
            };
            if let Some(group) = session.state.groups.get(&id) {
                if set {
                    let (mut allow, mut deny) = (0, 0);
                    if let Some(perms) = overrides.get(&id) {
                        allow = perms.0;
                        deny  = perms.1;
                    }
                    if !from_perm_string(&parts[2], &mut allow, &mut deny) {
                        println!("Invalid permission string");
                        continue;
                    }
                    overrides.insert(id, (allow, deny));
                    println!("Set \"{}\" to {}", group.name, to_perm_string(allow, deny));
                } else {
                    overrides.remove(&id);
                    println!("Unset: {}", group.name);
                }
            } else {
                println!("Could not find group");
            }
        }
        Ok(overrides)
    }
    pub fn get_user_groups(&self, mut groups: Vec<usize>, session: &Session) -> Result<Vec<usize>, ()> {
        let _guard = self.mute();
        let log = Vec::with_capacity(2);

        macro_rules! println {
            () => { self.log(String::new()); };
            ($arg:expr) => { self.log(String::from($arg)); };
            ($($arg:expr),*) => { self.log(format!($($arg),*)); };
        }

        loop {
            let result = groups.iter().fold(String::new(), |mut acc, item| {
                if !acc.is_empty() { acc.push_str(", "); }
                acc.push_str(&item.to_string());
                acc
            });
            println!("Groups: [{}]", result);
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
            if let Some(group) = session.state.groups.get(&id) {
                if group.pos == 0 {
                    println!("Unable to assign that group");
                    continue;
                }
                if add {
                    if !groups.contains(&id) {
                        groups.push(id);
                        groups.sort_unstable();
                    }
                    println!("Added: {}", group.name);
                } else {
                    let pos = groups.iter().position(|item| *item == id);
                    if let Some(pos) = pos {
                        groups.remove(pos);
                    }
                    // TODO remove_item once stable
                    println!("Removed: {}", group.name);
                }
            } else {
                println!("Could not find group");
            }
        }
        Ok(groups)
    }
}
