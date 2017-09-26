extern crate cursive;

use *;
use self::cursive::Cursive;
use self::cursive::view::SizeConstraint;
use self::cursive::views::{BoxView, Dialog, IdView, TextView};
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use std::thread;

pub struct Screen {
    log:    RwLock<Vec<(String, LogEntryId)>>,
    sink:   Mutex<mpsc::Sender<Box<Fn(&mut Cursive) + Send>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>
}
impl Screen {
    pub fn new() -> Screen {
        let (tx, rx) = mpsc::channel::<Box<Fn(&mut Cursive) + Send>>();

        let thread = thread::spawn(move || {
            let mut cursive = Cursive::new();
            cursive.set_fps(10);

            cursive.add_layer(BoxView::new(
                SizeConstraint::Full,
                SizeConstraint::Full,
                IdView::new("log", TextView::new("Hello World"))
            ));

            while cursive.is_running() {
                rx.recv().unwrap()(&mut cursive);
                cursive.step();
            }
        });

        Screen {
            log:    RwLock::new(Vec::new()),
            sink:   Mutex::new(tx),
            thread: Mutex::new(Some(thread))
        }
    }
    pub fn stop(&self) {
        if let Some(thread) = self.thread.lock().unwrap().take() {
            self.sink.lock().unwrap().send(Box::new(|cursive: &mut Cursive| cursive.quit())).unwrap();
            thread.join().unwrap();
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
        self.repaint_(&**self.log.read().unwrap());
    }
    fn repaint_(&self, log: &[(String, LogEntryId)]) {
        let text = log.iter().fold(String::new(), |mut acc, entry| {
            acc.push_str(&entry.0);
            acc.push('\n');
            acc
        });
        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            let text = text.clone();
            cursive.call_on_id("log", move |log: &mut TextView| {
                log.set_content(text);
            });
        })).unwrap();
    }

    pub fn readline(&self) -> Result<String, ()> {
        thread::sleep(std::time::Duration::from_secs(5));
        Err(())
        // let mut error = None;
        // let ret = {
        //     let mut editor = self.editor.lock().unwrap();
        //     match editor.readline("> ") {
        //         Ok(some) => { editor.add_history_entry(&some); Ok(some) },
        //         Err(ReadlineError::Interrupted) |
        //         Err(ReadlineError::Eof) => Err(()),
        //         Err(err) => {
        //             error = Some(err);
        //             Err(())
        //         }
        //     }
        // };
        // if let Some(err) = error {
        //     self.log(format!("Failed to read line: {}", err));
        // }
        // ret
    }
    pub fn readpass(&self) -> Result<String, ()> {
        Err(())
        // use termion::input::TermRead;
        // let mut error = None;
        // let ret = {
        //     match self.stdin.lock().unwrap().read_passwd(&mut *self.stdout.lock().unwrap()) {
        //         Ok(Some(some)) => Ok(some),
        //         Ok(None) => Err(()),
        //         Err(err) => {
        //             error = Some(err);
        //             Err(())
        //         }
        //     }
        // };
        // if let Some(err) = error {
        //     self.log(format!("Failed to read password: {}", err));
        // }
        // ret
    }

    pub fn get_user_attributes(&self, mut attributes: Vec<usize>, session: &Session) -> Result<Vec<usize>, ()> {
        Err(())
        // let _guard = self.mute();
        // let mut log = Vec::with_capacity(2);

        // macro_rules! println {
        //     ($($arg:expr),+) => { log.push((format!($($arg),+), LogEntryId::None)) }
        // }

        // loop {
        //     let result = attributes.iter().fold(String::new(), |mut acc, item| {
        //         if !acc.is_empty() { acc.push_str(", "); }
        //         acc.push_str(&item.to_string());
        //         acc
        //     });
        //     println!("Attributes: [{}]", result);
        //     println!("Commands: add, remove, quit");
        //     self.repaint_(&log);

        //     let line = self.readline()?;

        //     let parts = parser::parse(&line);
        //     if parts.is_empty() { continue; }
        //     let add = match &*parts[0] {
        //         "add" => true,
        //         "remove" => false,
        //         "quit" => break,
        //         _ => {
        //             println!("Unknown command");
        //             continue;
        //         }
        //     };

        //     if parts.len() != 2 {
        //         println!("Usage: add/remove <id>");
        //         continue;
        //     }
        //     let id = match parts[1].parse() {
        //         Ok(ok) => ok,
        //         Err(_) => {
        //             println!("Invalid ID");
        //             continue;
        //         }
        //     };
        //     if let Some(attribute) = session.attributes.get(&id) {
        //         if attribute.pos == 0 {
        //             println!("Unable to assign that attribute");
        //             continue;
        //         }
        //         if add {
        //             println!("Added: {}", attribute.name);
        //             attributes.push(id);
        //         } else {
        //             println!("Removed: {}", attribute.name);
        //             let pos = attributes.iter().position(|item| *item == id);
        //             if let Some(pos) = pos {
        //                 attributes.remove(pos);
        //             }
        //             // TODO remove_item once stable
        //         }
        //     } else {
        //         println!("Could not find attribute");
        //     }
        // }
        // Ok(attributes)
    }
}
