extern crate cursive;

use *;
use self::cursive::Cursive;
use self::cursive::view::{Identifiable, ScrollStrategy};
use self::cursive::views::{BoxView, DummyView, EditView, LinearLayout, ListView, TextView};
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use std::thread;

pub struct Screen {
    line:   Mutex<mpsc::Receiver<String>>,
    log:    RwLock<Vec<(String, LogEntryId)>>,
    sink:   Mutex<mpsc::Sender<Box<Fn(&mut Cursive) + Send>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>
}
impl Screen {
    pub fn new() -> Screen {
        let (tx_line, rx_line) = mpsc::channel::<String>();
        let (tx_sink, rx_sink) = mpsc::channel::<Box<Fn(&mut Cursive) + Send>>();
        // Because the Cursive built-in sink returns a borrowed reference
        // (and I have to get it back out of the thread).

        let thread = thread::spawn(move || {
            let mut cursive = Cursive::new();
            cursive.set_fps(30);

            cursive.add_fullscreen_layer(
                LinearLayout::horizontal()
                    .child(LinearLayout::vertical()
                        .child(BoxView::with_full_screen(
                            TextView::empty()
                                .scrollable(true)
                                .scroll_strategy(ScrollStrategy::StickToBottom)
                                .with_id("log")
                        ))
                        .child(BoxView::with_full_width(
                            EditView::new()
                                .on_submit(move |cursive, line| {
                                    cursive.call_on_id("input", |input: &mut EditView| {
                                        input.set_content(String::new());
                                    });
                                    tx_line.send(line.to_string()).unwrap();
                                })
                                .with_id("input")
                        ))
                    )
                    .child(BoxView::with_full_height(
                        ListView::new()
                            .child("Channels", DummyView)
                            .delimiter()
                            // TODO .on_select(|_, name| { println!("{}", name); })
                            .with_id("channels")
                    ))
            );
            cursive.focus_id("input").unwrap();

            while cursive.is_running() {
                if let Ok(callback) = rx_sink.try_recv() {
                    callback(&mut cursive);
                }
                cursive.step();
            }
        });

        Screen {
            line:   Mutex::new(rx_line),
            log:    RwLock::new(Vec::new()),
            sink:   Mutex::new(tx_sink),
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
        self.sink.lock().unwrap().send(Box::new(|cursive: &mut Cursive| {
            cursive.call_on_id("input", |input: &mut EditView| {
                input.set_secret(false);
            });
        })).unwrap();
        Ok(self.line.lock().unwrap().recv().unwrap())
    }
    pub fn readpass(&self) -> Result<String, ()> {
        self.sink.lock().unwrap().send(Box::new(|cursive: &mut Cursive| {
            cursive.call_on_id("input", |input: &mut EditView| {
                input.set_secret(true);
            });
        })).unwrap();
        Ok(self.line.lock().unwrap().recv().unwrap())
    }

    pub fn update(&self, session: &Session) {
        let mut names: Vec<_> = session.channels.values()
            .map(|c| {
                let mut name = String::with_capacity(1 + c.name.len());
                name.push('#');
                name.push_str(&c.name); // God forgive me for cloning
                name
            })
            .collect();
        names.sort();

        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            cursive.call_on_id("channels", |list: &mut ListView| {
                list.clear();
                list.add_child("Channels", DummyView);
                list.add_delimiter();
                for name in &*names {
                    list.add_child(&name, DummyView);
                }
            });
        })).unwrap();
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
