extern crate cursive;

use *;
use self::cursive::Cursive;
use self::cursive::view::{Identifiable, ScrollStrategy};
use self::cursive::views::*;
use std::boxed::FnBox;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use std::thread;

pub fn sanitize(mut text: String) -> String {
    text.retain(|c| {
        !c.is_control() || c == '\n' || c == '\t'
    });
    text
}

pub struct Screen {
    line:   Mutex<mpsc::Receiver<String>>,
    log:    RwLock<Vec<(String, LogEntryId)>>,
    sink:   Mutex<mpsc::Sender<Box<FnBox(&mut Cursive) + Send>>>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    typing: Arc<Mutex<Option<Box<FnMut(&str) + Send>>>>
}
impl Screen {
    pub fn new() -> Screen {
        let (tx_line, rx_line) = mpsc::channel::<String>();
        let (tx_sink, rx_sink) = mpsc::channel::<Box<FnBox(&mut Cursive) + Send>>();
        // Because the Cursive built-in sink returns a borrowed reference
        // (and I have to get it back out of the thread).

        let typing: Arc<Mutex<Option<Box<FnMut(&str) + Send>>>> = Arc::new(Mutex::new(None));
        let typing_clone1 = Arc::clone(&typing);
        let typing_clone2 = Arc::clone(&typing);

        let thread = thread::spawn(move || {
            let mut cursive = Cursive::new();
            cursive.set_fps(10);

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
                                .on_edit(move |_, line, _| {
                                    if let Some(ref mut callback) = *typing_clone1.lock().unwrap() {
                                        callback(line);
                                    }
                                })
                                .on_submit(move |cursive, line| {
                                    cursive.call_on_id("input", |input: &mut EditView| {
                                        input.set_content(String::new());
                                        input.set_secret(false);
                                    });
                                    *typing_clone2.lock().unwrap() = None;
                                    tx_line.send(line.to_string()).unwrap();
                                })
                                .with_id("input")
                        ))
                        .child(BoxView::with_full_width(
                            TextView::empty()
                                .with_id("typing")
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
                    callback.call_box((&mut cursive,));
                }
                cursive.step();
            }
        });

        Screen {
            line:   Mutex::new(rx_line),
            log:    RwLock::new(Vec::new()),
            sink:   Mutex::new(tx_sink),
            thread: Mutex::new(Some(thread)),
            typing: typing
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
        let log = log.iter().fold(String::new(), |mut acc, entry| {
            acc.push_str(&entry.0);
            acc.push('\n');
            acc
        });
        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            cursive.call_on_id("log", move |view: &mut TextView| {
                view.set_content(log);
            });
        })).unwrap();
    }

    pub fn readline(&self, typing: Option<Box<FnMut(&str) + Send>>) -> Result<String, ()> {
        if typing.is_some() {
            *self.typing.lock().unwrap() = typing;
        }
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

    pub fn typing_set(&self, typing: String) {
        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            cursive.call_on_id("typing", move |view: &mut TextView| {
                view.set_content(typing);
            });
        })).unwrap();
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

    pub fn get_user_groups(&self, _: Vec<usize>, _: &Session) -> Result<Vec<usize>, ()> {
        Err(())
    }
    pub fn get_channel_overrides(&self, overrides: HashMap<usize, (u8, u8)>, session: &Session)
            -> Result<HashMap<usize, (u8, u8)>, ()> {
        let names: HashMap<usize, String> = session.groups.iter()
            .map(|(id, group)| (*id, group.name.clone()))
            .collect();

        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            let mut group_read    = RadioGroup::new();
            let mut group_write   = RadioGroup::new();
            let mut group_channel = RadioGroup::new();

            let names = Rc::new(names);
            let names_clone = Rc::clone(&names);

            cursive.add_layer(Dialog::new()
                    .title("Channel override")
                    .content(LinearLayout::vertical()
                        .child(SelectView::new()
                            .popup()
                            .item_str("Select a role")
                            .with_id("role"))
                        .child(checkbox(&mut group_read, "Read messages in this channel"))
                        .child(checkbox(&mut group_write, "Send messages in this channel"))
                        .child(checkbox(&mut group_channel, "Manage this channel")))
                    .button("Add", move |cursive| {
                        cursive.add_layer(Dialog::around(SelectView::new()
                            .with_all_str(names_clone.iter().map(|(id, name)| {
                                let mut result = id.to_string();
                                result.reserve(2 + name.len());
                                result.push_str(": ");
                                result.push_str(&name);
                                result
                            }))
                            .on_submit(|cursive: &mut Cursive, string: &str| {
                                cursive.pop_layer();
                                cursive.call_on_id("role", |select: &mut SelectView| {
                                    select.add_item_str(string.to_string());
                                });
                            })
                        ).dismiss_button("Cancel"));
                    })
                    .button("Finish", |cursive| {
                        cursive.pop_layer();
                        // TODO return stuff
                    }));

            cursive.call_on_id("role", |select: &mut SelectView| {
                select.add_all_str(overrides.keys().map(|id| {
                    let mut result = id.to_string();
                    if let Some(name) = names.get(&id) {
                        result.reserve(2 + name.len());
                        result.push_str(": ");
                        result.push_str(&name);
                    }
                    result
                }));
            });
        })).unwrap();
        Err(())
    }
}
fn checkbox<S: Into<String>>(group: &mut RadioGroup<String>, text: S) -> LinearLayout {
    LinearLayout::horizontal()
        .child(BoxView::with_fixed_width(40, TextView::new(text)))
        .child(DummyView)
        .child(group.button_str(""))
        .child(group.button_str(""))
        .child(group.button_str(""))
}
