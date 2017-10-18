extern crate cursive;

use *;
use self::cursive::Cursive;
use self::cursive::view::{Identifiable, ScrollStrategy};
use self::cursive::views::*;
use std::boxed::FnBox;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use std::thread;

macro_rules! id_touple {
    ($id:expr) => {
        (concat!("+", $id), concat!("=", $id), concat!("-", $id))
    }
}

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

    pub fn get_channel_overrides(&self, overrides: HashMap<usize, (u8, u8)>, session: &Session)
            -> Result<HashMap<usize, (u8, u8)>, ()> {
        let names: HashMap<_, _> = session.groups.iter()
            .map(|(id, group)| (*id, group.name.clone())) // Sorry for cloning, but I don't see any other way :(
            .collect();

        let (tx, rx): (mpsc::Sender<HashMap<usize, (u8, u8)>>, mpsc::Receiver<_>) = mpsc::channel();

        self.sink.lock().unwrap().send(Box::new(move |cursive: &mut Cursive| {
            let group_read    = Rc::new(RefCell::new(RadioGroup::new()));
            let group_write   = Rc::new(RefCell::new(RadioGroup::new()));
            let group_channel = Rc::new(RefCell::new(RadioGroup::new()));
            let group_read_clone    = Rc::clone(&group_read);
            let group_write_clone   = Rc::clone(&group_write);
            let group_channel_clone = Rc::clone(&group_channel);
            let group_read_clone2    = Rc::clone(&group_read);
            let group_write_clone2   = Rc::clone(&group_write);
            let group_channel_clone2 = Rc::clone(&group_channel);

            let names = Rc::new(names);
            let names_clone = Rc::clone(&names);

            let overrides = Rc::new(RefCell::new(overrides));
            let overrides_clone  = Rc::clone(&overrides);
            let overrides_clone2 = Rc::clone(&overrides);
            let overrides_clone3 = Rc::clone(&overrides);

            let last = Rc::new(RefCell::new(None));
            let last_clone = Rc::clone(&last);

            cursive.add_layer(Dialog::new()
                    .title("Channel override")
                    .content(LinearLayout::vertical()
                        .child(SelectView::new()
                            .popup()
                            .item_str("Select a role")
                            .on_submit(move |cursive: &mut Cursive, label: &str| {
                                if let Some(id) = *last.borrow() {
                                    let bitmask = bitmask_for_buttons(
                                        &group_read_clone.borrow(),
                                        &group_write_clone.borrow(),
                                        &group_channel_clone.borrow()
                                    );
                                    overrides_clone.borrow_mut().insert(id, bitmask);
                                }

                                if let Some(id) = label.split(":").next().and_then(|id| id.parse().ok()) {
                                    // This is the most horrible, hacky, disgusting code I've written this week.
                                    // I tried keeping a map of index -> id, but in the end I failed.

                                    *last.borrow_mut() = Some(id);

                                    buttons_for_bitmask(
                                        overrides_clone3.borrow_mut()
                                            .get(&id)
                                            .map(|item| *item)
                                            .unwrap_or_default(),
                                        cursive
                                    )
                                }
                            })
                            .with_id("role"))
                        .child(checkbox(&mut group_read.borrow_mut(), id_touple!("read"), "Read messages in this channel"))
                        .child(checkbox(&mut group_write.borrow_mut(), id_touple!("write"), "Send messages in this channel"))
                        .child(checkbox(&mut group_channel.borrow_mut(), id_touple!("channel"), "Manage this channel")))
                    .button("Add", move |cursive| {
                        cursive.add_layer(Dialog::around(SelectView::new()
                            .with_all_str(names.iter().map(|(id, name)| {
                                let mut result = id.to_string();
                                result.reserve(2 + name.len());
                                result.push_str(": ");
                                result.push_str(&name);
                                result
                            }))
                            .on_submit(move |cursive: &mut Cursive, string: &str| {
                                cursive.pop_layer();
                                cursive.call_on_id("role", |select: &mut SelectView| {
                                    select.add_item_str(string.to_string());
                                    let pos = select.len()-1;
                                    select.set_selection(pos);
                                });
                            })
                        ).dismiss_button("Cancel"));
                    })
                    .button("Finish", move |cursive| {
                        cursive.pop_layer();

                        if let Some(last) = *last_clone.borrow() {
                            let bitmask = bitmask_for_buttons(
                                &group_read_clone2.borrow(),
                                &group_write_clone2.borrow(),
                                &group_channel_clone2.borrow()
                            );
                            overrides_clone2.borrow_mut().insert(last, bitmask);
                        }
                        tx.send(overrides_clone2.replace(HashMap::new())).unwrap();
                    }));

            cursive.call_on_id("role", |select: &mut SelectView| {
                select.add_all_str(overrides.borrow().keys().map(|id| {
                    let mut result = id.to_string();
                    if let Some(name) = names_clone.get(&id) {
                        result.reserve(2 + name.len());
                        result.push_str(": ");
                        result.push_str(&name);
                    }
                    result
                }));
            });
        })).unwrap();

        Ok(rx.recv().unwrap())
    }
    pub fn get_user_groups(&self, _: Vec<usize>, _: &Session) -> Result<Vec<usize>, ()> {
        Err(())
    }
}
fn checkbox<S: Into<String>>(group: &mut RadioGroup<String>, id: (S, S, S), text: S) -> LinearLayout {
    // If only concat! would work on &'static str...
    LinearLayout::horizontal()
        .child(BoxView::with_fixed_width(40, TextView::new(text)))
        .child(DummyView)
        .child(group.button_str("").with_id(id.0))
        .child(group.button_str("").with_id(id.1))
        .child(group.button_str("").with_id(id.2))
}
fn bitmask_for_buttons(
    read:    &RadioGroup<String>,
    write:   &RadioGroup<String>,
    channel: &RadioGroup<String>
) -> (u8, u8) {
    let mut allow = 0;
    let mut deny = 0;

    if read.selected_id()    == 0 { allow |= common::PERM_READ }
    if write.selected_id()   == 0 { allow |= common::PERM_WRITE }
    if channel.selected_id() == 0 { allow |= common::PERM_MANAGE_CHANNELS }
    if read.selected_id()    == 2 { deny  |= common::PERM_READ }
    if write.selected_id()   == 2 { deny  |= common::PERM_WRITE }
    if channel.selected_id() == 2 { deny  |= common::PERM_MANAGE_CHANNELS }

    // Admit it, this isn't the worst code you've seen me write.

    (allow, deny)
}
fn buttons_for_bitmask(bitmask: (u8, u8), cursive: &mut Cursive) {
    let (allow, deny) = bitmask;

    macro_rules! toggle {
        ($allow:expr, $deny:expr, $($perm:ident as $button:expr),+) => {
            $(
                {
                    let touple = id_touple!($button);
                    let button = if $allow & common::$perm == common::$perm { touple.0 }
                            else if $deny  & common::$perm == common::$perm { touple.2 }
                            else { touple.1 };

                    cursive.call_on_id(button, |button: &mut RadioButton<String>| button.select());
                }
            )+
        }
    }
    toggle!(
        allow, deny,
        PERM_READ as "read",
        PERM_WRITE as "write",
        PERM_MANAGE_CHANNELS as "channel"
    );
}
