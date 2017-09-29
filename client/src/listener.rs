use *;
use common::Packet;
use rusqlite::Connection as SqlConnection;
use std::io::Read;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use frontend;

pub fn listen(
    db: Arc<Mutex<SqlConnection>>,
    screen: Arc<frontend::Screen>,
    tx_sent: mpsc::SyncSender<()>,
    session: Arc<Mutex<Option<Session>>>,
    rx_stop: mpsc::Receiver<()>
) {
    macro_rules! println {
        () => { screen.log(String::new()); };
        ($($arg:expr),*) => { screen.log(format!($($arg),*)); }
    }

    let mut typing_last = Instant::now();
    let typing_check = Duration::from_secs(1);

    let mut size = true;
    let mut buf = vec![0; 2];
    let mut i = 0;
    loop {
        thread::sleep(Duration::from_millis(1));

        match rx_stop.try_recv() {
            Ok(_) |
            Err(mpsc::TryRecvError::Disconnected) => break,
            _ => {}
        }

        if let Some(ref mut session) = *session.lock().unwrap() {
            if typing_last.elapsed() >= typing_check {
                typing_last = Instant::now();
                let duration = Duration::from_secs(common::TYPING_TIMEOUT as u64); // TODO use const fn
                session.typing.retain(|_, time| time.elapsed() < duration);

                let people = session.typing.keys()
                    .filter_map(|&(author, channel)| {
                        if Some(channel) != session.channel {
                            return None;
                        }

                        session.users.get(&author).map(|ref user| &user.name)
                    });

                screen.typing_set(get_typing_string(people, session.typing.len()));
            }
            match session.stream.read(&mut buf[i..]) {
                Ok(0) => continue,
                Ok(read) => {
                    i += read;
                    if i >= buf.len() {
                        if size {
                            size = false;
                            let size = common::decode_u16(&buf) as usize;
                            buf = vec![0; size];
                            i = 0;
                        } else {
                            screen.delete(LogEntryId::Sending);

                            match common::deserialize(&buf) {
                                Ok(packet) => {
                                    match packet {
                                        Packet::ChannelDeleteReceive(event) => {
                                            session.channels.remove(&event.inner.id);
                                        },
                                        Packet::ChannelReceive(event) => {
                                            session.channels.insert(event.inner.id, event.inner);
                                        },
                                        Packet::GroupDeleteReceive(event) => {
                                            for attr in session.groups.values_mut() {
                                                if attr.pos > event.inner.pos {
                                                    attr.pos -= 1;
                                                }
                                            }
                                            session.groups.remove(&event.inner.id);
                                        },
                                        Packet::GroupReceive(event) => {
                                            if event.new {
                                                let pos = if let Some(old) = session.groups.get(&event.inner.id) {
                                                    Some(old.pos)
                                                } else { None };
                                                if let Some(pos) = pos {
                                                    if event.inner.pos > pos {
                                                        for attr in session.groups.values_mut() {
                                                            if attr.pos > pos && attr.pos <= event.inner.pos {
                                                                attr.pos -= 1;
                                                            }
                                                        }
                                                    } else if event.inner.pos < pos {
                                                        for attr in session.groups.values_mut() {
                                                            if attr.pos >= event.inner.pos && attr.pos < pos {
                                                                attr.pos += 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    for attr in session.groups.values_mut() {
                                                        if attr.pos >= event.inner.pos {
                                                            attr.pos += 1;
                                                        }
                                                    }
                                                }
                                            }
                                            session.groups.insert(event.inner.id, event.inner);
                                        },
                                        Packet::LoginSuccess(event) => {
                                            db.lock().unwrap().execute(
                                                "UPDATE servers SET token = ? WHERE ip = ?",
                                                &[&event.token, &session.addr.to_string()]
                                            ).unwrap();
                                        },
                                        Packet::MessageDeleteReceive(event) => {
                                            screen.delete(LogEntryId::Message(event.id));
                                            screen.repaint();
                                        },
                                        Packet::MessageReceive(msg) => {
                                            session.typing.remove(&(msg.author.id, msg.channel.id));

                                            if session.channel == Some(msg.channel.id) {
                                                screen.log_with_id(
                                                    format!(
                                                        "{} (ID #{}): {}",
                                                        msg.author.name,
                                                        msg.id,
                                                        String::from_utf8_lossy(&msg.text).replace("\x1b", "\\e")
                                                    ),
                                                    LogEntryId::Message(msg.id)
                                                );
                                            }
                                            if msg.author.id == session.id {
                                                session.last = Some((msg.id, msg.text));
                                            }
                                        },
                                        Packet::RateLimited(time) => {
                                            println!("Slow down! You may try again in {} seconds.", time);
                                        }
                                        Packet::TypingReceive(event) => {
                                            session.typing.insert((event.author, event.channel), Instant::now());
                                        },
                                        Packet::UserReceive(event) => {
                                            session.users.insert(event.inner.id, event.inner);
                                        },
                                        Packet::Err(common::ERR_ATTR_INVALID_POS) => {
                                            println!("Invalid group position");
                                        },
                                        Packet::Err(common::ERR_ATTR_LOCKED_NAME) => {
                                            println!("Can not change the name of that group");
                                        },
                                        Packet::Err(common::ERR_LIMIT_REACHED) => {
                                            println!("Too short or too long. No idea which");
                                        },
                                        Packet::Err(common::ERR_LOGIN_INVALID) => {
                                            println!("Invalid credentials");
                                        },
                                        Packet::Err(common::ERR_MISSING_PERMISSION) => {
                                            println!("Missing permission");
                                        },
                                        Packet::Err(common::ERR_UNKNOWN_CHANNEL) => {
                                            println!("This channel was deleted");
                                        },
                                        Packet::Err(common::ERR_UNKNOWN_GROUP) => {
                                            println!("This group was deleted");
                                        },
                                        packet => {
                                            println!("Unimplemented packet: {:?}", packet);
                                        },
                                    }
                                    screen.update(session);
                                },
                                Err(err) => {
                                    println!("Failed to deserialize message!");
                                    println!("{}", err);
                                }
                            };
                            let _ = tx_sent.try_send(());
                            size = true;
                            buf = vec![0; 2];
                            i = 0;
                        }
                    }
                },
                Err(_) => {}
            }
        }
    }
}
