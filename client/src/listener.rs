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
                                        Packet::ChannelReceive(event) => {
                                            session.channels.insert(event.inner.id, event.inner);
                                        },
                                        Packet::ChannelDeleteReceive(event) => {
                                            session.channels.remove(&event.inner.id);
                                        },
                                        Packet::AttributeReceive(event) => {
                                            if event.new {
                                                let pos = if let Some(old) = session.attributes.get(&event.inner.id) {
                                                    Some(old.pos)
                                                } else { None };
                                                if let Some(pos) = pos {
                                                    if event.inner.pos > pos {
                                                        for attr in session.attributes.values_mut() {
                                                            if attr.pos > pos && attr.pos <= event.inner.pos {
                                                                attr.pos -= 1;
                                                            }
                                                        }
                                                    } else if event.inner.pos < pos {
                                                        for attr in session.attributes.values_mut() {
                                                            if attr.pos >= event.inner.pos && attr.pos < pos {
                                                                attr.pos += 1;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    for attr in session.attributes.values_mut() {
                                                        if attr.pos >= event.inner.pos {
                                                            attr.pos += 1;
                                                        }
                                                    }
                                                }
                                            }
                                            session.attributes.insert(event.inner.id, event.inner);
                                        },
                                        Packet::AttributeDeleteReceive(event) => {
                                            for attr in session.attributes.values_mut() {
                                                if attr.pos > event.inner.pos {
                                                    attr.pos -= 1;
                                                }
                                            }
                                            session.attributes.remove(&event.inner.id);
                                        },
                                        Packet::UserReceive(event) => {
                                            session.users.insert(event.inner.id, event.inner);
                                        },
                                        Packet::TypingReceive(event) => {
                                            println!("{} typing in channel #{}", event.author, event.channel);
                                        },
                                        Packet::MessageReceive(msg) => {
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
                                        Packet::MessageDeleteReceive(event) => {
                                            screen.delete(LogEntryId::Message(event.id));
                                            screen.repaint();
                                        },
                                        Packet::LoginSuccess(event) => {
                                            db.lock().unwrap().execute(
                                                "UPDATE servers SET token = ? WHERE ip = ?",
                                                &[&event.token, &session.addr.to_string()]
                                            ).unwrap();
                                        },
                                        Packet::RateLimited(time) => {
                                            println!("Slow down! You may try again in {} seconds.", time);
                                        }
                                        Packet::Err(common::ERR_LOGIN_INVALID) => {
                                            println!("Invalid credentials");
                                        },
                                        Packet::Err(common::ERR_UNKNOWN_CHANNEL) => {
                                            println!("This channel was deleted");
                                        },
                                        Packet::Err(common::ERR_UNKNOWN_ATTRIBUTE) => {
                                            println!("This attribute was deleted");
                                        },
                                        Packet::Err(common::ERR_LIMIT_REACHED) => {
                                            println!("Too short or too long. No idea which");
                                        },
                                        Packet::Err(common::ERR_MISSING_PERMISSION) => {
                                            println!("Missing permission");
                                        },
                                        Packet::Err(common::ERR_ATTR_INVALID_POS) => {
                                            println!("Invalid attribute position");
                                        },
                                        Packet::Err(common::ERR_ATTR_LOCKED_NAME) => {
                                            println!("Can not change the name of that attribute");
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
