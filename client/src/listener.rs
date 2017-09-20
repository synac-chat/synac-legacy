use *;
use common::Packet;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use termion::cursor;

pub fn listen(session: Arc<Mutex<Option<Session>>>, sent_sender: mpsc::SyncSender<()>) {
    let mut size = true;
    let mut buf = vec![0; 2];
    let mut i = 0;
    loop {
        if let Some(ref mut session) = *session.lock().unwrap() {
            match session.stream.read(&mut buf[i..]) {
                Ok(0) => break,
                Ok(read) => {
                    i += read;
                    if i >= buf.len() {
                        if size {
                            size = false;
                            let size = common::decode_u16(&buf) as usize;
                            buf = vec![0; size];
                            i = 0;
                        } else {
                            match common::deserialize(&buf) {
                                Ok(Packet::ChannelReceive(event)) => {
                                    session.channels.insert(event.inner.id, event.inner);
                                },
                                Ok(Packet::ChannelDeleteReceive(event)) => {
                                    session.channels.remove(&event.inner.id);
                                },
                                Ok(Packet::AttributeReceive(event)) => {
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
                                Ok(Packet::AttributeDeleteReceive(event)) => {
                                    for attr in session.attributes.values_mut() {
                                        if attr.pos > event.inner.pos {
                                            attr.pos -= 1;
                                        }
                                    }
                                    session.attributes.remove(&event.inner.id);
                                },
                                Ok(Packet::UserReceive(event)) => {
                                    session.users.insert(event.inner.id, event.inner);
                                },
                                Ok(Packet::MessageReceive(msg)) => {
                                    if session.channel == Some(msg.channel.id) {
                                        println!("{}\r{} (ID #{}): {}", cursor::Restore, msg.author.name, msg.id,
                                                 String::from_utf8_lossy(&msg.text));
                                        to_terminal_bottom();
                                        flush!();
                                    }
                                    if msg.author.id == session.id {
                                        session.last = Some((msg.id, msg.text));
                                    }
                                },
                                Ok(Packet::MessageDeleteReceive(event)) => {
                                    println!("{}Deleted message: {}", cursor::Restore, event.id);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(Packet::Err(common::ERR_UNKNOWN_CHANNEL)) => {
                                    println!("{}It appears this channel was deleted", cursor::Restore);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(Packet::Err(common::ERR_UNKNOWN_ATTRIBUTE)) => {
                                    println!("{}It appears this attribute was deleted", cursor::Restore);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(Packet::Err(common::ERR_LIMIT_REACHED)) => {
                                    println!("{}Too short or too long. No idea which", cursor::Restore);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(Packet::Err(common::ERR_MISSING_PERMISSION)) => {
                                    println!("{}\rMissing permission", cursor::Restore);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(Packet::Err(common::ERR_ATTR_INVALID_POS)) => {
                                    println!("{}Invalid attribute position", cursor::Restore);
                                    to_terminal_bottom();
                                    flush!();
                                },
                                Ok(_) => {
                                    unimplemented!();
                                },
                                Err(err) => {
                                    println!("Failed to deserialize message!");
                                    println!("{}", err);
                                    continue;
                                }
                            };
                            size = true;
                            buf = vec![0; 2];
                            i = 0;
                        }
                        let _ = sent_sender.try_send(());
                    }
                },
                Err(_) => {}
            }
        }
        thread::sleep(Duration::from_millis(1));
        // thread::sleep(Duration::from_millis(250));
    }
}
