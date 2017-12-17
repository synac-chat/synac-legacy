use chrono::{Datelike, Local, Timelike, TimeZone, Utc};
use std::collections::HashMap;
use std::fmt::Write;
use synac::common::Message;

pub struct Messages {
    messages: HashMap<usize, Vec<Message>>
}
impl Messages {
    pub fn new() -> Self {
        Messages {
            messages: HashMap::new()
        }
    }
    pub fn add(&mut self, msg: Message) {
        let messages = self.messages.entry(msg.channel).or_insert_with(Vec::default);
        let i = match messages.binary_search_by_key(&msg.timestamp, |msg| msg.timestamp) {
            Err(i) => i,
            Ok(mut i) => {
                let original_timestamp = Some(messages[i].timestamp);
                let original_id = Some(messages[i].id);
                while messages.get(i-1).map(|msg| msg.timestamp) == original_timestamp {
                    i -= 1;
                }
                loop {
                    let message = messages.get_mut(i);
                    if message.as_ref().map(|msg| msg.id) == original_id {
                        *message.unwrap() = msg;
                        return;
                    }
                    if message.map(|msg| msg.timestamp) != original_timestamp {
                        break;
                    }
                    i += 1
                }
                i+1
            }
        };
        messages.insert(i, msg);
    }
    pub fn remove(&mut self, id: usize) {
        for messages in self.messages.values_mut() {
            if let Some(i) = messages.iter().position(|msg| msg.id == id) {
                messages.remove(i);
            }
        }
    }
    pub fn get(&self, channel: usize) -> &[Message] {
        self.messages.get(&channel).map(|inner| &*inner as &[Message]).unwrap_or(&[])
    }
    pub fn has(&self, channel: usize) -> bool {
        self.messages.contains_key(&channel)
    }
}

pub fn format(output: &mut String, timestamp: i64) {
    let time  = Utc.timestamp(timestamp, 0);
    let local = time.with_timezone(&Local);
    let now   = Local::now();
    let diff  = now.signed_duration_since(local);

    match diff.num_days() {
        0 => output.push_str("Today"),
        1 => output.push_str("Yesterday"),
        2 => output.push_str("Two days ago"),
        3 => output.push_str("Three days ago"),
        x if x < 7 => output.push_str("A few days ago"),
        7 => output.push_str("A week ago"),
        _ => {
            write!(output, "{}-{}-{}", local.year(), local.month(), local.day()).unwrap();
        }
    }
    output.push_str(" at ");
    let (is_pm, hour) = local.hour12();
    write!(output, "{}:{:02} ", hour, local.minute()).unwrap();
    output.push_str(if is_pm { "PM" } else { "AM" });
}
