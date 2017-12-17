use std::collections::HashMap;
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
                let original = Some(messages[i].timestamp);
                loop {
                    i += 1;
                    if messages.get(i).map(|msg| msg.timestamp) != original {
                        break;
                    }
                }
                i
            }
        };
        messages.insert(i, msg);
    }
    pub fn remove(&mut self, id: usize) {
        let messages = self.messages.get_mut(&id).unwrap();
        if let Some(i) = messages.iter().position(|msg| msg.id == id) {
            messages.remove(i);
        }
    }
    pub fn get(&self, id: usize) -> &[Message] {
        self.messages.get(&id).map(|inner| &*inner as &[Message]).unwrap_or(&[])
    }
    pub fn has(&self, id: usize) -> bool {
        self.messages.contains_key(&id)
    }
}
