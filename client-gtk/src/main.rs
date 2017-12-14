extern crate gtk;

use gtk::prelude::*;
use gtk::{
    Align,
    Box as GtkBox,
    Button,
    Dialog,
    DialogFlags,
    Entry,
    Label,
    Orientation,
    ResponseType,
    Separator,
    Window,
    WindowType
};

fn main() {
    if let Err(err) = gtk::init() {
        eprintln!("gtk error: {}", err);
        return;
    }
    let window = Window::new(WindowType::Toplevel);
    window.set_title("Synac GTK+ client");
    window.set_default_size(1000, 700);

    let hbox = GtkBox::new(Orientation::Horizontal, 10);

    let servers = GtkBox::new(Orientation::Vertical, 2);
    let spacer = Label::new("");
    spacer.set_property_margin(10);
    servers.add(&spacer);
    servers.add(&Separator::new(Orientation::Vertical));
    servers.add(&Button::new_with_label("Server 1"));
    servers.add(&Button::new_with_label("Server 2"));
    servers.add(&Button::new_with_label("Server 3"));
    servers.add(&Button::new_with_label("Server 4"));
    let add = Button::new_with_label("add...");
    add.set_valign(Align::End);
    add.set_vexpand(true);
    let window_clone = window.clone();
    add.connect_clicked(move |_| {
        let dialog = Dialog::new_with_buttons(
            Some("Synac: Add server"),
            Some(&window_clone),
            DialogFlags::MODAL,
            &[("Cancel", ResponseType::Cancel.into()), ("Ok", ResponseType::Ok.into())]
        );
        let content = dialog.get_content_area();

        let server = Entry::new();
        server.set_placeholder_text("Server IP");
        content.add(&server);

        let hash = Entry::new();
        hash.set_placeholder_text("Server's certificate hash");
        content.add(&hash);

        dialog.connect_response(|me, response| {
            me.destroy();
            if response != ResponseType::Ok.into() {
                return;
            }
        });
        dialog.show_all();
    });
    servers.add(&add);
    hbox.add(&servers);

    hbox.add(&Separator::new(Orientation::Horizontal));

    let channels = GtkBox::new(Orientation::Vertical, 2);
    let server_name = Label::new("Server 1");
    server_name.set_property_margin(10);
    channels.add(&server_name);
    channels.add(&Separator::new(Orientation::Vertical));
    channels.add(&Button::new_with_label("Channel 1"));
    channels.add(&Button::new_with_label("Channel 2"));
    channels.add(&Button::new_with_label("Channel 3"));
    channels.add(&Button::new_with_label("Channel 4"));
    hbox.add(&channels);

    hbox.add(&Separator::new(Orientation::Horizontal));

    let content = GtkBox::new(Orientation::Vertical, 2);
    let channel_name = Label::new("Channel 1");
    channel_name.set_property_margin(10);
    content.add(&channel_name);
    content.add(&Separator::new(Orientation::Vertical));
    let messages = GtkBox::new(Orientation::Vertical, 2);
    messages.set_vexpand(true);
    content.add(&messages);
    let input = Entry::new();
    input.set_hexpand(true);
    messages.set_valign(Align::Center);
    input.set_placeholder_text("Send a message");
    content.add(&input);
    hbox.add(&content);

    window.add(&hbox);
    window.show_all();
    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        Inhibit(false)
    });

    gtk::main();
}
