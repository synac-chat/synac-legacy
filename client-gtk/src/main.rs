#[macro_use] extern crate failure;
extern crate gtk;
extern crate rusqlite;
extern crate synac;
extern crate xdg;

mod connections;

use gtk::prelude::*;
use gtk::{
    Align,
    Box as GtkBox,
    Button,
    ButtonsType,
    Dialog,
    DialogFlags,
    Entry,
    InputPurpose,
    Label,
    Menu,
    MenuItem,
    MessageDialog,
    MessageType,
    Orientation,
    ResponseType,
    Separator,
    Stack,
    Window,
    WindowType
};
use connections::Connections;
use rusqlite::Connection as SqlConnection;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::env;
use synac::common;
use xdg::BaseDirectories;

fn main() {
    let basedirs = match BaseDirectories::with_prefix("synac") {
        Ok(basedirs) => basedirs,
        Err(err) => { eprintln!("error initializing xdg: {}", err); return; }
    };
    let path = match basedirs.find_data_file("data.sqlite") {
        Some(path) => path,
        None => match basedirs.place_data_file("data.sqlite") {
            Ok(path) => path,
            Err(err) => { eprintln!("error placing config: {}", err); return; }
        }
    };
    let db = match SqlConnection::open(&path) {
        Ok(ok) => ok,
        Err(err) => {
            eprintln!("Failed to open database");
            eprintln!("{}", err);
            return;
        }
    };
    let db = Rc::new(db);
    db.execute("CREATE TABLE IF NOT EXISTS data (
                    key     TEXT NOT NULL UNIQUE,
                    value   TEXT NOT NULL
                )", &[])
        .expect("Couldn't create SQLite table");
    db.execute("CREATE TABLE IF NOT EXISTS servers (
                    ip      TEXT NOT NULL PRIMARY KEY,
                    name    TEXT NOT NULL,
                    hash    BLOB NOT NULL,
                    token   TEXT
                )", &[])
        .expect("Couldn't create SQLite table");

    let nick = {
        let mut stmt = db.prepare("SELECT value FROM data WHERE key = 'nick'").unwrap();
        let mut rows = stmt.query(&[]).unwrap();

        if let Some(row) = rows.next() {
            row.unwrap().get::<_, String>(0)
        } else {
            #[cfg(unix)]
            { env::var("USER").unwrap_or_else(|_| String::from("unknown")) }
            #[cfg(windows)]
            { env::var("USERNAME").unwrap_or_else(|_| String::from("unknown")) }
            #[cfg(not(any(unix, windows)))]
            { String::from("unknown") }
        }
    };

    if let Err(err) = gtk::init() {
        eprintln!("gtk error: {}", err);
        return;
    }

    let connections = Connections::new(&db, nick);

    let window = Window::new(WindowType::Toplevel);
    window.set_title("Synac GTK+ client");
    window.set_default_size(1000, 700);

    let stack = Stack::new();
    let main = GtkBox::new(Orientation::Horizontal, 10);

    let servers_wrapper = GtkBox::new(Orientation::Vertical, 0);

    let user_name = Label::new(&*connections.nick);
    user_name.set_property_margin(10);
    servers_wrapper.add(&user_name);

    servers_wrapper.add(&Separator::new(Orientation::Vertical));

    let servers = GtkBox::new(Orientation::Vertical, 2);
    render_servers(&connections, &db, &servers, &window);
    servers_wrapper.add(&servers);

    let add = Button::new_with_label("Add...");
    add.set_valign(Align::End);
    add.set_vexpand(true);

    servers_wrapper.add(&add);

    main.add(&servers_wrapper);

    main.add(&Separator::new(Orientation::Horizontal));

    let channels = GtkBox::new(Orientation::Vertical, 2);

    let server_name = Label::new("Server 1");
    server_name.set_property_margin(10);
    channels.add(&server_name);

    channels.add(&Separator::new(Orientation::Vertical));

    channels.add(&Button::new_with_label("Channel 1"));
    channels.add(&Button::new_with_label("Channel 2"));
    channels.add(&Button::new_with_label("Channel 3"));
    channels.add(&Button::new_with_label("Channel 4"));

    main.add(&channels);

    main.add(&Separator::new(Orientation::Horizontal));

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

    main.add(&content);
    stack.add(&main);

    let add_server = GtkBox::new(Orientation::Vertical, 2);

    let name = Entry::new();
    name.set_placeholder_text("Name");
    add_server.add(&name);
    add_server.add(&Label::new("The server name. This can be anything you want it to."));

    let server = Entry::new();
    server.set_placeholder_text("Server IP");
    add_server.add(&server);
    add_server.add(&Label::new(&*format!("The server IP address. The default port is {}.", common::DEFAULT_PORT)));

    let hash = Entry::new();
    hash.set_placeholder_text("Server's certificate hash");
    add_server.add(&hash);
    add_server.add(&Label::new("The server's certificate public key hash.\n\
                               This is to verify nobody is snooping on your connection"));

    let add_server_controls = GtkBox::new(Orientation::Horizontal, 2);

    let add_server_cancel = Button::new_with_label("Cancel");
    let stack_clone = stack.clone();
    let main_clone  = main.clone();
    add_server_cancel.connect_clicked(move |_| {
        stack_clone.set_visible_child(&main_clone);
    });
    add_server_controls.add(&add_server_cancel);

    let add_server_ok = Button::new_with_label("Ok");

    let db_clone = Rc::clone(&db);
    let connections_clone = Arc::clone(&connections);
    let main_clone  = main.clone();
    let servers_clone = servers.clone();
    let stack_clone = stack.clone();
    let window_clone = window.clone();
    add_server_ok.connect_clicked(move |_| {
        let name_text   = name.get_text().unwrap_or_default();
        let server_text = server.get_text().unwrap_or_default();
        let hash_text   = hash.get_text().unwrap_or_default();

        let ip = match connections::parse_addr(&server_text) {
            Some(ip) => ip,
            None => return
        };

        name.set_text("");
        server.set_text("");
        hash.set_text("");

        stack_clone.set_visible_child(&main_clone);

        db_clone.execute(
            "INSERT INTO servers (name, ip, hash) VALUES (?, ?, ?)",
            &[&name_text, &ip.to_string(), &hash_text]
        ).unwrap();
        render_servers(&connections_clone, &db_clone, &servers_clone, &window_clone);
    });
    add_server_controls.add(&add_server_ok);

    add_server.add(&add_server_controls);
    stack.add(&add_server);

    let stack_clone = stack.clone();
    let add_server = add_server.clone();
    add.connect_clicked(move |_| {
        stack_clone.set_visible_child(&add_server);
    });

    window.add(&stack);
    window.show_all();
    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        Inhibit(false)
    });

    gtk::idle_add(move || {
        match connections.try_read() {
            Ok(Some(packet)) => println!("received {:?}", packet),
            Ok(None) => (),
            Err(err) => eprintln!("receive error: {}", err)
        }
        Continue(true)
    });
    gtk::main();
}
fn alert(window: &Window, kind: MessageType, message: &str) {
    let dialog = MessageDialog::new(
        Some(window),
        DialogFlags::MODAL,
        kind,
        ButtonsType::Ok,
        message
    );
    dialog.connect_response(|dialog, _| dialog.destroy());
    dialog.show_all();
}
fn parse_addr(ip: &str, window: &Window) -> Option<SocketAddr> {
    connections::parse_addr(ip).or_else(|| {
        alert(window, MessageType::Error, "Failed to parse IP address. Format: <ip[:port]>");
        None
    })
}
fn render_servers(connections: &Arc<Connections>, db: &Rc<SqlConnection>, servers: &GtkBox, window: &Window) {
    for child in servers.get_children() {
        servers.remove(&child);
    }
    let mut stmt = db.prepare("SELECT ip, name, hash, token FROM servers ORDER BY name").unwrap();
    let mut rows = stmt.query(&[]).unwrap();

    while let Some(row) = rows.next() {
        let row = row.unwrap();
        let ip:   String = row.get(0);
        let name: String = row.get(1);
        let hash: String = row.get(2);
        let token: Option<String> = row.get(3);

        let ip_parsed = parse_addr(&ip, window);

        let button = Button::new_with_label(&name);
        let connections_clone = Arc::clone(connections);
        let db_clone = Rc::clone(db);
        let window_clone = window.clone();
        button.connect_clicked(move |_| {
            let ip = match ip_parsed {
                Some(ip) => ip,
                None => return
            };
            println!("Server with IP {} was clicked", ip);
            let mut err = true;
            connections_clone.execute(&ip, |result| {
                err = result.is_err();
            });
            if err {
                let result = connections_clone.connect(ip, hash.clone(), token.clone(), || {
                    let dialog = Dialog::new_with_buttons(
                        Some("Synac: Password dialog"),
                        Some(&window_clone),
                        DialogFlags::MODAL,
                        &[("Ok", ResponseType::Ok.into())]
                    );

                    let content = dialog.get_content_area();
                    content.add(&Label::new("Password:"));
                    let entry = Entry::new();
                    entry.set_input_purpose(InputPurpose::Password);
                    entry.set_visibility(false);
                    content.add(&entry);

                    dialog.show_all();
                    dialog.run();
                    let text = entry.get_text().unwrap_or_default();
                    dialog.destroy();
                    Some((text, Rc::clone(&db_clone)))
                });
                if let Err(ref err) = result {
                    alert(&window_clone, MessageType::Error, &format!("connection error: {}", err));
                }
                connections_clone.insert(ip, result);
            }
        });

        let connections_clone = Arc::clone(connections);
        let db_clone = Rc::clone(db);
        let servers_clone = servers.clone();
        let window_clone = window.clone();
        button.connect_button_press_event(move |_, event| {
            if event.get_button() == 3 {
                let menu = Menu::new();

                let forget = MenuItem::new_with_label("Forget server");

                let connections_clone = Arc::clone(&connections_clone);
                let db_clone = Rc::clone(&db_clone);
                let ip_clone = ip.clone();
                let servers_clone = servers_clone.clone();
                let window_clone = window_clone.clone();
                forget.connect_activate(move |_| {
                    db_clone.execute("DELETE FROM servers WHERE ip = ?", &[&ip_clone.to_string()]).unwrap();
                    render_servers(&connections_clone, &db_clone, &servers_clone, &window_clone);
                });
                menu.add(&forget);

                menu.show_all();
                menu.popup_at_pointer(Some(&**event));
            }
            Inhibit(false)
        });
        servers.add(&button);
    }
    servers.show_all();
    servers.queue_draw();
}
