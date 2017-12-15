extern crate gtk;
extern crate rusqlite;
extern crate synac;

use gtk::prelude::*;
use gtk::{
    Align,
    Box as GtkBox,
    Button,
    Entry,
    Label,
    Menu,
    MenuItem,
    Orientation,
    Separator,
    Stack,
    Window,
    WindowType
};
use rusqlite::Connection as SqlConnection;
use std::path::PathBuf;
use std::rc::Rc;
use std::{fs, env};
use synac::common;

fn main() {
    #[cfg(unix)]
    let path = env::var("XDG_CONFIG_HOME").ok().map(|item| PathBuf::from(item)).or_else(|| {
        env::home_dir().map(|mut home| {
            home.push(".config");
            home
        })
    }).map(|mut path| {
        path.push("synac");
        path
    });
    #[cfg(not(unix))]
    let path = None;

    let mut path = path.unwrap_or_else(|| PathBuf::new());
    if let Err(err) = fs::create_dir_all(&path) {
        eprintln!("Failed to create all directories");
        eprintln!("{}", err);
        return;
    }
    path.push("gtk-data.sqlite");
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
                    id      ROWID NOT NULL,
                    ip      TEXT NOT NULL PRIMARY KEY,
                    key     BLOB NOT NULL,
                    name    TEXT NOT NULL,
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

    let window = Window::new(WindowType::Toplevel);
    window.set_title("Synac GTK+ client");
    window.set_default_size(1000, 700);

    let stack = Stack::new();
    let main = GtkBox::new(Orientation::Horizontal, 10);

    let servers_wrapper = GtkBox::new(Orientation::Vertical, 0);

    let user_name = Label::new(&*nick);
    user_name.set_property_margin(10);
    servers_wrapper.add(&user_name);

    servers_wrapper.add(&Separator::new(Orientation::Vertical));

    let servers = GtkBox::new(Orientation::Vertical, 2);
    render_servers(&db, &servers);
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
    let servers_clone = servers.clone();
    let stack_clone = stack.clone();
    let main_clone  = main.clone();
    add_server_ok.connect_clicked(move |_| {
        let name_text   = name.get_text().unwrap_or_default();
        let server_text = server.get_text().unwrap_or_default();
        let hash_text   = hash.get_text().unwrap_or_default();

        name.set_text("");
        server.set_text("");
        hash.set_text("");

        stack_clone.set_visible_child(&main_clone);

        db_clone.execute(
            "INSERT INTO servers (name, ip, key) VALUES (?, ?, ?)",
            &[&name_text, &server_text, &hash_text]
        ).unwrap();
        render_servers(&db_clone, &servers_clone);
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

    gtk::main();
}
fn render_servers(db: &Rc<SqlConnection>, servers: &GtkBox) {
    for child in servers.get_children() {
        servers.remove(&child);
    }
    let mut stmt = db.prepare("SELECT name, id FROM servers ORDER BY name").unwrap();
    let mut rows = stmt.query(&[]).unwrap();

    while let Some(row) = rows.next() {
        let row  = row.unwrap();
        let name: String = row.get(0);
        let id = row.get::<_, i64>(1) as usize;

        let button = Button::new_with_label(&name);
        button.connect_clicked(move |_| {
            println!("Server with ID {} was clicked", id);
        });

        let db_clone = Rc::clone(&db);
        let servers_clone = servers.clone();
        button.connect_button_press_event(move |_, event| {
            if event.get_button() == 3 {
                let menu = Menu::new();

                let forget = MenuItem::new_with_label("Forget server");
                let db_clone = Rc::clone(&db_clone);
                let servers_clone = servers_clone.clone();
                forget.connect_activate(move |_| {
                    db_clone.execute("DELETE FROM servers WHERE id = ?", &[&(id as i64)]).unwrap();
                    render_servers(&db_clone, &servers_clone);
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
