use *;
use synac::common::Packet;

use frontend;

pub fn connect(
    addr: SocketAddr,
    connector: &Connector,
    screen: &frontend::Screen
) -> Option<Session> {
    // See https://github.com/rust-lang/rust/issues/35853
    macro_rules! println {
        () => { screen.log(String::new()); };
        ($arg:expr) => { screen.log(String::from($arg)); };
        ($($arg:expr),*) => { screen.log(format!($($arg),*)); };
    }
    macro_rules! readline {
        ($break:block) => {
            match screen.readline() {
                Ok(ok) => ok,
                Err(_) => $break
            }
        }
    }
    macro_rules! readpass {
        ($break:block) => {
            match screen.readpass() {
                Ok(ok) => ok,
                Err(_) => $break
            }
        }
    }

    let db = connector.db.lock().unwrap();
    let nick = connector.nick.read().unwrap();

    let mut stmt = db.prepare("SELECT key, token FROM servers WHERE ip = ?").unwrap();
    let mut rows = stmt.query(&[&addr.to_string()]).unwrap();

    let public_key: String;
    let mut token: Option<String> = None;
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        public_key = row.get(0);
        token = row.get(1);
    } else {
        println!("To securely connect, data from the server (\"public key\") is needed.");
        println!("You can obtain the \"public key\" from the server owner.");
        println!("Enter the key here:");
        public_key = readline!({ return None; });

        db.execute(
            "INSERT INTO servers (ip, key) VALUES (?, ?)",
            &[&addr.to_string(), &public_key]
        ).unwrap();
    }
    let mut inner = match synac::Session::new(addr, public_key) {
        Ok(ok) => ok,
        Err(err) => {
            println!("Failed to open session: {}", err);
            return None;
        }
    };

    let mut id = None;
    if let Some(token) = token {
        if let Err(err) = inner.login_with_token(false, nick.to_string(), token.to_string()) {
            println!("Could not request login");
            println!("{}", err);
            return None;
        }

        match inner.read() {
            Ok(Packet::LoginSuccess(login)) => {
                id = Some(login.id);
                if login.created {
                    println!("Tried to log in with your token: Apparently an account was created.");
                    println!("I think you should stay away from this server. It's weird.");
                    return None;
                }
                println!("Logged in as user #{}", login.id);
            },
            Ok(Packet::Err(code)) => match code {
                common::ERR_LOGIN_INVALID |
                common::ERR_MISSING_FIELD => {},
                common::ERR_LIMIT_REACHED => {
                    println!("Username too long");
                    return None;
                },
                common::ERR_LOGIN_BANNED => {
                    println!("You have been banned from this server. :(");
                    return None;
                },
                common::ERR_LOGIN_BOT => {
                    println!("This account is a bot account");
                    return None;
                },
                common::ERR_MAX_CONN_PER_IP => {
                    println!("Too many connections made from this IP");
                    return None;
                },
                _ => {
                    println!("The server responded with an invalid error.");
                    return None;
                }
            },
            Ok(_) => {
                println!("The server responded with an invalid packet.");
                return None;
            }
            Err(err) => {
                println!("Failed to read from server");
                println!("{}", err);
                return None;
            }
        }
    }

    if id.is_none() {
        println!("If you don't have an account, choose a new password here.");
        println!("Otherwise, enter your existing one.");
        println!("Password: ");
        let pass = readpass!({ return None; });

        if let Err(err) = inner.login_with_password(false, nick.to_string(), pass) {
            println!("Could not request login");
            println!("{}", err);
            return None;
        }

        match inner.read() {
            Ok(Packet::LoginSuccess(login)) => {
                db.execute(
                    "UPDATE servers SET token = ? WHERE ip = ?",
                    &[&login.token, &addr.to_string()]
                ).unwrap();
                if login.created {
                    println!("Account created");
                }
                id = Some(login.id);
                println!("Logged in as user #{}", login.id);
            },
            Ok(Packet::Err(code)) => match code {
                common::ERR_LIMIT_REACHED => {
                    println!("Username too long");
                    return None;
                },
                common::ERR_LOGIN_BANNED => {
                    println!("You have been banned from this server. :(");
                    return None;
                },
                common::ERR_LOGIN_BOT => {
                    println!("This account is a bot account");
                    return None;
                },
                common::ERR_LOGIN_INVALID => {
                    println!("Invalid credentials");
                    return None;
                },
                _ => {
                    println!("The server responded with an invalid error. :/");
                    return None;
                }
            },
            Ok(_) => {
                println!("The server responded with an invalid packet. :/");
                return None;
            }
            Err(err) => {
                println!("Failed to read from server");
                println!("{}", err);
                return None;
            }
        }
    }
    inner.inner_stream().get_ref().set_nonblocking(true).expect("Failed to make stream non-blocking");
    Some(Session::new(addr, id.unwrap(), inner))
}

pub fn reconnect(
    connector: &Connector,
    err: &std::io::Error,
    screen: &frontend::Screen,
    session: &mut Session
) {
    if err.kind() == std::io::ErrorKind::BrokenPipe {
        screen.log(String::from("Attempting reconnect..."));
        if let Some(new) = connect(session.addr, &connector, screen) {
            *session = new;
        }
    }
}

pub fn write(
    connector: &Connector,
    packet: &Packet,
    screen: &frontend::Screen,
    session: &mut Session
) -> bool {
    if let Err(err) = session.inner.send(packet) {
        screen.log(String::from("Sending failed."));
        screen.log(format!("{}", err));
        if let synac::Error::IoError(err) = err {
            reconnect(&connector, &err, screen, session);
        }
        return false;
    }
    true
}
