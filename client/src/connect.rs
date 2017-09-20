use *;
use common::Packet;
use openssl::ssl::{SslConnector, SSL_VERIFY_PEER};
use rusqlite::Connection as SqlConnection;
use rustyline::error::ReadlineError;

pub fn connect<T: rustyline::completion::Completer>(
    db: &SqlConnection,
    nick: &str,
    ip: &str,
    editor: &mut rustyline::Editor<T>,
    ssl: &SslConnector
) -> Option<Session> {
    let addr = match parse_ip(ip) {
        Some(some) => some,
        None => {
            println!("Could not parse IP");
            return None;
        }
    };

    let mut stmt = db.prepare("SELECT key, token FROM servers WHERE ip = ?").unwrap();
    let mut rows = stmt.query(&[&addr.to_string()]).unwrap();

    let public_key: String;
    let mut token: Option<String> = None;
    if let Some(row) = rows.next() {
        let row = row.unwrap();
        public_key = row.get(0);
        token = row.get(1);
    } else {
        println!("To securely connect, we need some data from the server (\"public key\").");
        println!("The server owner should have given you this.");
        println!("Once you have it, enter it here:");
        flush!();
        public_key = readline!(editor, "", { return None; });

        db.execute(
            "INSERT INTO servers (ip, key) VALUES (?, ?)",
            &[&addr.to_string(), &public_key]
        ).unwrap();
    }
    let stream = match TcpStream::connect(addr) {
        Ok(ok) => ok,
        Err(err) => {
            println!("Could not connect!");
            println!("{}", err);
            return None;
        }
    };
    let mut stream = {
        let mut config = ssl.configure().expect("Failed to configure SSL connector");
        config.ssl_mut().set_verify_callback(SSL_VERIFY_PEER, move |_, cert| {
            match cert.current_cert() {
                Some(cert) => match cert.public_key() {
                    Ok(pkey) => match pkey.public_key_to_pem() {
                        Ok(pem) => {
                            let digest = openssl::sha::sha256(&pem);
                            let mut digest_str = String::with_capacity(64);
                            for byte in &digest {
                                digest_str.push_str(&format!("{:0X}", byte));
                            }
                            use std::ascii::AsciiExt;
                            public_key.trim().eq_ignore_ascii_case(&digest_str)
                        },
                        Err(_) => false
                    },
                    Err(_) => false
                },
                None => false
            }
        });

        match
config.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
        {
            Ok(ok) => ok,
            Err(_) => {
                println!("Faild to validate certificate");
                return None;
            }
        }
    };

    let mut id = None;
    if let Some(token) = token {
        let packet = Packet::Login(common::Login {
            bot: false,
            name: nick.to_string(),
            password: None,
            token: Some(token.to_string())
        });

        if let Err(err) = common::write(&mut stream, &packet) {
            println!("Could not request login");
            println!("{}", err);
            return None;
        }

        match common::read(&mut stream) {
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
                common::ERR_LOGIN_EMPTY => {},
                common::ERR_LOGIN_BANNED => {
                    println!("Oh noes, you have been banned from this server :(");
                    return None;
                },
                common::ERR_LOGIN_BOT => {
                    println!("This account is a bot account");
                    return None;
                },
                common::ERR_LIMIT_REACHED => {
                    println!("Username too long");
                    return None;
                },
                _ => {
                    println!("The server responded with an invalid error :/");
                    return None;
                }
            },
            Ok(_) => {
                println!("The server responded with an invalid packet :/");
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
        print!("Password: ");
        flush!();
        use termion::input::TermRead;
        let pass = match io::stdin().read_passwd(&mut io::stdout()) {
            Ok(Some(some)) => some,
            Ok(None) => { println!(); return None },
            Err(err) => {
                println!("Failed to read password");
                println!("{}", err);
                return None;
            }
        };
        println!();

        let packet = Packet::Login(common::Login {
            bot: false,
            name: nick.to_string(),
            password: Some(pass),
            token: None
        });

        if let Err(err) = common::write(&mut stream, &packet) {
            println!("Could not request login");
            println!("{}", err);
            return None;
        }

        match common::read(&mut stream) {
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
                common::ERR_LOGIN_INVALID => {
                    println!("Invalid credentials");
                    return None;
                },
                common::ERR_LOGIN_BANNED => {
                    println!("Oh noes, you have been banned from this server :(");
                    return None;
                },
                common::ERR_LOGIN_BOT => {
                    println!("This account is a bot account");
                    return None;
                },
                common::ERR_LIMIT_REACHED => {
                    println!("Username too long");
                    return None;
                },
                _ => {
                    println!("The server responded with an invalid error :/");
                    return None;
                }
            },
            Ok(_) => {
                println!("The server responded with an invalid packet :/");
                return None;
            }
            Err(err) => {
                println!("Failed to read from server");
                println!("{}", err);
                return None;
            }
        }
    }
    stream.get_ref().set_nonblocking(true).expect("Failed to make stream non-blocking");
    Some(Session::new(id.unwrap(), stream))
}
