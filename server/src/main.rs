extern crate common;
extern crate futures;
extern crate rusqlite;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;

use futures::{Future, Stream};
use openssl::rsa::Rsa;
use std::env;
use std::io::BufReader;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Handle};
use tokio_io::io;

macro_rules! attempt_or {
    ($result:expr, $fail:block) => {
        match $result {
            Ok(ok) => ok,
            Err(_) => {
                $fail
            }
        }
    }
}

fn main() {
    let db = attempt_or!(rusqlite::Connection::open("data.sqlite"), {
        eprintln!("SQLite initialization failed.");
        eprintln!("Is the file corrupt?");
        eprintln!("Is the file permissions badly configured?");
        eprintln!("Just guessing here ¯\\_(ツ)_/¯");
        return;
    });
    db.execute("CREATE TABLE IF NOT EXISTS data (
                type    INTEGER NOT NULL,
                value   BLOB NOT NULL
                )", &[])
        .expect("SQLite table creation failed");

    let mut args = env::args();
    args.next();
    match args.next().as_ref().map(|s| &**s) {
        Some("start") => {},
        Some("reset-keys") => {
            db.execute("DELETE FROM data WHERE type=0", &[]).unwrap();
            println!("Public & Private keys reset.");
            return;
        },
        _ => {
            println!("Usage: ./unnamed start [port] OR ./unnamed reset-keys");
            return;
        }
    };
    let port = args.next().map(|val| match val.parse() {
        Ok(ok) => ok,
        Err(_) => {
            eprintln!("Warning: Supplied port is not a valid number.");
            eprintln!("Using default.");
            common::DEFAULT_PORT
        }
    }).unwrap_or_else(|| {
        println!("TIP: You can change port by putting it as a command line argument.");
        common::DEFAULT_PORT
    });

    println!("Setting up...");

    let mut stmt = db.prepare("SELECT value FROM data WHERE type = 0").unwrap();
    let mut rows = stmt.query(&[]).unwrap();

    let rsa;

    if let Some(row) = rows.next() {
        let row = row.unwrap();
        rsa = attempt_or!(Rsa::private_key_from_pem(&row.get::<_, Vec<_>>(0)), {
            eprintln!("Could not use private key.");
            eprintln!("Is it invalid? D:");
            return;
        });
        let public = rsa.public_key_to_pem().unwrap();
        let string = attempt_or!(std::str::from_utf8(&public), {
            eprintln!("Oh no! Text isn't valid UTF-8!");
            eprintln!("Please contact my developer!");
            return;
        });
        println!("In case you forgot your public key, it's:");
        println!();
        println!("{}", string);
    } else {
        // Generate new public and private keys.
        rsa = Rsa::generate(common::RSA_KEY_BIT_LEN).expect("Failed to generate public/private key");
        let private = rsa.private_key_to_pem().unwrap();
        let public = rsa.public_key_to_pem().unwrap();
        db.execute("INSERT INTO data (type, value) VALUES (0, ?)", &[&private]).unwrap();
        // be friendly
        let string = attempt_or!(std::str::from_utf8(&public), {
            eprintln!("Oh no! Text isn't valid UTF-8!");
            eprintln!("Please contact my developer!");
            return;
        });
        println!("Almost there! To secure your users' connection,");
        println!("you will have to *securely* send a piece of data manually.");
        println!("Example #1: Write it down and give it to them IRL.");
        println!("Example #2: Send it in *parts* over multiple applications.");
        println!("The text is as follows: ");
        println!();
        println!("{}", string);
    }

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });

    let rsa = Rc::new(rsa);
    let handle = Rc::new(handle);

    println!("I'm alive!");

    let server = listener.incoming().for_each(|(conn, _)| {
        let bufreader = BufReader::new(conn);
        handle_client(rsa.clone(), handle.clone(), bufreader);

        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn handle_client(rsa: Rc<Rsa>, handle: Rc<Handle>, bufreader: BufReader<TcpStream>) {
    let handle_clone = handle.clone();
    let rsa_clone = rsa.clone();
    let length = io::read_exact(bufreader, [0; 4])
        .map_err(|_| ())
        .and_then(move |(bufreader, bytes)| {
            let (size_rsa, size_aes) = common::decode_size(&bytes);
            let (size_rsa, size_aes) = (size_rsa as usize, size_aes as usize);

            println!("Size RSA: {}", size_rsa);
            println!("Size AES: {}", size_aes);

            if size_rsa == 0 || size_aes == 0 {
                return Ok(());
            }

            let handle_clone_clone_ugh = handle_clone.clone();
            let lines = io::read_exact(bufreader, vec![0; size_rsa+size_aes])
                .map_err(|_| ())
                .and_then(move |(bufreader, bytes)| {
                    let packet = match common::decrypt(&rsa_clone, size_rsa, &bytes) {
                        Ok(ok) => ok,
                        Err(err) => {
                            eprintln!("Failed to decrypt message from client: {}", err);
                            return Ok(());
                        }
                    };

                    use common::Packet;
                    match packet {
                        Packet::MessageCreate(msg) => {
                            println!("Decoded: {:?}", msg.text)
                        }
                        _ => unimplemented!(),
                    }

                    handle_client(rsa_clone, handle_clone_clone_ugh, bufreader);
                    Ok(())
                });

            handle_clone.spawn(lines);
            Ok(())
        });

    handle.spawn(length);
}
