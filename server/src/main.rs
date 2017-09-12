extern crate common;
extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;

use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
use futures::{Future, Stream};
use openssl::pkey::PKey;
use openssl::ssl::{SslMethod, SslAcceptorBuilder};
use tokio_openssl::{SslAcceptorExt, SslStream};
use openssl::x509::X509;
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
    println!("Setting up...");

    let mut public = Vec::new();
    {
        let mut file = attempt_or!(File::open("cert.pem"), {
            eprintln!("Could not open certificate file (cert.pem).");
            eprintln!("Are you in the right directory?");
            eprintln!("Did you remember to create a self signed certificate?");
            return;
        });
        attempt_or!(file.read_to_end(&mut public), {
            eprintln!("Failed to read from file.");
            eprintln!("I have no idea why this would happen...");
            eprintln!("Is your computer OK, dude?!");
            return;
        });
    }
    let mut private = Vec::new();
    {
        let mut file = attempt_or!(File::open("key.pem"), {
            eprintln!("Could not open key file (key.pem).");
            eprintln!("Are you in the right directory?");
            eprintln!("Did you remember to create a self signed certificate?");
            return;
        });
        attempt_or!(file.read_to_end(&mut private), {
            eprintln!("Failed to read from file.");
            eprintln!("I have no idea why this would happen...");
            eprintln!("Is your computer OK, dude?!");
            return;
        });
    }

    let pkey = attempt_or!(PKey::private_key_from_pem(&private), {
        eprintln!("Failed to deserialize key file.");
        eprintln!("Is it corrupt?");
        return;
    });
    let cert = attempt_or!(X509::from_pem(&public), {
        eprintln!("Failed to deserialize certificate file.");
        eprintln!("Is it corrupt?");
        return;
    });

    let ssl = SslAcceptorBuilder::mozilla_intermediate::<Vec<X509>>(SslMethod::tls(), &pkey, &cert, Vec::new())
        .expect("Could not create SslAcceptorBuilder")
        .build();


    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1234), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });
    let rc = Rc::new(handle);

    println!("I'm alive!");

    let server = listener.incoming().for_each(|(conn, _)| {
        let rc_clone = rc.clone();
        let conn = ssl.accept_async(conn).and_then(|conn| {
            let bufreader = BufReader::new(conn);
            read_until(rc_clone, bufreader);

            Ok(())
        }).map_err(|_| ());

        (*rc).spawn(conn);

        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn read_until(handle: Rc<Handle>, bufreader: BufReader<SslStream<TcpStream>>) {
    let handle_clone = handle.clone();
    let lines = io::read_until(bufreader, b'\n', Vec::new())
        .and_then(move |(bufreader, mut bytes)| {
            if bytes.is_empty() {
                return Ok(());
            }
            bytes.pop();
            println!("{:?}", bytes);
            println!("Decoding: {:?}", common::deserialize(&bytes));

            read_until(handle_clone, bufreader);
            Ok(())
        })
        .map_err(|_| ());

    (*handle).spawn(lines);
}
