extern crate common;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;

use std::env;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
use std::io::BufReader;
use futures::{Future, Stream};
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
    println!("TIP: You can change port by putting it as a command line argument.");
    println!("Setting up...");

    let port = env::args().skip(1).next().map(|val| match val.parse() {
        Ok(ok) => ok,
        Err(_) => {
            eprintln!("Warning: Supplied port is not a valid number.");
            eprintln!("Using default.");
            common::DEFAULT_PORT
        }
    }).unwrap_or(common::DEFAULT_PORT);

    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });
    let rc = Rc::new(handle);

    println!("I'm alive!");

    let server = listener.incoming().for_each(|(conn, _)| {
        let bufreader = BufReader::new(conn);
        read_until(rc.clone(), bufreader);

        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn read_until(handle: Rc<Handle>, bufreader: BufReader<TcpStream>) {
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
