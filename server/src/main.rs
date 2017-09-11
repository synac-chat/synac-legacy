extern crate futures;
extern crate structs;
extern crate tokio_core;
extern crate tokio_io;

use std::io::BufReader;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::rc::Rc;
use futures::Stream;
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpListener, TcpStream};
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
    let mut core = Core::new().expect("Could not start tokio core!");
    let handle = core.handle();
    let listener = attempt_or!(TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1234), &handle), {
        eprintln!("An error occured when binding TCP listener!");
        eprintln!("Is the port in use?");
        return;
    });
    let rc = Rc::new(handle);
    let server = listener.incoming().for_each(|(conn, _)| {
        let bufreader = BufReader::new(conn);
        read_until(rc.clone(), bufreader);

        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}

fn read_until(handle: Rc<Handle>, bufreader: BufReader<TcpStream>) {
    use futures::Future;

    let handle_clone = handle.clone();
    let lines = io::read_until(bufreader, b'\n', Vec::new())
        .and_then(move |(bufreader, mut bytes)| {
            if bytes.is_empty() {
                return Ok(());
            }
            bytes.pop();
            println!("{:?}", bytes);
            println!("Decoding: {:?}", structs::deserialize(&bytes));

            read_until(handle_clone, bufreader);
            Ok(())
        })
        .map_err(|_| ());

    (*handle).spawn(lines);
}
