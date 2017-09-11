extern crate futures;
extern crate tokio_core;
extern crate tokio_io;

use std::io::BufReader;
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use futures::Stream;
use tokio_core::reactor::Core;
use tokio_core::net::TcpListener;
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
    let server = listener.incoming().for_each(|(conn, _)| {
        let lines = io::lines(BufReader::new(conn))
                        .map_err(|_| ())
                        .for_each(|line| {


            Ok(())
        });

        handle.spawn(lines);
        Ok(())
    });

    core.run(server).expect("Could not run tokio core!");
}
