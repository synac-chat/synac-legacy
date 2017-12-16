use failure::Error;
use rusqlite::Connection as SqlConnection;
use std::collections::HashMap;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use synac::common::{self, Packet};
use synac::{Listener, Session, State};

#[derive(Debug, Fail)]
pub enum ConnectionError {
    #[fail(display = "invalid packet")]
    InvalidPacket,
    #[fail(display = "invalid token: password authentication needed")]
    InvalidToken,
    #[fail(display = "invalid password")]
    InvalidPassword
}

pub struct Synac {
    pub addr: SocketAddr,
    pub listener: Listener,
    pub session: Session,
    pub state: State
}
impl Synac {
    pub fn new(addr: SocketAddr, session: Session) -> Self {
        Synac {
            addr: addr,
            listener: Listener::new(),
            session: session,
            state: State::new()
        }
    }
}

pub enum Connection {
    Connecting(JoinHandle<Result<Synac, Error>>),
    Connected(Result<Synac, Error>)
}
impl Connection {
    pub fn join(&mut self) -> Result<&mut Synac, &mut Error> {
        let old = mem::replace(self, unsafe { mem::uninitialized() });
        let new = match old {
            Connection::Connecting(handle) => Connection::Connected(handle.join().unwrap()),
            old @ Connection::Connected(_) => old
        };
        mem::forget(mem::replace(self, new));

        match *self {
            Connection::Connecting(_) => unreachable!(),
            Connection::Connected(ref mut inner) => inner.as_mut()
        }
    }
}

pub struct Connections {
    pub current_server: Mutex<Option<SocketAddr>>,
    pub nick: RwLock<String>,
    pub servers: Arc<Mutex<HashMap<SocketAddr, Connection>>>
}
impl Connections {
    pub fn new(db: &SqlConnection, nick: String) -> Arc<Self> {
        let me = Arc::new(Connections {
            current_server: Mutex::new(None),
            nick: RwLock::new(nick),
            servers: Arc::new(Mutex::new(HashMap::new()))
        });
        {
            let mut servers = me.servers.lock().unwrap();

            let mut stmt = db.prepare("SELECT ip, hash, token FROM servers").unwrap();
            let mut rows = stmt.query(&[]).unwrap();

            while let Some(row) = rows.next() {
                let row = row.unwrap();
                let addr  = match parse_addr(&row.get::<_, String>(0)) {
                    Some(addr) => addr,
                    None => {
                        eprintln!("invalid socket address, skipping");
                        continue;
                    }
                };
                let hash  = row.get(1);
                let token = row.get(2);

                let me_clone = Arc::clone(&me);
                servers.insert(addr, Connection::Connecting(thread::spawn(move || {
                    me_clone.connect(addr, hash, token, || None)
                        .map(|session| Synac::new(addr, session))
                        .map_err(|err| { eprintln!("connect error: {}", err); err })
                })));
            }
        }

        me
    }
    pub fn connect<F>(&self, addr: SocketAddr, hash: String, token: Option<String>, password: F)
        -> Result<Session, Error>
        where F: FnOnce() -> Option<(String, Rc<SqlConnection>)>
    {
        let mut session = Session::new(addr, hash)?;

        if let Some(token) = token {
            session.login_with_token(false, self.nick.read().unwrap().clone(), token)?;
            match session.read()? {
                Packet::LoginSuccess(_) => {
                    session.set_nonblocking(true)?;
                    return Ok(session);
                },
                Packet::Err(common::ERR_LOGIN_INVALID) => {},
                _ => return Err(ConnectionError::InvalidPacket.into())
            }
        }
        if let Some((password, db)) = password() {
            session.login_with_password(false, self.nick.read().unwrap().clone(), password)?;
            match session.read()? {
                Packet::LoginSuccess(login) => {
                    db.execute("UPDATE servers SET token = ? WHERE ip = ?", &[&login.token, &addr.to_string()]).unwrap();
                    session.set_nonblocking(true)?;
                    return Ok(session);
                },
                Packet::Err(common::ERR_LOGIN_INVALID) =>
                     return Err(ConnectionError::InvalidPassword.into()),
                _ => return Err(ConnectionError::InvalidPacket.into())
            }
        }

        Err(ConnectionError::InvalidToken.into())
    }
    pub fn insert(&self, addr: SocketAddr, result: Synac) {
        self.servers.lock().unwrap()
            .insert(addr, Connection::Connected(Ok(result)));
    }
    pub fn set_current(&self, addr: Option<SocketAddr>) {
        *self.current_server.lock().unwrap() = addr;
    }
    pub fn execute<F>(&self, addr: &SocketAddr, callback: F)
        where F: FnOnce(Result<&mut Synac, &mut Error>)
    {
        let mut servers = self.servers.lock().unwrap();
        let server = servers.get_mut(addr);

        if let Some(inner) = server {
            callback(inner.join());
        }
    }
    pub fn try_read<F>(&self, mut callback: F) -> Result<(), Error>
        where F: FnMut(&mut Synac, Packet)
    {
        if let Ok(mut servers) = self.servers.try_lock() {
            for server in servers.values_mut() {
                if let Ok(ref mut synac) = server.join() {
                    let read = synac.listener.try_read(synac.session.inner_stream())?;
                    if let Some(packet) = read {
                        synac.state.update(&packet);
                        callback(synac, packet);
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn parse_addr(input: &str) -> Option<SocketAddr> {
    let mut parts = input.rsplitn(2, ':');
    let addr = match (parts.next()?, parts.next()) {
        (port, Some(addr)) => (addr, port.parse().ok()?),
        (addr,   None)     => (addr, common::DEFAULT_PORT)
    };

    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}
