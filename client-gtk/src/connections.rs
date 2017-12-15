use failure::Error;
use rusqlite::Connection as SqlConnection;
use std::collections::HashMap;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
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
    listener: Listener,
    session: Session,
    state: State
}
impl Synac {
    pub fn new(session: Session) -> Self {
        Synac {
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
    pub nick: String,
    pub servers: Arc<Mutex<HashMap<SocketAddr, Connection>>>
}
impl Connections {
    pub fn new(db: &SqlConnection, nick: String) -> Arc<Self> {
        let me = Arc::new(Connections {
            nick: nick.clone(),
            servers: Arc::new(Mutex::new(HashMap::new()))
        });
        {
            let mut servers = me.servers.lock().unwrap();

            let mut stmt = db.prepare("SELECT ip, hash, token FROM servers").unwrap();
            let mut rows = stmt.query(&[]).unwrap();

            while let Some(row) = rows.next() {
                let row = row.unwrap();
                let ip  = match parse_addr(&row.get::<_, String>(0)) {
                    Some(ip) => ip,
                    None => {
                        eprintln!("invalid socket address, skipping");
                        continue;
                    }
                };
                let hash  = row.get(1);
                let token = row.get(2);

                let me_clone = Arc::clone(&me);
                servers.insert(ip.clone(), Connection::Connecting(thread::spawn(move || {
                    me_clone.connect(ip, hash, token, || None)
                        .map(|session| Synac::new(session))
                        .map_err(|err| { eprintln!("connect error: {}", err); err })
                })));
            }
        }

        me
    }
    pub fn connect<F>(&self, ip: SocketAddr, hash: String, token: Option<String>, password: F)
        -> Result<Session, Error>
        where F: FnOnce() -> Option<(String, Rc<SqlConnection>)>
    {
        let mut session = Session::new(ip, hash)?;

        if let Some(token) = token {
            session.login_with_token(false, self.nick.clone(), token)?;
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
            session.login_with_password(false, self.nick.clone(), password)?;
            match session.read()? {
                Packet::LoginSuccess(login) => {
                    db.execute("UPDATE servers SET token = ? WHERE ip = ?", &[&login.token, &ip.to_string()]).unwrap();
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
    pub fn insert(&self, ip: SocketAddr, result: Result<Session, Error>) {
        self.servers.lock().unwrap()
            .insert(ip, Connection::Connected(result.map(|session| Synac::new(session))));
    }
    pub fn execute<F>(&self, ip: &SocketAddr, callback: F)
        where F: FnOnce(Result<&mut Synac, &mut Error>)
    {
        let mut servers = self.servers.lock().unwrap();
        let server = servers.get_mut(ip);

        if let Some(inner) = server {
            callback(inner.join());
        }
    }
    pub fn try_read(&self) -> Result<Option<Packet>, Error> {
        if let Ok(mut servers) = self.servers.try_lock() {
            for server in servers.values_mut() {
                if let Ok(ref mut synac) = server.join() {
                    let read = synac.listener.try_read(synac.session.inner_stream())?;
                    if read.is_some() {
                        synac.state.update(read.as_ref().unwrap());
                        return Ok(read);
                    }
                }
            }
        }
        Ok(None)
    }
}

pub fn parse_addr(input: &str) -> Option<SocketAddr> {
    let mut parts = input.rsplitn(2, ':');
    let addr = match (parts.next()?, parts.next()) {
        (port, Some(ip)) => (ip, port.parse().ok()?),
        (ip,   None)     => (ip, common::DEFAULT_PORT)
    };

    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}
