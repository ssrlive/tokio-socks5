//! Derived from tokio-rs/tokio-socks5

use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, IpAddr};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use futures::future;
use futures::{Future, Stream, Poll, Async};
use tokio_io::io::{read_exact, write_all, Window};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Core, Handle, Timeout};
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientStream;

/// Helper class to build [`Server`]s.
#[derive(Debug, Eq, PartialEq)]
pub struct Builder {
    local_address: Option<SocketAddr>,
    dns_address: Option<SocketAddr>,
}

impl Builder {
    /// Create a new [`Builder`].
    pub fn new() -> Self {
        Self {
            local_address: None,
            dns_address: None,
        }
    }

    /// Set the local address the [`Server`] will listen on.
    pub fn local_address(mut self, local_address: SocketAddr) -> Self {
        self.local_address = Some(local_address);
        self
    }

    /// Set the DNS server.
    pub fn dns_address(mut self, dns_address: SocketAddr) -> Self {
        self.dns_address = Some(dns_address);
        self
    }

    /// Validate the contents and return a [`Server`].
    pub fn build(self) -> io::Result<Server> {
        let local_address = self.local_address.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing local address"))?;
        let dns_address = self.local_address.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Missing DNS address"))?;
        Ok(Server {
            local_address,
            dns_address,
        })
    }
}

/// A SOCKS server.
#[derive(Debug)]
pub struct Server {
    local_address: SocketAddr,
    dns_address: SocketAddr,
}

impl Server {
    pub fn serve(&self) -> io::Result<()> {
        let mut core = Core::new()?;
        let listener = TcpListener::bind(&self.local_address, &core.handle())?;
        let (stream, sender) = UdpClientStream::new(self.dns_address, core.handle());
        let dns_client = ClientFuture::new(stream, sender, core.handle(), None);

        let buffer = Rc::new(RefCell::new(vec![0; 64 * 1024]));
        let handle = &core.handle();
        let clients = listener.incoming().map(move |(socket, addr)| {
            (Handler {
                buffer: buffer.clone(),
                dns_client: dns_client.clone(),
                handle: handle.clone(),
            }.serve(socket), addr)
        });

        let handle = core.handle().clone();
        let server = clients.for_each(|(client, addr)| {
            handle.spawn(client.then(move |res| {
                if let Err(e) = res {
                    error!("Error for {}: {}", addr, e);
                }
                future::ok(())
            }));
            Ok(())
        });

        core.run(server)
    }
}

struct Handler {
    buffer: Rc<RefCell<Vec<u8>>>,
    dns_client: BasicClientHandle,
    handle: Handle,
}

impl Handler {
    fn serve(self, conn: TcpStream) -> Box<dyn Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            match buf[0] {
                v5::VERSION => self.serve_v5(conn),
                v4::VERSION => self.serve_v4(conn),
                _ => Box::new(future::err(other("unknown version"))),
            }
        }))
    }

    fn serve_v4(self, _conn: TcpStream) -> Box<dyn Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(future::err(other("unimplemented")))
    }

    fn serve_v5(self, conn: TcpStream) -> Box<dyn Future<Item=(u64, u64), Error=io::Error>> {
        let num_methods = read_exact(conn, [0u8]);
        let authenticated = Box::new(num_methods.and_then(|(conn, buf)| {
            read_exact(conn, vec![0u8; buf[0] as usize])
        }).and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        }));

        let part1 = Box::new(authenticated.and_then(|conn| {
            write_all(conn, [v5::VERSION, v5::METH_NO_AUTH])
        }));

        let ack = Box::new(part1.and_then(|(conn, _)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::VERSION {
                    Ok(conn)
                } else {
                    Err(other("didn't confirm with v5 version"))
                }
            })
        }));
        let command = Box::new(ack.and_then(|conn| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::CMD_CONNECT {
                    Ok(conn)
                } else {
                    Err(other("unsupported command"))
                }
            })
        }));

        let mut dns_client = self.dns_client.clone();
        let resv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
        let atyp = resv.and_then(|c| read_exact(c, [0u8]));
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                v5::ATYP_IPV4 => {
                    mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                        let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let addr = SocketAddrV4::new(addr, port);
                        (c, SocketAddr::V4(addr))
                    }))
                }
                v5::ATYP_IPV6 => {
                    mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                        let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                        let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                        let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                        let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                        let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                        let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                        let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                        let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                        let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                        let addr = SocketAddrV6::new(addr, port, 0, 0);
                        (conn, SocketAddr::V6(addr))
                    }))
                }
                v5::ATYP_DOMAIN => {
                    mybox(read_exact(c, [0u8]).and_then(|(conn, buf)| {
                        read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(move |(conn, buf)| {
                        let (name, port) = match name_port(&buf) {
                            Ok(UrlHost::Name(name, port)) => (name, port),
                            Ok(UrlHost::Addr(addr)) => {
                                return mybox(future::ok((conn, addr)))
                            }
                            Err(e) => return mybox(future::err(e)),
                        };

                        let ipv4 = dns_client.query(name, DNSClass::IN, RecordType::A)
                                      .map_err(|e| other(&format!("DNS error: {}", e)))
                                      .and_then(move |r| get_addr(r, port));
                        mybox(ipv4.map(|addr| (conn, addr)))
                    }))
                }

                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }
        }));

        let handle = self.handle.clone();
        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
        }));

        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) |
                Err(..) => addr,
            };
            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| {
                c2.map(|c2| (c1, c2))
            })
        }));

        let timeout = match Timeout::new(Duration::new(10, 0), &self.handle) {
            Ok(t) => t,
            Err(e) => return Box::new(future::err(e)),
        };

        let pair = mybox(handshake_finish.map(Ok).select(timeout.map(Err)).then(|res| {
            match res {
                Ok((Ok(pair), _timeout)) => Ok(pair),
                Ok((Err(()), _handshake)) => Err(other("timeout during handshake")),
                Err((e, _other)) => Err(e),
            }
        }));

        let buffer = self.buffer.clone();
        mybox(pair.and_then(|(c1, c2)| {
            let c1 = Rc::new(c1);
            let c2 = Rc::new(c2);

            let half1 = Transfer::new(c1.clone(), c2.clone(), buffer.clone());
            let half2 = Transfer::new(c2, c1, buffer);
            half1.join(half2)
        }))
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<dyn Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Rc<RefCell<Vec<u8>>>,
    amt: u64,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>,
           writer: Rc<TcpStream>,
           buffer: Rc<RefCell<Vec<u8>>>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: buffer,
            amt: 0,
        }
    }
}

impl Future for Transfer {
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<u64, io::Error> {
        let mut buffer = self.buf.borrow_mut();

        loop {
            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();
            if !read_ready || !write_ready {
                return Ok(Async::NotReady)
            }

            let n = try_nb!((&*self.reader).read(&mut buffer));
            if n == 0 {
                self.writer.shutdown(Shutdown::Write)?;
                return Ok(self.amt.into())
            }
            self.amt += n as u64;

            let m = (&*self.writer).write(&buffer[..n])?;
            assert_eq!(n, m);
        }
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(Name, u16),
    Addr(SocketAddr),
}

fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = str::from_utf8(hostname).map_err(|_e| {
        other("hostname buffer provided was not valid utf-8")
    })?;
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)))
    }
    let name = Name::parse(hostname, Some(&Name::root())).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    })?;
    Ok(UrlHost::Name(name, port))
}

fn get_addr(response: Message, port: u16) -> io::Result<SocketAddr> {
    if response.get_response_code() != ResponseCode::NoError {
        return Err(other("resolution failed"));
    }
    let addr = response.get_answers().iter().filter_map(|ans| {
        match *ans.get_rdata() {
            RData::A(addr) => Some(IpAddr::V4(addr)),
            RData::AAAA(addr) => Some(IpAddr::V6(addr)),
            _ => None,
        }
    }).next();

    match addr {
        Some(addr) => Ok(SocketAddr::new(addr, port)),
        None => Err(other("no address records in response")),
    }
}

pub mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

pub mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}
