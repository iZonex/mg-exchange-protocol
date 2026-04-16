//! Non-blocking Event Reactor — poll-based I/O multiplexing.
//!
//! Single-threaded event loop for handling multiple connections without
//! threads or async runtimes. This is how production trading systems work:
//! one thread, explicit poll, no context switching.
//!
//! Architecture (Aeron conductor pattern):
//!   loop {
//!       let events = reactor.poll(timeout)?;
//!       for event in events {
//!           match event.token {
//!               LISTENER => accept_new_client(),
//!               client_id => process_client_message(),
//!           }
//!       }
//!       check_heartbeats();
//!       maybe_send_market_data();
//!   }
//!
//! Uses kqueue on macOS, would use epoll on Linux.
//! Falls back to poll(2) for portability.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

/// Maximum events returned per poll call.
const MAX_EVENTS: usize = 256;

/// Event interest flags.
#[derive(Clone, Copy, Debug)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

impl Interest {
    pub const READABLE: Self = Self { readable: true, writable: false };
    pub const WRITABLE: Self = Self { readable: false, writable: true };
    pub const BOTH: Self = Self { readable: true, writable: true };
}

/// An I/O event from the reactor.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// User-assigned token identifying the source.
    pub token: usize,
    /// The file descriptor that triggered.
    pub fd: RawFd,
    /// Whether the fd is readable.
    pub readable: bool,
    /// Whether the fd is writable.
    pub writable: bool,
    /// Whether an error or hangup occurred.
    pub error: bool,
}

/// Poll-based I/O reactor.
/// Uses kqueue on macOS, epoll on Linux.
pub struct Reactor {
    #[cfg(target_os = "macos")]
    kq: RawFd,
    #[cfg(target_os = "linux")]
    ep: RawFd,
    events_buf: Vec<u8>, // raw OS event buffer
}

impl Reactor {
    /// Create a new reactor.
    pub fn new() -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let kq = unsafe { kqueue() };
            if kq < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                kq,
                events_buf: vec![0u8; MAX_EVENTS * std::mem::size_of::<Kevent>()],
            })
        }

        #[cfg(target_os = "linux")]
        {
            let ep = unsafe { epoll_create1(0) };
            if ep < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                ep,
                events_buf: vec![0u8; MAX_EVENTS * std::mem::size_of::<EpollEvent>()],
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "reactor not supported on this OS"))
        }
    }

    /// Register a file descriptor for events.
    pub fn register(&self, fd: RawFd, token: usize, interest: Interest) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            if interest.readable {
                let ev = Kevent {
                    ident: fd as usize,
                    filter: EVFILT_READ,
                    flags: EV_ADD | EV_ENABLE,
                    fflags: 0,
                    data: 0,
                    udata: token as *mut std::ffi::c_void,
                };
                let r = unsafe { kevent_register(self.kq, &ev) };
                if r < 0 { return Err(io::Error::last_os_error()); }
            }
            if interest.writable {
                let ev = Kevent {
                    ident: fd as usize,
                    filter: EVFILT_WRITE,
                    flags: EV_ADD | EV_ENABLE,
                    fflags: 0,
                    data: 0,
                    udata: token as *mut std::ffi::c_void,
                };
                let r = unsafe { kevent_register(self.kq, &ev) };
                if r < 0 { return Err(io::Error::last_os_error()); }
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            let mut flags = 0u32;
            if interest.readable { flags |= EPOLLIN; }
            if interest.writable { flags |= EPOLLOUT; }
            let mut ev = EpollEvent { events: flags, data: token as u64 };
            let r = unsafe { epoll_ctl(self.ep, EPOLL_CTL_ADD, fd, &mut ev) };
            if r < 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { Err(io::Error::new(io::ErrorKind::Unsupported, "not supported")) }
    }

    /// Deregister a file descriptor.
    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let ev = Kevent {
                ident: fd as usize,
                filter: EVFILT_READ,
                flags: EV_DELETE,
                fflags: 0, data: 0,
                udata: std::ptr::null_mut(),
            };
            unsafe { kevent_register(self.kq, &ev) };
            let ev2 = Kevent {
                ident: fd as usize,
                filter: EVFILT_WRITE,
                flags: EV_DELETE,
                fflags: 0, data: 0,
                udata: std::ptr::null_mut(),
            };
            unsafe { kevent_register(self.kq, &ev2) };
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            let r = unsafe { epoll_ctl(self.ep, EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
            if r < 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { Err(io::Error::new(io::ErrorKind::Unsupported, "not supported")) }
    }

    /// Poll for events. Returns ready events.
    /// `timeout` = None means block indefinitely. Some(Duration::ZERO) = non-blocking.
    pub fn poll(&mut self, timeout: Option<Duration>) -> io::Result<Vec<Event>> {
        #[cfg(target_os = "macos")]
        {
            let ts = timeout.map(|d| Timespec {
                tv_sec: d.as_secs() as i64,
                tv_nsec: d.subsec_nanos() as i64,
            });
            let ts_ptr = ts.as_ref().map(|t| t as *const Timespec).unwrap_or(std::ptr::null());

            let events_ptr = self.events_buf.as_mut_ptr() as *mut Kevent;
            let n = unsafe {
                kevent_poll(self.kq, std::ptr::null(), 0, events_ptr, MAX_EVENTS as i32, ts_ptr)
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut result = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let ev = unsafe { &*events_ptr.add(i) };
                result.push(Event {
                    token: ev.udata as usize,
                    fd: ev.ident as RawFd,
                    readable: ev.filter == EVFILT_READ,
                    writable: ev.filter == EVFILT_WRITE,
                    error: (ev.flags & EV_ERROR) != 0 || (ev.flags & EV_EOF) != 0,
                });
            }
            Ok(result)
        }

        #[cfg(target_os = "linux")]
        {
            let timeout_ms = timeout.map(|d| d.as_millis() as i32).unwrap_or(-1);
            let events_ptr = self.events_buf.as_mut_ptr() as *mut EpollEvent;
            let n = unsafe {
                epoll_wait(self.ep, events_ptr, MAX_EVENTS as i32, timeout_ms)
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut result = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                let ev = unsafe { &*events_ptr.add(i) };
                result.push(Event {
                    token: ev.data as usize,
                    fd: 0, // epoll doesn't give us the fd directly
                    readable: (ev.events & EPOLLIN) != 0,
                    writable: (ev.events & EPOLLOUT) != 0,
                    error: (ev.events & (EPOLLERR | EPOLLHUP)) != 0,
                });
            }
            Ok(result)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { Err(io::Error::new(io::ErrorKind::Unsupported, "not supported")) }
    }

    /// Convenience: register a TcpListener.
    pub fn register_listener(&self, listener: &TcpListener, token: usize) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        self.register(listener.as_raw_fd(), token, Interest::READABLE)
    }

    /// Convenience: register a TcpStream.
    pub fn register_stream(&self, stream: &TcpStream, token: usize, interest: Interest) -> io::Result<()> {
        stream.set_nonblocking(true)?;
        self.register(stream.as_raw_fd(), token, interest)
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        unsafe { close_fd(self.kq); }
        #[cfg(target_os = "linux")]
        unsafe { close_fd(self.ep); }
    }
}

// ============================================================================
// OS-specific FFI
// ============================================================================

#[cfg(target_os = "macos")]
const EVFILT_READ: i16 = -1;
#[cfg(target_os = "macos")]
const EVFILT_WRITE: i16 = -2;
#[cfg(target_os = "macos")]
const EV_ADD: u16 = 0x0001;
#[cfg(target_os = "macos")]
const EV_DELETE: u16 = 0x0002;
#[cfg(target_os = "macos")]
const EV_ENABLE: u16 = 0x0004;
#[cfg(target_os = "macos")]
const EV_ERROR: u16 = 0x4000;
#[cfg(target_os = "macos")]
const EV_EOF: u16 = 0x8000;

#[cfg(target_os = "macos")]
#[repr(C)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut std::ffi::c_void,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(target_os = "macos")]
unsafe fn kqueue() -> RawFd {
    unsafe extern "C" { safe fn kqueue() -> i32; }
    kqueue()
}

#[cfg(target_os = "macos")]
unsafe fn kevent_register(kq: RawFd, ev: &Kevent) -> i32 {
    unsafe extern "C" {
        safe fn kevent(kq: i32, changelist: *const Kevent, nchanges: i32,
                  eventlist: *mut Kevent, nevents: i32, timeout: *const Timespec) -> i32;
    }
    kevent(kq, ev as *const Kevent, 1, std::ptr::null_mut(), 0, std::ptr::null())
}

#[cfg(target_os = "macos")]
unsafe fn kevent_poll(kq: RawFd, changelist: *const Kevent, nchanges: i32,
                      eventlist: *mut Kevent, nevents: i32, timeout: *const Timespec) -> i32 {
    unsafe extern "C" {
        safe fn kevent(kq: i32, changelist: *const Kevent, nchanges: i32,
                  eventlist: *mut Kevent, nevents: i32, timeout: *const Timespec) -> i32;
    }
    kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
}

#[cfg(target_os = "linux")]
const EPOLLIN: u32 = 0x001;
#[cfg(target_os = "linux")]
const EPOLLOUT: u32 = 0x004;
#[cfg(target_os = "linux")]
const EPOLLERR: u32 = 0x008;
#[cfg(target_os = "linux")]
const EPOLLHUP: u32 = 0x010;
#[cfg(target_os = "linux")]
const EPOLL_CTL_ADD: i32 = 1;
#[cfg(target_os = "linux")]
const EPOLL_CTL_DEL: i32 = 2;

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[cfg(target_os = "linux")]
unsafe fn epoll_create1(flags: i32) -> RawFd {
    unsafe extern "C" { safe fn epoll_create1(flags: i32) -> i32; }
    epoll_create1(flags)
}

#[cfg(target_os = "linux")]
unsafe fn epoll_ctl(ep: RawFd, op: i32, fd: RawFd, event: *mut EpollEvent) -> i32 {
    unsafe extern "C" { safe fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32; }
    epoll_ctl(ep, op, fd, event)
}

#[cfg(target_os = "linux")]
unsafe fn epoll_wait(ep: RawFd, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32 {
    unsafe extern "C" { safe fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32; }
    epoll_wait(ep, events, maxevents, timeout)
}

unsafe fn close_fd(fd: RawFd) {
    unsafe extern "C" { safe fn close(fd: i32) -> i32; }
    close(fd);
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn reactor_basic_tcp() {
        let mut reactor = Reactor::new().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        reactor.register_listener(&listener, 0).unwrap();

        // Connect client
        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nonblocking(true).unwrap();

        // Poll — should see the listener is readable (new connection)
        let events = reactor.poll(Some(Duration::from_millis(100))).unwrap();
        assert!(!events.is_empty(), "should have at least one event");
        assert!(events.iter().any(|e| e.token == 0 && e.readable));

        // Accept
        let (mut server_conn, _) = listener.accept().unwrap();
        server_conn.set_nonblocking(true).unwrap();
        reactor.register_stream(&server_conn, 1, Interest::READABLE).unwrap();

        // Client sends data
        client.write_all(b"hello").unwrap();

        // Poll — server connection should be readable
        let events = reactor.poll(Some(Duration::from_millis(100))).unwrap();
        assert!(events.iter().any(|e| e.token == 1 && e.readable));

        // Read
        let mut buf = [0u8; 64];
        let n = server_conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        reactor.deregister(listener.as_raw_fd()).unwrap();
        reactor.deregister(server_conn.as_raw_fd()).unwrap();
    }

    #[test]
    fn reactor_multiple_clients() {
        let mut reactor = Reactor::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        reactor.register_listener(&listener, 0).unwrap();

        // Connect 5 clients
        let mut clients: Vec<TcpStream> = (0..5)
            .map(|_| {
                let c = TcpStream::connect(addr).unwrap();
                c.set_nonblocking(true).unwrap();
                c
            })
            .collect();

        // Accept all and register
        let mut server_conns = Vec::new();
        for i in 0..5 {
            // Poll for accept
            let _ = reactor.poll(Some(Duration::from_millis(50)));
            let (conn, _) = listener.accept().unwrap();
            conn.set_nonblocking(true).unwrap();
            reactor.register_stream(&conn, 100 + i, Interest::READABLE).unwrap();
            server_conns.push(conn);
        }

        // All clients send
        for (i, client) in clients.iter_mut().enumerate() {
            client.write_all(format!("msg{}", i).as_bytes()).unwrap();
        }

        std::thread::sleep(Duration::from_millis(50));

        // Poll — should see all readable
        let events = reactor.poll(Some(Duration::from_millis(100))).unwrap();
        let readable_tokens: Vec<usize> = events.iter()
            .filter(|e| e.readable && e.token >= 100)
            .map(|e| e.token)
            .collect();
        assert!(readable_tokens.len() >= 3, "should see multiple readable clients, got {}", readable_tokens.len());
    }

    #[test]
    fn reactor_with_mgep_message() {
        let mut reactor = Reactor::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        reactor.register_listener(&listener, 0).unwrap();

        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nonblocking(true).unwrap();

        let _ = reactor.poll(Some(Duration::from_millis(50)));
        let (server_conn, _) = listener.accept().unwrap();
        server_conn.set_nonblocking(true).unwrap();

        let mut transport = crate::transport::TcpTransport::from_stream(server_conn).unwrap();
        transport.set_nonblocking(true).unwrap();

        // Send MGEP message via raw socket
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = crate::codec::MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        client.write_all(enc.as_slice()).unwrap();

        std::thread::sleep(Duration::from_millis(50));

        // Receive via TcpTransport
        let msg = transport.recv().unwrap().unwrap();
        let decoded = crate::codec::MessageBuffer::decode_new_order(msg);
        assert_eq!(decoded.order_id, 42);
    }
}
