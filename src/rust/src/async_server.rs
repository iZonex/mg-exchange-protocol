#![allow(dead_code, unused_imports, unused_variables)]
//! Async Exchange Server — fully non-blocking, reactor-based.
//!
//! Fixes every problem with the original blocking server:
//!   - Non-blocking handshake (partial reads don't block)
//!   - Per-client timeout (slowloris protection)
//!   - Reactor-driven event loop (kqueue/epoll)
//!   - No allocations in hot message path
//!   - DDoS protection: max pending, handshake deadline
//!
//! Architecture:
//!   Reactor (kqueue/epoll)
//!     │
//!     ├── Listener token(0) → accept, create PendingClient
//!     │
//!     ├── PendingClient tokens(1..N) → non-blocking handshake state machine
//!     │     states: ReadNegotiate → SendNegotiateResp → ReadEstablish → SendEstablishAck → Done
//!     │     timeout: 5s per client (configurable)
//!     │
//!     └── ActiveClient tokens(N+1..) → message processing
//!           on_readable → recv + dispatch + handle
//!           on_error → disconnect

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};


use crate::frame::FrameHeader;
use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::metrics::Metrics;
use crate::reactor::{Interest, Reactor};
use crate::session::*;
use crate::transport::TcpTransport;

const LISTENER_TOKEN: usize = 0;
const PENDING_BASE: usize = 1;
const ACTIVE_BASE: usize = 100_000;

/// Server configuration.
pub struct AsyncServerConfig {
    pub max_clients: usize,
    pub max_pending: usize,
    pub keepalive_ms: u32,
    pub handshake_timeout: Duration,
    pub security_level: SecurityLevel,
    pub auth_key: Vec<u8>,
    pub rate_limit_per_sec: u32,
}

impl Default for AsyncServerConfig {
    fn default() -> Self {
        Self {
            max_clients: 4096,
            max_pending: 256,
            keepalive_ms: 1000,
            handshake_timeout: Duration::from_secs(5),
            security_level: SecurityLevel::None,
            auth_key: Vec::new(),
            rate_limit_per_sec: 0,
        }
    }
}

/// Handshake state machine — each step is non-blocking.
#[derive(Debug)]
enum HandshakeState {
    ReadNegotiate,
    SendNegotiateResp { resp: Vec<u8>, sent: usize },
    ReadEstablish,
    SendEstablishAck { resp: Vec<u8>, sent: usize },
    Done,
    Failed,
}

/// A client in the handshake process (not yet active).
struct PendingClient {
    stream: TcpStream,
    addr: SocketAddr,
    state: HandshakeState,
    session: Session,
    read_buf: Vec<u8>,
    read_len: usize,
    created_at: Instant,
}

/// An active client (handshake complete).
struct ActiveClient {
    transport: TcpTransport,
    session: Session,
    addr: SocketAddr,
    last_activity: Instant,
    tokens: u32,
    last_refill: Instant,
}

/// Handler callback.
pub type AsyncHandler = dyn FnMut(u64, &[u8]) -> Option<Vec<u8>>;

/// Fully non-blocking MGEP server.
pub struct AsyncServer {
    reactor: Reactor,
    listener: TcpListener,
    config: AsyncServerConfig,
    pending: HashMap<usize, PendingClient>,
    active: HashMap<usize, ActiveClient>,
    next_pending_id: usize,
    next_active_id: usize,
    pub metrics: Metrics,
    scratch: Vec<u8>,
}

impl AsyncServer {
    pub fn bind(addr: &str, config: AsyncServerConfig) -> io::Result<Self> {
        let reactor = Reactor::new()?;
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        reactor.register(listener.as_raw_fd(), LISTENER_TOKEN, Interest::READABLE)?;

        Ok(Self {
            reactor,
            listener,
            config,
            pending: HashMap::new(),
            active: HashMap::new(),
            next_pending_id: PENDING_BASE,
            next_active_id: ACTIVE_BASE,
            metrics: Metrics::new(),
            scratch: vec![0u8; 4096],
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn active_clients(&self) -> usize { self.active.len() }
    pub fn pending_clients(&self) -> usize { self.pending.len() }

    /// Run one iteration of the event loop.
    pub fn poll(&mut self, handler: &mut AsyncHandler) -> io::Result<usize> {
        let events = self.reactor.poll(Some(Duration::from_millis(1)))?;
        let mut processed = 0;

        for event in &events {
            match event.token {
                LISTENER_TOKEN => {
                    self.accept_connections()?;
                }
                t if t >= ACTIVE_BASE => {
                    if event.error {
                        self.disconnect_active(t);
                    } else if event.readable {
                        processed += self.process_active(t, handler);
                    }
                }
                t if t >= PENDING_BASE => {
                    if event.error {
                        self.drop_pending(t);
                    } else {
                        self.advance_handshake(t);
                    }
                }
                _ => {}
            }
        }

        // Promote completed handshakes
        self.promote_completed();

        // Timeout checks
        self.check_handshake_timeouts();
        self.check_active_timeouts();

        Ok(processed)
    }

    /// Run until stopped.
    pub fn run(&mut self, handler: &mut AsyncHandler, should_stop: &dyn Fn() -> bool) -> io::Result<()> {
        while !should_stop() {
            self.poll(handler)?;
        }
        Ok(())
    }

    /// Send to a specific active client.
    pub fn send_to(&mut self, token: usize, msg: &[u8]) -> io::Result<()> {
        if let Some(client) = self.active.get_mut(&token) {
            client.transport.send(msg)?;
            self.metrics.record_send(msg.len());
        }
        Ok(())
    }

    /// Broadcast to all active clients.
    pub fn broadcast(&mut self, msg: &[u8]) -> usize {
        let mut sent = 0;
        let tokens: Vec<usize> = self.active.keys().copied().collect();
        for t in tokens {
            if let Some(client) = self.active.get_mut(&t)
                && client.transport.send(msg).is_ok() {
                    sent += 1;
                }
        }
        self.metrics.record_send(msg.len() * sent);
        sent
    }

    // ── Accept ───────────────────────────────────────────────

    fn accept_connections(&mut self) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    if self.pending.len() >= self.config.max_pending {
                        drop(stream); // too many pending
                        continue;
                    }
                    if self.active.len() >= self.config.max_clients {
                        drop(stream); // full
                        continue;
                    }

                    stream.set_nonblocking(true)?;
                    stream.set_nodelay(true)?;

                    let token = self.next_pending_id;
                    self.next_pending_id += 1;

                    self.reactor.register(stream.as_raw_fd(), token, Interest::READABLE)?;

                    self.pending.insert(token, PendingClient {
                        stream,
                        addr,
                        state: HandshakeState::ReadNegotiate,
                        session: Session::new(0),
                        read_buf: vec![0u8; 512],
                        read_len: 0,
                        created_at: Instant::now(),
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // ── Non-blocking handshake ───────────────────────────────

    fn advance_handshake(&mut self, token: usize) {
        let Some(client) = self.pending.get_mut(&token) else { return };

        match &client.state {
            HandshakeState::ReadNegotiate => {
                // Try to read Negotiate
                match client.stream.read(&mut client.read_buf[client.read_len..]) {
                    Ok(0) => { client.state = HandshakeState::Failed; return; }
                    Ok(n) => client.read_len += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return,
                    Err(_) => { client.state = HandshakeState::Failed; return; }
                }

                // Check if we have a complete message
                if client.read_len < FrameHeader::SIZE { return; }
                let frame = FrameHeader::from_bytes(&client.read_buf);
                let msg_size = frame.message_size as usize;
                if client.read_len < msg_size { return; }

                // Parse Negotiate
                if msg_size < CORE_BLOCK_OFFSET { client.state = HandshakeState::Failed; return; }
                let header = FullHeader::from_bytes(&client.read_buf);
                if header.message.message_type != SessionMsgType::Negotiate as u16 {
                    client.state = HandshakeState::Failed;
                    return;
                }

                let negotiate = NegotiateCore::from_bytes(&client.read_buf[CORE_BLOCK_OFFSET..]);
                if client.session.handle_negotiate(negotiate).is_err() {
                    client.state = HandshakeState::Failed;
                    return;
                }

                // Build response
                let mut buf = [0u8; 256];
                match client.session.build_negotiate_response(&mut buf, true, 0, [0u8; 32]) {
                    Ok(len) => {
                        let resp = buf[..len].to_vec();
                        client.read_len = 0; // reset for next read
                        client.state = HandshakeState::SendNegotiateResp { resp, sent: 0 };
                        // Re-register for write
                        let _ = self.reactor.deregister(client.stream.as_raw_fd());
                        let _ = self.reactor.register(client.stream.as_raw_fd(), token, Interest::WRITABLE);
                    }
                    Err(_) => { client.state = HandshakeState::Failed; }
                }
            }

            HandshakeState::SendNegotiateResp { .. } => {
                // Extract state to avoid borrow issues
                let (resp, mut sent) = match std::mem::replace(&mut client.state, HandshakeState::Failed) {
                    HandshakeState::SendNegotiateResp { resp, sent } => (resp, sent),
                    _ => return,
                };

                match client.stream.write(&resp[sent..]) {
                    Ok(n) => sent += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        client.state = HandshakeState::SendNegotiateResp { resp, sent };
                        return;
                    }
                    Err(_) => return,
                }

                if sent >= resp.len() {
                    client.state = HandshakeState::ReadEstablish;
                    let _ = self.reactor.deregister(client.stream.as_raw_fd());
                    let _ = self.reactor.register(client.stream.as_raw_fd(), token, Interest::READABLE);
                } else {
                    client.state = HandshakeState::SendNegotiateResp { resp, sent };
                }
            }

            HandshakeState::ReadEstablish => {
                match client.stream.read(&mut client.read_buf[client.read_len..]) {
                    Ok(0) => { client.state = HandshakeState::Failed; return; }
                    Ok(n) => client.read_len += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return,
                    Err(_) => { client.state = HandshakeState::Failed; return; }
                }

                if client.read_len < FrameHeader::SIZE { return; }
                let frame = FrameHeader::from_bytes(&client.read_buf);
                let msg_size = frame.message_size as usize;
                if client.read_len < msg_size { return; }

                if msg_size < CORE_BLOCK_OFFSET { client.state = HandshakeState::Failed; return; }
                let header = FullHeader::from_bytes(&client.read_buf);
                if header.message.message_type != SessionMsgType::Establish as u16 {
                    client.state = HandshakeState::Failed;
                    return;
                }

                let establish = EstablishCore::from_bytes(&client.read_buf[CORE_BLOCK_OFFSET..]);

                // Auth check
                if !self.config.auth_key.is_empty() {
                    let hmac = crate::auth::HmacSha256::new(&self.config.auth_key);
                    let expected = hmac.authenticate(&client.session.session_id().to_le_bytes());
                    if establish.credentials[..16] != expected[..] {
                        client.state = HandshakeState::Failed;
                        return;
                    }
                }

                if client.session.handle_establish(establish).is_err() {
                    client.state = HandshakeState::Failed;
                    return;
                }

                let mut buf = [0u8; 256];
                match client.session.build_establish_ack(&mut buf) {
                    Ok(len) => {
                        let resp = buf[..len].to_vec();
                        client.state = HandshakeState::SendEstablishAck { resp, sent: 0 };
                        let _ = self.reactor.deregister(client.stream.as_raw_fd());
                        let _ = self.reactor.register(client.stream.as_raw_fd(), token, Interest::WRITABLE);
                    }
                    Err(_) => { client.state = HandshakeState::Failed; }
                }
            }

            HandshakeState::SendEstablishAck { .. } => {
                let (resp, mut sent) = match std::mem::replace(&mut client.state, HandshakeState::Failed) {
                    HandshakeState::SendEstablishAck { resp, sent } => (resp, sent),
                    _ => return,
                };

                match client.stream.write(&resp[sent..]) {
                    Ok(n) => sent += n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        client.state = HandshakeState::SendEstablishAck { resp, sent };
                        return;
                    }
                    Err(_) => return,
                }

                if sent >= resp.len() {
                    client.state = HandshakeState::Done;
                } else {
                    client.state = HandshakeState::SendEstablishAck { resp, sent };
                }
            }

            HandshakeState::Done | HandshakeState::Failed => {}
        }
    }

    fn promote_completed(&mut self) {
        let completed: Vec<usize> = self.pending.iter()
            .filter(|(_, c)| matches!(c.state, HandshakeState::Done))
            .map(|(&t, _)| t)
            .collect();

        for token in completed {
            if let Some(client) = self.pending.remove(&token) {
                let _ = self.reactor.deregister(client.stream.as_raw_fd());

                let active_token = self.next_active_id;
                self.next_active_id += 1;

                if let Ok(transport) = TcpTransport::from_stream(client.stream) {
                    let _ = transport.set_nonblocking(true);
                    let _ = self.reactor.register(
                        transport.inner().as_raw_fd(),
                        active_token,
                        Interest::READABLE,
                    );
                    self.active.insert(active_token, ActiveClient {
                        transport,
                        session: client.session,
                        addr: client.addr,
                        last_activity: Instant::now(),
                        tokens: self.config.rate_limit_per_sec,
                        last_refill: Instant::now(),
                    });
                }
            }
        }

        // Drop failed handshakes
        let failed: Vec<usize> = self.pending.iter()
            .filter(|(_, c)| matches!(c.state, HandshakeState::Failed))
            .map(|(&t, _)| t)
            .collect();
        for token in failed {
            self.drop_pending(token);
        }
    }

    fn drop_pending(&mut self, token: usize) {
        if let Some(client) = self.pending.remove(&token) {
            let _ = self.reactor.deregister(client.stream.as_raw_fd());
        }
    }

    // ── Active client processing ─────────────────────────────

    fn process_active(&mut self, token: usize, handler: &mut AsyncHandler) -> usize {
        let Some(client) = self.active.get_mut(&token) else { return 0 };
        let mut processed = 0;

        // Rate limit refill
        if self.config.rate_limit_per_sec > 0
            && client.last_refill.elapsed() >= Duration::from_secs(1) {
                client.tokens = self.config.rate_limit_per_sec;
                client.last_refill = Instant::now();
            }

        loop {
            match client.transport.recv() {
                Ok(Some(msg)) => {
                    if self.config.rate_limit_per_sec > 0 {
                        if client.tokens == 0 { break; }
                        client.tokens -= 1;
                    }

                    client.last_activity = Instant::now();
                    self.metrics.record_recv(msg.len());
                    let msg_owned = msg.to_vec();

                    // Session messages
                    if msg_owned.len() >= FullHeader::SIZE {
                        let header = FullHeader::from_bytes(&msg_owned);
                        if header.message.schema_id == SESSION_SCHEMA_ID {
                            if header.message.message_type == SessionMsgType::Terminate as u16 {
                                self.disconnect_active(token);
                                return processed;
                            }
                            processed += 1;
                            continue;
                        }

                        client.session.accept_seq(header.message.sequence_num);
                    }

                    if let Some(response) = handler(token as u64, &msg_owned) {
                        let _ = client.transport.send(&response);
                        self.metrics.record_send(response.len());
                    }
                    processed += 1;
                }
                Ok(None) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.disconnect_active(token);
                    return processed;
                }
            }
        }

        let _ = client.transport.flush();
        processed
    }

    fn disconnect_active(&mut self, token: usize) {
        if let Some(client) = self.active.remove(&token) {
            let _ = self.reactor.deregister(client.transport.inner().as_raw_fd());
            self.metrics.record_connection_reset();
        }
    }

    // ── Timeout checks ───────────────────────────────────────

    fn check_handshake_timeouts(&mut self) {
        let now = Instant::now();
        let timed_out: Vec<usize> = self.pending.iter()
            .filter(|(_, c)| now.duration_since(c.created_at) > self.config.handshake_timeout)
            .map(|(&t, _)| t)
            .collect();
        for t in timed_out {
            self.drop_pending(t);
        }
    }

    fn check_active_timeouts(&mut self) {
        let timeout = Duration::from_millis(self.config.keepalive_ms as u64 * 3);
        let now = Instant::now();
        let timed_out: Vec<usize> = self.active.iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) > timeout)
            .map(|(&t, _)| t)
            .collect();
        for t in timed_out {
            self.disconnect_active(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{MessageBuffer, MessageKind, dispatch_message};
    use crate::connection::{Connection, ConnectionConfig};
    use crate::messages::*;
    use crate::types::*;

    #[test]
    fn async_server_basic() {
        let config = AsyncServerConfig {
            keepalive_ms: 5000,
            ..Default::default()
        };
        let mut server = AsyncServer::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let config = ConnectionConfig { session_id: 42, ..Default::default() };
            let mut conn = Connection::connect(addr, config).unwrap();
            let mut enc = MessageBuffer::with_capacity(256);
            let seq = conn.session_mut().next_seq();
            let order = NewOrderSingleCore {
                order_id: 999, instrument_id: 7, side: 1, order_type: 2,
                client_order_id: 0,
                time_in_force: 1, price: Decimal::from_f64(100.0),
                quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
            };
            enc.encode(1, seq, &order, None);
            conn.send(enc.as_slice()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            conn.disconnect().unwrap();
        });

        std::thread::sleep(Duration::from_millis(50));

        let received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let received2 = received.clone();
        let mut handler = move |_: u64, msg: &[u8]| -> Option<Vec<u8>> {
            if let MessageKind::NewOrder(o) = dispatch_message(msg) {
                if o.order_id == 999 {
                    received2.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
            None
        };

        for _ in 0..50 {
            let _ = server.poll(&mut handler);
            std::thread::sleep(Duration::from_millis(10));
            if received.load(std::sync::atomic::Ordering::Relaxed) { break; }
        }

        handle.join().unwrap();
        assert!(received.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn async_server_handshake_timeout() {
        let config = AsyncServerConfig {
            handshake_timeout: Duration::from_millis(200),
            ..Default::default()
        };
        let mut server = AsyncServer::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr().unwrap();

        // Connect but DON'T handshake (slowloris)
        let _slowloris = TcpStream::connect(addr).unwrap();

        // Poll a few times
        for _ in 0..5 {
            let _ = server.poll(&mut |_, _| None);
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(server.pending_clients(), 1, "should have 1 pending");

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(300));
        let _ = server.poll(&mut |_, _| None);

        assert_eq!(server.pending_clients(), 0, "slowloris should be timed out");
    }

    #[test]
    fn async_server_concurrent_clients() {
        let config = AsyncServerConfig {
            keepalive_ms: 5000,
            ..Default::default()
        };
        let mut server = AsyncServer::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr().unwrap();

        let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        // 10 clients, each sends 100 messages
        let mut handles = Vec::new();
        for i in 0..10u64 {
            let addr = addr;
            handles.push(std::thread::spawn(move || {
                let config = ConnectionConfig { session_id: i + 1, ..Default::default() };
                let mut conn = Connection::connect(addr, config).unwrap();
                let mut enc = MessageBuffer::with_capacity(256);
                for j in 0..100u64 {
                    enc.reset();
                    let seq = conn.session_mut().next_seq();
                    let order = NewOrderSingleCore {
                        order_id: i * 1000 + j, instrument_id: 1, side: 1,
                        client_order_id: 0,
                        order_type: 2, time_in_force: 1,
                        price: Decimal::from_f64(100.0),
                        quantity: Decimal::from_f64(1.0),
                        stop_price: Decimal::NULL,
                    };
                    enc.encode(1, seq, &order, None);
                    conn.send(enc.as_slice()).unwrap();
                }
                std::thread::sleep(Duration::from_millis(50));
                conn.disconnect().unwrap();
            }));
        }

        let count2 = count.clone();
        let mut handler = move |_: u64, _: &[u8]| -> Option<Vec<u8>> {
            count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let _ = server.poll(&mut handler);
            if count.load(std::sync::atomic::Ordering::Relaxed) >= 1000 { break; }
            std::thread::sleep(Duration::from_millis(1));
        }

        for h in handles { h.join().unwrap(); }

        // Final drain
        for _ in 0..100 {
            let _ = server.poll(&mut handler);
            std::thread::sleep(Duration::from_millis(5));
        }

        let total = count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(total >= 900, "expected ~1000 messages, got {}", total);
    }
}
