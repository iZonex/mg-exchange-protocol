//! MGEP Server Framework — multi-client session management.
//!
//! Handles:
//!   - Accepting new TCP connections
//!   - Session handshake (Negotiate/Establish) with auth verification
//!   - Message routing to application handler
//!   - Per-client rate limiting
//!   - Heartbeat management for all clients
//!   - Graceful client disconnect
//!
//! Usage:
//!   let mut server = MgepServer::bind("0.0.0.0:9000", config)?;
//!   server.run(|client_id, msg| {
//!       // handle application message
//!       match dispatch_message(msg) { ... }
//!   });

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};


use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::metrics::Metrics;
use crate::session::*;
use crate::transport::TcpTransport;

/// Server configuration.
pub struct ServerConfig {
    /// Maximum concurrent clients.
    pub max_clients: usize,
    /// Keepalive interval (ms). Clients that don't heartbeat within 3x are disconnected.
    pub keepalive_ms: u32,
    /// Security level required for all clients.
    pub security_level: SecurityLevel,
    /// HMAC key for auth verification (empty = no auth check).
    pub auth_key: Vec<u8>,
    /// Rate limit: max messages per second per client (0 = unlimited).
    pub rate_limit_per_sec: u32,
    /// Non-blocking poll interval.
    pub poll_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_clients: 1024,
            keepalive_ms: 1000,
            security_level: SecurityLevel::None,
            auth_key: Vec::new(),
            rate_limit_per_sec: 0,
            poll_interval: Duration::from_millis(1),
        }
    }
}

/// Per-client state tracked by the server.
pub struct ClientState {
    pub id: u64,
    pub addr: SocketAddr,
    pub session: Session,
    pub transport: TcpTransport,
    pub connected_at: Instant,
    pub last_activity: Instant,
    // Rate limiting
    tokens: u32,
    last_refill: Instant,
}

/// Callback type for handling application messages.
/// Receives (client_id, raw message buffer).
/// Returns optional response bytes to send back.
pub type MessageHandler = dyn FnMut(u64, &[u8]) -> Option<Vec<u8>>;

/// MGEP server with multi-client management.
pub struct MgepServer {
    listener: TcpListener,
    config: ServerConfig,
    clients: HashMap<u64, ClientState>,
    next_client_id: u64,
    pub metrics: Metrics,
    buf: Vec<u8>,
}

impl MgepServer {
    /// Bind and start listening.
    pub fn bind(addr: &str, config: ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        Ok(Self {
            listener,
            config,
            clients: HashMap::new(),
            next_client_id: 1,
            metrics: Metrics::new(),
            buf: vec![0u8; 4096],
        })
    }

    /// Get local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Run one iteration of the server event loop.
    /// Accepts new clients, reads messages from all clients, calls handler.
    /// Returns the number of messages processed.
    pub fn poll(&mut self, handler: &mut MessageHandler) -> io::Result<usize> {
        let mut processed = 0;

        // Accept new connections
        self.accept_new_clients()?;

        // Process messages from all clients
        let client_ids: Vec<u64> = self.clients.keys().copied().collect();
        for client_id in client_ids {
            match self.poll_client(client_id, handler) {
                Ok(n) => processed += n,
                Err(_) => {
                    self.disconnect_client(client_id);
                }
            }
        }

        // Check for timed-out clients
        self.check_timeouts();

        Ok(processed)
    }

    /// Run the server loop continuously until stopped.
    /// `handler` is called for each application message.
    /// `should_stop` is checked each iteration.
    pub fn run(
        &mut self,
        handler: &mut MessageHandler,
        should_stop: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        while !should_stop() {
            let processed = self.poll(handler)?;
            if processed == 0 {
                std::thread::sleep(self.config.poll_interval);
            }
        }
        Ok(())
    }

    /// Broadcast a message to all connected clients.
    pub fn broadcast(&mut self, msg: &[u8]) -> usize {
        let mut sent = 0;
        let client_ids: Vec<u64> = self.clients.keys().copied().collect();
        for id in client_ids {
            if let Some(client) = self.clients.get_mut(&id) {
                if client.transport.send(msg).is_ok() {
                    sent += 1;
                    self.metrics.record_send(msg.len());
                }
            }
        }
        sent
    }

    /// Send a message to a specific client.
    pub fn send_to(&mut self, client_id: u64, msg: &[u8]) -> io::Result<()> {
        let client = self.clients.get_mut(&client_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "client not found"))?;
        client.transport.send(msg)?;
        self.metrics.record_send(msg.len());
        Ok(())
    }

    /// Disconnect a specific client.
    pub fn disconnect_client(&mut self, client_id: u64) {
        if let Some(mut client) = self.clients.remove(&client_id) {
            // Try to send Terminate gracefully
            let _ = client.session.build_terminate(&mut self.buf, 0)
                .and_then(|len| {
                    client.transport.send(&self.buf[..len])
                        .map_err(|_| SessionError::InvalidState {
                            current: client.session.state(),
                            operation: "disconnect",
                        })
                });
        }
    }

    // ── Internal ─────────────────────────────────────────────

    fn accept_new_clients(&mut self) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    if self.clients.len() >= self.config.max_clients {
                        drop(stream); // reject
                        continue;
                    }
                    if let Err(_e) = self.setup_client(stream, addr) {
                        // Handshake failed — silently drop
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn setup_client(&mut self, stream: TcpStream, addr: SocketAddr) -> io::Result<()> {
        stream.set_nonblocking(false)?; // blocking for handshake
        let mut transport = TcpTransport::from_stream(stream)?;
        let mut session = Session::new(0);

        // Step 1: Receive Negotiate
        let msg = transport.recv()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "no Negotiate")
        })?;
        if msg.len() < CORE_BLOCK_OFFSET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated"));
        }
        let header = FullHeader::from_bytes(msg);
        if header.message.message_type != SessionMsgType::Negotiate as u16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Negotiate"));
        }
        let negotiate = NegotiateCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
        session.handle_negotiate(negotiate)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Step 2: Send NegotiateResponse
        let len = session.build_negotiate_response(&mut self.buf, true, 0, [0u8; 32])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        transport.send(&self.buf[..len])?;
        transport.flush()?;

        // Step 3: Receive Establish
        let msg = transport.recv()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "no Establish")
        })?;
        let header = FullHeader::from_bytes(msg);
        if header.message.message_type != SessionMsgType::Establish as u16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected Establish"));
        }
        let establish = EstablishCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);

        // Verify credentials if auth is configured
        if !self.config.auth_key.is_empty() {
            let hmac = crate::auth::HmacSha256::new(&self.config.auth_key);
            let expected = hmac.authenticate(&session.session_id().to_le_bytes());
            if establish.credentials[..16] != expected[..] {
                // Reject: bad credentials
                let _ = session.handle_establish(establish);
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "bad credentials"));
            }
        }

        session.handle_establish(establish)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Step 4: Send EstablishAck
        let len = session.build_establish_ack(&mut self.buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        transport.send(&self.buf[..len])?;
        transport.flush()?;

        // Switch to non-blocking for the event loop
        transport.set_nonblocking(true)?;

        let client_id = self.next_client_id;
        self.next_client_id += 1;
        let now = Instant::now();

        self.clients.insert(client_id, ClientState {
            id: client_id,
            addr,
            session,
            transport,
            connected_at: now,
            last_activity: now,
            tokens: self.config.rate_limit_per_sec,
            last_refill: now,
        });

        Ok(())
    }

    fn poll_client(
        &mut self,
        client_id: u64,
        handler: &mut MessageHandler,
    ) -> io::Result<usize> {
        let mut processed = 0;

        // Borrow client, process messages, collect responses
        let mut responses: Vec<Vec<u8>> = Vec::new();

        let client = self.clients.get_mut(&client_id).unwrap();

        // Rate limit refill
        if self.config.rate_limit_per_sec > 0 {
            let elapsed = client.last_refill.elapsed();
            if elapsed >= Duration::from_secs(1) {
                client.tokens = self.config.rate_limit_per_sec;
                client.last_refill = Instant::now();
            }
        }

        loop {
            match client.transport.recv() {
                Ok(Some(msg)) => {
                    // Rate limit check
                    if self.config.rate_limit_per_sec > 0 {
                        if client.tokens == 0 {
                            break; // exceeded rate limit, process next tick
                        }
                        client.tokens -= 1;
                    }

                    client.last_activity = Instant::now();
                    self.metrics.record_recv(msg.len());

                    let msg_owned = msg.to_vec();

                    // Handle session messages internally
                    if msg_owned.len() >= FullHeader::SIZE {
                        let header = FullHeader::from_bytes(&msg_owned);
                        if header.message.schema_id == SESSION_SCHEMA_ID {
                            match header.message.message_type {
                                x if x == SessionMsgType::Heartbeat as u16 => {
                                    client.session.accept_seq(header.message.sequence_num);
                                }
                                x if x == SessionMsgType::Terminate as u16 => {
                                    client.session.handle_terminate();
                                    return Err(io::Error::new(
                                        io::ErrorKind::ConnectionReset, "client terminated",
                                    ));
                                }
                                _ => {}
                            }
                            processed += 1;
                            continue;
                        }

                        // Track sequence
                        let seq = header.message.sequence_num;
                        let check = client.session.check_seq(seq);
                        match check {
                            SeqCheck::Expected => {
                                client.session.accept_seq(seq);
                            }
                            SeqCheck::Gap { expected, received } => {
                                // Send NotApplied
                                let count = received - expected;
                                if let Ok(len) = client.session.build_not_applied(
                                    &mut self.buf, expected as u32, count as u32
                                ) {
                                    let _ = client.transport.send(&self.buf[..len]);
                                    self.metrics.record_sequence_gap();
                                }
                                client.session.accept_seq(seq);
                            }
                            SeqCheck::Duplicate => {
                                processed += 1;
                                continue; // skip duplicates
                            }
                        }
                    }

                    // Call application handler
                    if let Some(response) = handler(client_id, &msg_owned) {
                        responses.push(response);
                    }
                    processed += 1;
                }
                Ok(None) => break,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        // Send responses outside the borrow
        let client = self.clients.get_mut(&client_id).unwrap();
        for resp in responses {
            let _ = client.transport.send(&resp);
            self.metrics.record_send(resp.len());
        }
        let _ = client.transport.flush();

        Ok(processed)
    }

    fn check_timeouts(&mut self) {
        let timeout = Duration::from_millis(self.config.keepalive_ms as u64 * 3);
        let now = Instant::now();
        let timed_out: Vec<u64> = self.clients.iter()
            .filter(|(_, c)| now.duration_since(c.last_activity) > timeout)
            .map(|(&id, _)| id)
            .collect();

        for id in timed_out {
            self.metrics.record_connection_reset();
            self.disconnect_client(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{dispatch_message, MessageKind};
    use crate::connection::{Connection, ConnectionConfig};
    use crate::codec::MessageBuffer;
    use crate::messages::*;
    use crate::types::*;

    #[test]
    fn server_accept_and_handle_order() {
        let config = ServerConfig {
            keepalive_ms: 5000,
            ..Default::default()
        };
        let mut server = MgepServer::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let config = ConnectionConfig {
                session_id: 42,
                ..Default::default()
            };
            let mut conn = Connection::connect(addr, config).unwrap();

            let order = NewOrderSingleCore {
                order_id: 1000, instrument_id: 7, side: 1, order_type: 2,
                time_in_force: 1, price: Decimal::from_f64(100.0),
                quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
            };
            let seq = conn.session_mut().next_seq();
            let mut enc = MessageBuffer::with_capacity(256);
            enc.encode(1, seq, &order, None);
            conn.send(enc.as_slice()).unwrap();

            std::thread::sleep(std::time::Duration::from_millis(50));
            conn.disconnect().unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(100));

        let received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let received2 = received.clone();
        let mut handler = move |_client_id: u64, msg: &[u8]| -> Option<Vec<u8>> {
            if let MessageKind::NewOrder(o) = dispatch_message(msg) {
                if o.order_id == 1000 {
                    received2.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
            None
        };

        for _ in 0..20 {
            let _ = server.poll(&mut handler);
            std::thread::sleep(std::time::Duration::from_millis(20));
            if received.load(std::sync::atomic::Ordering::Relaxed) { break; }
        }

        handle.join().unwrap();
        assert!(received.load(std::sync::atomic::Ordering::Relaxed), "server should have received the order");
    }

    #[test]
    fn server_rate_limiting() {
        let config = ServerConfig {
            rate_limit_per_sec: 5,
            keepalive_ms: 5000,
            ..Default::default()
        };
        let mut server = MgepServer::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let config = ConnectionConfig { session_id: 1, ..Default::default() };
            let mut conn = Connection::connect(addr, config).unwrap();

            for i in 0..20u64 {
                let order = NewOrderSingleCore {
                    order_id: i, instrument_id: 1, side: 1, order_type: 2,
                    time_in_force: 1, price: Decimal::from_f64(100.0),
                    quantity: Decimal::from_f64(1.0), stop_price: Decimal::NULL,
                };
                let seq = conn.session_mut().next_seq();
                let mut enc = MessageBuffer::with_capacity(256);
                enc.encode(1, seq, &order, None);
                conn.send(enc.as_slice()).unwrap();
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
            conn.disconnect().unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(200));

        let count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let count2 = count.clone();
        let mut handler = move |_: u64, _: &[u8]| -> Option<Vec<u8>> {
            count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        };

        let _ = server.poll(&mut handler);

        handle.join().unwrap();
        let c = count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(c <= 10, "rate limiter should cap at ~5, got {}", c);
    }
}
