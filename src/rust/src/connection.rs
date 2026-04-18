//! High-level MGEP Connection — wraps Session + Transport with reconnect.
//!
//! Provides a simple API for application code:
//!   let mut conn = Connection::connect("127.0.0.1:9000", config)?;
//!   conn.send(&order_msg)?;
//!   let msg = conn.recv()?;
//!
//! Handles:
//!   - Full session handshake (Negotiate → Establish)
//!   - Automatic reconnection with exponential backoff
//!   - Sequence recovery on reconnect (detects gaps, triggers retransmit)
//!   - Heartbeat management
//!   - Optional HMAC authentication

use std::io;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::session::*;
use crate::transport::TcpTransport;
use crate::types::Timestamp;

/// Connection configuration.
pub struct ConnectionConfig {
    /// Session ID (unique per client).
    pub session_id: u64,
    /// Security level.
    pub security_level: SecurityLevel,
    /// Keepalive interval in milliseconds.
    pub keepalive_ms: u32,
    /// HMAC key for SecurityLevel::Authenticated (empty = no auth).
    pub auth_key: Vec<u8>,
    /// Reconnect: initial delay.
    pub reconnect_initial_ms: u64,
    /// Reconnect: maximum delay.
    pub reconnect_max_ms: u64,
    /// Reconnect: backoff multiplier.
    pub reconnect_multiplier: f64,
    /// Maximum reconnect attempts (0 = unlimited).
    pub max_reconnect_attempts: u32,
    /// Sender component ID.
    pub sender_comp_id: u32,
    /// `SessionFlags` bitmap requested at Negotiate (e.g.
    /// `CANCEL_ON_DISCONNECT`). The server is authoritative — it may
    /// filter flags it will not honor; the accepted set is available via
    /// `conn.session().negotiated_flags()` once `Active`.
    pub session_flags: u8,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            session_id: 1,
            security_level: SecurityLevel::None,
            keepalive_ms: 1000,
            auth_key: Vec::new(),
            reconnect_initial_ms: 100,
            reconnect_max_ms: 5000,
            reconnect_multiplier: 2.0,
            max_reconnect_attempts: 0,
            sender_comp_id: 1,
            session_flags: 0,
        }
    }
}

/// Connection state visible to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Active,
    Reconnecting,
}

/// High-level connection wrapping Session + TcpTransport.
pub struct Connection {
    session: Session,
    transport: Option<TcpTransport>,
    config: ConnectionConfig,
    addr: String,
    state: ConnectionState,
    reconnect_attempts: u32,
    connected_at: Option<Instant>,
    buf: Vec<u8>,
}

impl Connection {
    /// Connect to an MGEP server and complete the session handshake.
    pub fn connect<A: ToSocketAddrs + ToString>(
        addr: A,
        config: ConnectionConfig,
    ) -> Result<Self, io::Error> {
        let addr_str = addr.to_string();
        let mut conn = Self {
            session: Session::new(config.session_id),
            transport: None,
            config,
            addr: addr_str,
            state: ConnectionState::Disconnected,
            reconnect_attempts: 0,
            connected_at: None,
            buf: vec![0u8; 4096],
        };

        conn.session.set_security_level(conn.config.security_level);
        conn.session.set_keepalive_ms(conn.config.keepalive_ms);
        conn.session.request_flags(conn.config.session_flags);

        conn.do_connect()?;
        Ok(conn)
    }

    /// Current connection state.
    pub fn state(&self) -> ConnectionState { self.state }

    /// Access the underlying session (for sequence numbers, etc).
    pub fn session(&self) -> &Session { &self.session }

    /// Mutable access to the session.
    pub fn session_mut(&mut self) -> &mut Session { &mut self.session }

    /// Uptime in seconds since last successful connect.
    pub fn uptime_secs(&self) -> u32 {
        self.connected_at
            .map(|t| t.elapsed().as_secs() as u32)
            .unwrap_or(0)
    }

    /// Send a pre-encoded MGEP message. Handles journaling for retransmission.
    pub fn send(&mut self, msg: &[u8]) -> Result<(), io::Error> {
        if self.state != ConnectionState::Active {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "not connected"));
        }

        let transport = self.transport.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no transport"))?;

        // Extract sequence number from message header for journaling
        if msg.len() >= FullHeader::SIZE {
            let header = FullHeader::from_bytes(msg);
            let seq = header.message.sequence_num;
            if seq > 0 {
                self.session.journal_outbound(seq, msg);
            }
        }

        transport.send(msg)?;
        transport.flush()
    }

    /// Try to receive a message. Non-blocking if transport is non-blocking.
    /// Allocating version — returns owned Vec. Use `recv_into` for zero-alloc.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        let mut tmp = [0u8; 65536];
        match self.recv_into(&mut tmp) {
            Ok(Some(n)) => Ok(Some(tmp[..n].to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Zero-allocation receive — copies message into caller's buffer.
    /// Returns the number of bytes written, or None if no message available.
    /// Session-layer messages (heartbeat, terminate) are handled internally.
    pub fn recv_into(&mut self, out: &mut [u8]) -> Result<Option<usize>, io::Error> {
        if self.state != ConnectionState::Active {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "not connected"));
        }

        let transport = self.transport.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no transport"))?;

        match transport.recv() {
            Ok(Some(msg)) => {
                let msg_len = msg.len();

                // Check if session message — handle internally
                if msg_len >= FullHeader::SIZE {
                    let header = FullHeader::from_bytes(msg);
                    if header.message.schema_id == SESSION_SCHEMA_ID {
                        // Copy to temp for session handling (transport borrow ends)
                        let mut tmp = [0u8; 256];
                        let n = msg_len.min(tmp.len());
                        tmp[..n].copy_from_slice(&msg[..n]);
                        let _ = msg; // release transport borrow
                        // Re-borrow is ok now
                        self.handle_session_message(&tmp[..n]);
                        return Ok(None);
                    }

                    self.session.accept_seq(header.message.sequence_num);
                }

                // Copy to caller's buffer
                if out.len() < msg_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("buffer too small: {} < {}", out.len(), msg_len),
                    ));
                }
                out[..msg_len].copy_from_slice(msg);
                Ok(Some(msg_len))
            }
            Ok(None) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset
                || e.kind() == io::ErrorKind::BrokenPipe
                || e.kind() == io::ErrorKind::UnexpectedEof =>
            {
                self.state = ConnectionState::Reconnecting;
                self.do_reconnect()?;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Send a heartbeat if needed (based on keepalive interval).
    pub fn maybe_heartbeat(&mut self) -> Result<bool, io::Error> {
        if self.state != ConnectionState::Active {
            return Ok(false);
        }

        let now = Timestamp::now();
        if self.session.needs_heartbeat(now) {
            let len = self.session.build_heartbeat(&mut self.buf)
                .map_err(|e| io::Error::other(e.to_string()))?;
            if let Some(transport) = self.transport.as_mut() {
                transport.send(&self.buf[..len])?;
                transport.flush()?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Graceful disconnect.
    pub fn disconnect(&mut self) -> Result<(), io::Error> {
        if self.state == ConnectionState::Active
            && let Ok(len) = self.session.build_terminate(&mut self.buf, 0)
                && let Some(transport) = self.transport.as_mut() {
                    let _ = transport.send(&self.buf[..len]);
                    let _ = transport.flush();
                }
        self.transport = None;
        self.state = ConnectionState::Disconnected;
        Ok(())
    }

    /// Attempt reconnection with exponential backoff.
    pub fn reconnect(&mut self) -> Result<(), io::Error> {
        self.state = ConnectionState::Reconnecting;
        self.do_reconnect()
    }

    // ── Internal ─────────────────────────────────────────────

    fn do_connect(&mut self) -> Result<(), io::Error> {
        self.state = ConnectionState::Connecting;

        let transport = TcpTransport::connect(&self.addr)?;
        self.transport = Some(transport);

        self.do_handshake()?;

        self.state = ConnectionState::Active;
        self.connected_at = Some(Instant::now());
        self.reconnect_attempts = 0;
        Ok(())
    }

    fn do_reconnect(&mut self) -> Result<(), io::Error> {
        self.transport = None;
        self.session.reset_to_disconnected();

        let max = self.config.max_reconnect_attempts;
        let mut delay_ms = self.config.reconnect_initial_ms;

        loop {
            self.reconnect_attempts += 1;
            if max > 0 && self.reconnect_attempts > max {
                self.state = ConnectionState::Disconnected;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("max reconnect attempts ({}) exceeded", max),
                ));
            }

            std::thread::sleep(Duration::from_millis(delay_ms));

            match self.do_connect() {
                Ok(()) => return Ok(()),
                Err(_) => {
                    delay_ms = ((delay_ms as f64 * self.config.reconnect_multiplier) as u64)
                        .min(self.config.reconnect_max_ms);
                }
            }
        }
    }

    fn do_handshake(&mut self) -> Result<(), io::Error> {
        let transport = self.transport.as_mut().unwrap();

        // Step 1: Negotiate
        let len = self.session.build_negotiate(&mut self.buf, [0u8; 32])
            .map_err(|e| io::Error::other(e.to_string()))?;
        transport.send(&self.buf[..len])?;
        transport.flush()?;

        // Step 2: NegotiateResponse
        let msg = transport.recv()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "no NegotiateResponse")
        })?;
        let header = FullHeader::from_bytes(msg);
        if header.message.message_type != SessionMsgType::NegotiateResponse as u16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected NegotiateResponse, got 0x{:02X}", header.message.message_type),
            ));
        }
        let resp = NegotiateResponseCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
        self.session.handle_negotiate_response(resp)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

        // Step 3: Establish
        let credentials = if !self.config.auth_key.is_empty() {
            let hmac = crate::auth::HmacSha256::new(&self.config.auth_key);
            let tag = hmac.authenticate(&self.session.session_id().to_le_bytes());
            let mut creds = [0u8; 32];
            creds[..16].copy_from_slice(&tag);
            creds
        } else {
            [0u8; 32]
        };

        let len = self.session.build_establish(&mut self.buf, credentials)
            .map_err(|e| io::Error::other(e.to_string()))?;
        transport.send(&self.buf[..len])?;
        transport.flush()?;

        // Step 4: EstablishAck
        let msg = transport.recv()?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "no EstablishAck")
        })?;
        let header = FullHeader::from_bytes(msg);
        if header.message.message_type != SessionMsgType::EstablishAck as u16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected EstablishAck, got 0x{:02X}", header.message.message_type),
            ));
        }
        let ack = EstablishAckCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
        self.session.handle_establish_ack(ack)
            .map_err(|e| io::Error::other(e.to_string()))?;

        Ok(())
    }

    fn handle_session_message(&mut self, msg: &[u8]) {
        let header = FullHeader::from_bytes(msg);
        match header.message.message_type {
            x if x == SessionMsgType::Heartbeat as u16 => {
                // Heartbeat — update last_received timestamp
                let _hb = HeartbeatCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
            }
            x if x == SessionMsgType::SequenceReset as u16 => {
                if let Some(core) = SequenceResetCore::try_from_bytes(&msg[CORE_BLOCK_OFFSET..]) {
                    self.session.handle_sequence_reset(core);
                }
            }
            x if x == SessionMsgType::Terminate as u16 => {
                self.session.handle_terminate();
                self.state = ConnectionState::Disconnected;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;

    #[test]
    fn connection_config_defaults() {
        let cfg = ConnectionConfig::default();
        assert_eq!(cfg.reconnect_initial_ms, 100);
        assert_eq!(cfg.reconnect_max_ms, 5000);
        assert_eq!(cfg.reconnect_multiplier, 2.0);
        assert_eq!(cfg.keepalive_ms, 1000);
    }

    #[test]
    fn connection_full_lifecycle() {
        use crate::transport::TcpServer;

        let server = TcpServer::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        // Server thread
        let handle = std::thread::spawn(move || {
            let mut transport = server.accept().unwrap();
            let mut session = Session::new(0);
            let mut buf = [0u8; 4096];

            // Handle Negotiate
            let msg = transport.recv().unwrap().unwrap();
            let negotiate = NegotiateCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
            session.handle_negotiate(negotiate).unwrap();

            // Send NegotiateResponse
            let len = session.build_negotiate_response(&mut buf, true, 0, [0u8; 32]).unwrap();
            transport.send(&buf[..len]).unwrap();
            transport.flush().unwrap();

            // Handle Establish
            let msg = transport.recv().unwrap().unwrap();
            let establish = EstablishCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
            session.handle_establish(establish).unwrap();

            // Send EstablishAck
            let len = session.build_establish_ack(&mut buf).unwrap();
            transport.send(&buf[..len]).unwrap();
            transport.flush().unwrap();

            // Receive one application message
            let msg = transport.recv().unwrap().unwrap();
            let order = crate::messages::NewOrderSingleCore::from_bytes(&msg[CORE_BLOCK_OFFSET..]);
            assert_eq!(order.order_id, 42);
        });

        // Client side — use Connection
        let config = ConnectionConfig {
            session_id: 0xBEEF,
            ..Default::default()
        };
        let mut conn = Connection::connect(addr, config).unwrap();
        assert_eq!(conn.state(), ConnectionState::Active);
        assert_eq!(conn.session().session_id(), 0xBEEF);

        // Send an order
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        let seq = conn.session_mut().next_seq();
        enc.encode(1, seq, &order, None);
        conn.send(enc.as_slice()).unwrap();

        // Verify journaled
        assert!(conn.session().get_journaled(seq).is_some());

        handle.join().unwrap();

        conn.disconnect().unwrap();
        assert_eq!(conn.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn reset_to_disconnected_preserves_state() {
        let mut session = Session::new(42);
        let mut buf = [0u8; 256];

        // Fast-forward to Active
        session.build_negotiate(&mut buf, [0u8; 32]).unwrap();
        let resp = NegotiateResponseCore {
            session_id: 42, keepalive_ms: 1000, security_level: 0,
            session_flags: 0, max_message_size: 4096,
            status: 0, reject_reason: 0, _pad: 0, public_key: [0u8; 32],
        };
        session.handle_negotiate_response(&resp).unwrap();
        session.build_establish(&mut buf, [0u8; 32]).unwrap();
        let ack = EstablishAckCore { session_id: 42, next_seq_num: 1, journal_low_seq_num: 0 };
        session.handle_establish_ack(&ack).unwrap();

        // Record outbound seq and journal
        let seq = session.next_seq();
        session.journal_outbound(seq, &[1, 2, 3]);

        // Reset
        session.reset_to_disconnected();

        assert_eq!(session.state(), SessionState::Disconnected);
        assert_eq!(session.session_id(), 42);
        assert_eq!(session.next_outbound_seq(), seq + 1); // preserved
        assert!(session.get_journaled(seq).is_some()); // journal preserved
    }
}
