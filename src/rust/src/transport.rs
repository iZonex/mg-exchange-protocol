//! MGEP TCP Transport
//!
//! Non-blocking TCP transport with length-prefixed framing.
//! Designed for low-latency: TCP_NODELAY, optional SO_BUSY_POLL.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use crate::frame::FrameHeader;

/// Maximum message size (configurable per session, default 64KB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 65536;

/// TCP connection wrapper with read buffering for message framing.
pub struct TcpTransport {
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,   // Current read position in buffer
    read_len: usize,   // Valid data length in buffer
    write_buf: Vec<u8>,
    max_message_size: usize,
    max_version: u8,
}

impl TcpTransport {
    /// Connect to a remote MGEP endpoint.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Self::from_stream(stream)
    }

    /// Wrap an existing TCP stream.
    pub fn from_stream(stream: TcpStream) -> io::Result<Self> {
        // TCP_NODELAY: disable Nagle's algorithm for minimal latency
        stream.set_nodelay(true)?;

        Ok(Self {
            stream,
            read_buf: vec![0u8; DEFAULT_MAX_MESSAGE_SIZE * 2],
            read_pos: 0,
            read_len: 0,
            write_buf: vec![0u8; DEFAULT_MAX_MESSAGE_SIZE],
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_version: 255, // accept all versions by default
        })
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    /// Send a pre-encoded message. The buffer must contain a complete MGEP message
    /// with a valid frame header (message_size at offset 0).
    pub fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        self.stream.write_all(msg)
    }

    /// Try to receive a complete message. Returns a slice of the internal buffer
    /// containing one complete message, or None if not enough data yet.
    ///
    /// The returned slice is valid until the next call to recv().
    pub fn recv(&mut self) -> io::Result<Option<&[u8]>> {
        // Always compact buffer to offset 0 so that message data is aligned.
        // Vec<u8> is at least 8-byte aligned, so zero-copy struct casts are safe.
        if self.read_pos > 0 {
            if self.read_pos == self.read_len {
                self.read_pos = 0;
                self.read_len = 0;
            } else {
                let remaining = self.read_len - self.read_pos;
                self.read_buf.copy_within(self.read_pos..self.read_len, 0);
                self.read_pos = 0;
                self.read_len = remaining;
            }
        }

        // Check if we already have a complete message before reading more
        let available = self.read_len - self.read_pos;
        let need_more = if available >= FrameHeader::SIZE {
            let frame = FrameHeader::from_bytes(&self.read_buf[self.read_pos..]);
            available < frame.message_size as usize
        } else {
            true
        };

        // Only read from socket if we need more data
        if need_more {
            let n = match self.stream.read(&mut self.read_buf[self.read_len..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection closed")),
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                Err(e) => return Err(e),
            };
            self.read_len += n;
        }

        // Check if we have a complete message
        let available = self.read_len - self.read_pos;
        if available < FrameHeader::SIZE {
            return Ok(None); // Not enough for frame header
        }

        let frame = FrameHeader::from_bytes(&self.read_buf[self.read_pos..]);
        let msg_size = frame.message_size as usize;

        if msg_size > self.max_message_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message too large: {} > {}", msg_size, self.max_message_size),
            ));
        }

        // Minimum valid message: FullHeader (24 bytes) = Frame (8) + Message (16)
        if msg_size < crate::header::FullHeader::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message too small: {} (min {})", msg_size, crate::header::FullHeader::SIZE),
            ));
        }

        // Validate schema version
        if frame.version > self.max_version {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported version: {} (max {})", frame.version, self.max_version),
            ));
        }

        if available < msg_size {
            return Ok(None); // Not enough data for complete message
        }

        // We have a complete message
        let msg_start = self.read_pos;
        self.read_pos += msg_size;

        Ok(Some(&self.read_buf[msg_start..msg_start + msg_size]))
    }

    /// Get mutable access to the write buffer for zero-copy encoding.
    /// After encoding, call send_buffered() with the actual length.
    pub fn write_buffer(&mut self) -> &mut [u8] {
        &mut self.write_buf
    }

    /// Send the first `len` bytes of the write buffer.
    pub fn send_buffered(&mut self, len: usize) -> io::Result<()> {
        self.stream.write_all(&self.write_buf[..len])
    }

    /// Flush the underlying TCP stream.
    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    /// Get a reference to the underlying TcpStream for advanced options.
    pub fn inner(&self) -> &TcpStream {
        &self.stream
    }
}

/// MGEP TCP server — accepts incoming connections.
pub struct TcpServer {
    listener: TcpListener,
}

impl TcpServer {
    /// Bind to an address and start listening.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    /// Accept a new connection. Blocking.
    pub fn accept(&self) -> io::Result<TcpTransport> {
        let (stream, _addr) = self.listener.accept()?;
        TcpTransport::from_stream(stream)
    }

    /// Set non-blocking mode on the listener.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    /// Get the local address this server is bound to.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::messages::NewOrderSingleCore;
    use crate::types::*;

    #[test]
    fn tcp_client_server_roundtrip() {
        // Start server on random port
        let server = TcpServer::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        // Client connects
        let mut client = TcpTransport::connect(addr).unwrap();

        // Server accepts
        let mut server_conn = server.accept().unwrap();

        // Client sends a NewOrder
        let order = NewOrderSingleCore {
            order_id: 42,
            client_order_id: 0,
            instrument_id: 1,
            side: Side::Buy as u8,
            order_type: OrderType::Limit as u8,
            time_in_force: TimeInForce::Day as u16,
            price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0),
            stop_price: Decimal::NULL,
        };

        let mut encoder = MessageBuffer::with_capacity(256);
        encoder.encode_new_order(1, 1, &order, None);
        client.send(encoder.as_slice()).unwrap();
        client.flush().unwrap();

        // Server receives
        // In blocking mode, recv will read until we have a complete message
        let msg = server_conn.recv().unwrap().unwrap();

        let decoded = MessageBuffer::decode_new_order(msg);
        assert_eq!(decoded.order_id, 42);
        assert_eq!(decoded.side(), Some(Side::Buy));
        assert!((decoded.price.to_f64() - 100.0).abs() < 1e-6);
    }

    #[test]
    fn tcp_multiple_messages() {
        let server = TcpServer::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let mut client = TcpTransport::connect(addr).unwrap();
        let mut server_conn = server.accept().unwrap();

        // Send 100 messages
        for i in 0..100u64 {
            let order = NewOrderSingleCore {
                order_id: i,
                client_order_id: 0,
                instrument_id: 1,
                side: Side::Buy as u8,
                order_type: OrderType::Limit as u8,
                time_in_force: TimeInForce::Day as u16,
                price: Decimal::from_f64(100.0 + i as f64),
                quantity: Decimal::from_f64(10.0),
                stop_price: Decimal::NULL,
            };

            let mut encoder = MessageBuffer::with_capacity(256);
            encoder.encode_new_order(1, i as u64, &order, None);
            client.send(encoder.as_slice()).unwrap();
        }
        client.flush().unwrap();

        // Receive all 100 messages
        for i in 0..100u64 {
            let msg = server_conn.recv().unwrap().unwrap();
            let decoded = MessageBuffer::decode_new_order(msg);
            assert_eq!(decoded.order_id, i);
        }
    }

    #[test]
    fn tcp_write_buffer_zero_copy() {
        let server = TcpServer::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let mut client = TcpTransport::connect(addr).unwrap();
        let mut server_conn = server.accept().unwrap();

        // Encode directly into transport's write buffer
        let order = NewOrderSingleCore {
            order_id: 999,
            client_order_id: 0,
            instrument_id: 7,
            side: Side::Sell as u8,
            order_type: OrderType::Market as u8,
            time_in_force: TimeInForce::IOC as u16,
            price: Decimal::NULL,
            quantity: Decimal::from_f64(50.0),
            stop_price: Decimal::NULL,
        };

        // Build message directly into the transport buffer
        let buf = client.write_buffer();
        // Write directly into the transport buffer
        let total = (32 + NewOrderSingleCore::SIZE) as u32;
        let header = crate::header::FullHeader::new(
            0x0001, 0x01, 1, 1, 0, total, crate::frame::FrameFlags::NONE,
        );
        header.write_to(buf);
        buf[32..32 + NewOrderSingleCore::SIZE].copy_from_slice(order.as_bytes());

        client.send_buffered(total as usize).unwrap();
        client.flush().unwrap();

        let msg = server_conn.recv().unwrap().unwrap();
        let decoded = MessageBuffer::decode_new_order(msg);
        assert_eq!(decoded.order_id, 999);
        assert_eq!(decoded.side(), Some(Side::Sell));
    }
}
