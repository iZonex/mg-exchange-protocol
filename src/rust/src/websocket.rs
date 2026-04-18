//! WebSocket Binary Transport — wraps MGEP in WebSocket binary frames.
//!
//! Gives 10x improvement over WS+JSON with zero client infrastructure changes.
//! Uses RFC 6455 WebSocket protocol with binary opcode (0x02).
//!
//! Design:
//!   - Pure Rust WebSocket implementation (no external deps)
//!   - Only binary frames (no text, no fragmentation for simplicity)
//!   - Client-side masking per RFC 6455
//!   - Server-side: no masking (per spec, server→client is unmasked)
//!   - HTTP/1.1 Upgrade handshake with Sec-WebSocket-Key/Accept
//!
//! Wire format:
//!   [WS frame header (2-14 bytes)] [MGEP message (N bytes)]
//!
//! Each WebSocket binary frame contains exactly one MGEP message.
//! Batching is done at the MGEP level (BatchWriter), not WS level.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};


// ============================================================================
// WebSocket frame encoding/decoding (RFC 6455)
// ============================================================================

const WS_OPCODE_BINARY: u8 = 0x02;
const WS_OPCODE_CLOSE: u8 = 0x08;
const WS_OPCODE_PING: u8 = 0x09;
const WS_OPCODE_PONG: u8 = 0x0A;
const WS_FIN_BIT: u8 = 0x80;
const WS_MASK_BIT: u8 = 0x80;

/// WebSocket transport for MGEP — client side.
pub struct WsClient {
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
}

/// WebSocket transport for MGEP — server side (accepted connection).
pub struct WsConnection {
    stream: TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_len: usize,
}

/// WebSocket server — accepts incoming WS connections.
pub struct WsServer {
    listener: TcpListener,
}

impl WsClient {
    /// Connect to a WebSocket MGEP server.
    /// Performs HTTP Upgrade handshake.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;

        let mut client = Self {
            stream,
            read_buf: vec![0u8; 131072],
            read_pos: 0,
            read_len: 0,
        };

        client.do_client_handshake()?;
        Ok(client)
    }

    /// Send an MGEP message as a WebSocket binary frame (client-masked).
    pub fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        let mask_key = generate_mask_key();
        let frame = encode_ws_frame(msg, WS_OPCODE_BINARY, true, &mask_key);
        self.stream.write_all(&frame)
    }

    /// Receive the next MGEP message from a WebSocket binary frame.
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        recv_ws_message(&mut self.stream, &mut self.read_buf, &mut self.read_pos, &mut self.read_len)
    }

    /// Flush the underlying stream.
    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    /// Send a WebSocket close frame.
    pub fn close(&mut self) -> io::Result<()> {
        let mask_key = generate_mask_key();
        let frame = encode_ws_frame(&[], WS_OPCODE_CLOSE, true, &mask_key);
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn do_client_handshake(&mut self) -> io::Result<()> {
        // Generate Sec-WebSocket-Key (base64 of 16 random bytes)
        let key_bytes: [u8; 16] = {
            let mut k = [0u8; 16];
            // Simple pseudo-random (not cryptographic, fine for WS handshake)
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            for (i, b) in k.iter_mut().enumerate() {
                *b = ((seed >> (i * 3)) & 0xFF) as u8;
            }
            k
        };
        let key = base64_encode(&key_bytes);

        let request = format!(
            "GET /mgep HTTP/1.1\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: mgep\r\n\
             \r\n",
            key
        );

        self.stream.write_all(request.as_bytes())?;
        self.stream.flush()?;

        // Read response (just verify 101 status)
        let mut resp_buf = [0u8; 1024];
        let n = self.stream.read(&mut resp_buf)?;
        let resp = std::str::from_utf8(&resp_buf[..n])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid handshake response"))?;

        if !resp.starts_with("HTTP/1.1 101") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("WebSocket handshake failed: {}", resp.lines().next().unwrap_or("")),
            ));
        }

        Ok(())
    }
}

impl WsServer {
    /// Bind to an address and start listening.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener })
    }

    /// Accept a new WebSocket connection (performs server-side handshake).
    pub fn accept(&self) -> io::Result<WsConnection> {
        let (stream, _addr) = self.listener.accept()?;
        stream.set_nodelay(true)?;

        let mut conn = WsConnection {
            stream,
            read_buf: vec![0u8; 131072],
            read_pos: 0,
            read_len: 0,
        };

        conn.do_server_handshake()?;
        Ok(conn)
    }

    /// Get the local address.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }
}

impl WsConnection {
    /// Send an MGEP message as a WebSocket binary frame (server — unmasked).
    pub fn send(&mut self, msg: &[u8]) -> io::Result<()> {
        let frame = encode_ws_frame(msg, WS_OPCODE_BINARY, false, &[0; 4]);
        self.stream.write_all(&frame)
    }

    /// Receive the next MGEP message.
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        recv_ws_message(&mut self.stream, &mut self.read_buf, &mut self.read_pos, &mut self.read_len)
    }

    /// Flush the underlying stream.
    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    /// Send a WebSocket close frame.
    pub fn close(&mut self) -> io::Result<()> {
        let frame = encode_ws_frame(&[], WS_OPCODE_CLOSE, false, &[0; 4]);
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn do_server_handshake(&mut self) -> io::Result<()> {
        // Read client request
        let mut req_buf = [0u8; 4096];
        let n = self.stream.read(&mut req_buf)?;
        let req = std::str::from_utf8(&req_buf[..n])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid handshake"))?;

        // Extract Sec-WebSocket-Key
        let key = req.lines()
            .find(|l| l.to_lowercase().starts_with("sec-websocket-key:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|k| k.trim().to_string())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Sec-WebSocket-Key"))?;

        // Compute Sec-WebSocket-Accept = BASE64(SHA1(key + GUID))
        let accept = compute_ws_accept(&key);

        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             Sec-WebSocket-Protocol: mgep\r\n\
             \r\n",
            accept
        );

        self.stream.write_all(response.as_bytes())?;
        self.stream.flush()
    }
}

// ============================================================================
// WebSocket frame codec
// ============================================================================

fn encode_ws_frame(payload: &[u8], opcode: u8, masked: bool, mask_key: &[u8; 4]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(14 + len);

    // Byte 0: FIN + opcode
    frame.push(WS_FIN_BIT | opcode);

    // Byte 1+: MASK + payload length
    let mask_bit = if masked { WS_MASK_BIT } else { 0 };
    if len < 126 {
        frame.push(mask_bit | len as u8);
    } else if len <= 65535 {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }

    // Mask key (client→server only)
    if masked {
        frame.extend_from_slice(mask_key);
        // Masked payload
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask_key[i % 4]);
        }
    } else {
        frame.extend_from_slice(payload);
    }

    frame
}

fn recv_ws_message(
    stream: &mut TcpStream,
    buf: &mut [u8],
    pos: &mut usize,
    len: &mut usize,
) -> io::Result<Option<Vec<u8>>> {
    // Ensure we have data
    if *pos >= *len {
        *pos = 0;
        *len = 0;
    }

    // Read more data if needed
    loop {
        let available = *len - *pos;
        if available >= 2 {
            // Try to parse a frame
            let data = &buf[*pos..*len];
            if let Some((payload, frame_size)) = decode_ws_frame(data)? {
                *pos += frame_size;
                return Ok(Some(payload));
            }
        }

        // Need more data
        if *len >= buf.len() {
            // Compact
            if *pos > 0 {
                let remaining = *len - *pos;
                buf.copy_within(*pos..*len, 0);
                *pos = 0;
                *len = remaining;
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "WS frame too large"));
            }
        }

        let n = stream.read(&mut buf[*len..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection closed"));
        }
        *len += n;
    }
}

/// Try to decode a WebSocket frame from a buffer.
/// Returns (payload, total_frame_size) or None if not enough data.
fn decode_ws_frame(data: &[u8]) -> io::Result<Option<(Vec<u8>, usize)>> {
    if data.len() < 2 {
        return Ok(None);
    }

    let opcode = data[0] & 0x0F;
    let masked = (data[1] & WS_MASK_BIT) != 0;
    let len_byte = data[1] & 0x7F;

    let (payload_len, header_size) = if len_byte < 126 {
        (len_byte as usize, 2)
    } else if len_byte == 126 {
        if data.len() < 4 { return Ok(None); }
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        (len, 4)
    } else {
        if data.len() < 10 { return Ok(None); }
        let len = u64::from_be_bytes(data[2..10].try_into().unwrap()) as usize;
        (len, 10)
    };

    let mask_size = if masked { 4 } else { 0 };
    let total_frame_size = header_size + mask_size + payload_len;

    if data.len() < total_frame_size {
        return Ok(None); // not enough data
    }

    // Handle control frames
    match opcode {
        WS_OPCODE_CLOSE => {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "WS close frame"));
        }
        WS_OPCODE_PING | WS_OPCODE_PONG => {
            // Skip control frames, return None to retry
            return Ok(Some((Vec::new(), total_frame_size)));
        }
        WS_OPCODE_BINARY => {} // our data
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected WS opcode: 0x{:02X}", opcode),
            ));
        }
    }

    let payload_start = header_size + mask_size;
    let mut payload = data[payload_start..payload_start + payload_len].to_vec();

    // Unmask if needed
    if masked {
        let mask_key = &data[header_size..header_size + 4];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask_key[i % 4];
        }
    }

    Ok(Some((payload, total_frame_size)))
}

// ============================================================================
// SHA-1 for WebSocket handshake (RFC 6455 requires it)
// ============================================================================

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn compute_ws_accept(key: &str) -> String {
    let mut input = String::with_capacity(key.len() + WS_GUID.len());
    input.push_str(key);
    input.push_str(WS_GUID);
    let hash = sha1(input.as_bytes());
    base64_encode(&hash)
}

/// Minimal SHA-1 implementation (only used for WS handshake, not security).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ============================================================================
// Base64 (minimal, for WS handshake only)
// ============================================================================

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(B64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(B64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(B64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn generate_mask_key() -> [u8; 4] {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    [
        (ns & 0xFF) as u8,
        ((ns >> 8) & 0xFF) as u8,
        ((ns >> 16) & 0xFF) as u8,
        ((ns >> 24) & 0xFF) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_frame_encode_decode_unmasked() {
        let payload = b"Hello MGEP over WebSocket!";
        let frame = encode_ws_frame(payload, WS_OPCODE_BINARY, false, &[0; 4]);

        let (decoded, size) = decode_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(size, frame.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ws_frame_encode_decode_masked() {
        let payload = b"Masked payload data";
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        let frame = encode_ws_frame(payload, WS_OPCODE_BINARY, true, &mask_key);

        let (decoded, size) = decode_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(size, frame.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ws_frame_large_payload() {
        // 16KB payload (uses 2-byte extended length)
        let payload = vec![0xABu8; 16384];
        let frame = encode_ws_frame(&payload, WS_OPCODE_BINARY, false, &[0; 4]);

        let (decoded, _) = decode_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(decoded.len(), 16384);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ws_frame_mgep_message() {
        // Encode a real MGEP message into WS frame
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = crate::codec::MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);

        let frame = encode_ws_frame(enc.as_slice(), WS_OPCODE_BINARY, true, &[0x11, 0x22, 0x33, 0x44]);
        let (decoded, _) = decode_ws_frame(&frame).unwrap().unwrap();

        // Verify MGEP message is intact
        let header = crate::header::FullHeader::from_bytes(&decoded);
        assert_eq!(header.message.schema_id, 0x0001);
        assert_eq!(header.message.message_type, 0x01);

        let decoded_order = crate::codec::MessageBuffer::decode_new_order(&decoded);
        assert_eq!(decoded_order.order_id, 42);
    }

    #[test]
    fn sha1_known_vector() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = sha1(b"");
        assert_eq!(hash[0], 0xda);
        assert_eq!(hash[1], 0x39);
        assert_eq!(hash[19], 0x09);
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn ws_accept_computation() {
        // RFC 6455 example: key = "dGhlIHNhbXBsZSBub25jZQ=="
        let accept = compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ws_client_server_roundtrip() {
        let server = WsServer::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let mut conn = server.accept().unwrap();

            // Receive MGEP message
            let msg = conn.recv().unwrap().unwrap();
            let order = crate::codec::MessageBuffer::decode_new_order(&msg);
            assert_eq!(order.order_id, 123);

            // Send back
            conn.send(&msg).unwrap();
            conn.flush().unwrap();
        });

        let mut client = WsClient::connect(addr).unwrap();

        // Build and send MGEP order
        let order = crate::messages::NewOrderSingleCore {
            order_id: 123, instrument_id: 1, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(50.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = crate::codec::MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);

        client.send(enc.as_slice()).unwrap();
        client.flush().unwrap();

        // Receive echo
        let msg = client.recv().unwrap().unwrap();
        let decoded = crate::codec::MessageBuffer::decode_new_order(&msg);
        assert_eq!(decoded.order_id, 123);

        handle.join().unwrap();
    }
}
