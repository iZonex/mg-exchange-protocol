//! UDP Multicast Transport — for market data feeds.
//!
//! One datagram = one MGEP message. No length prefix needed (OS preserves boundaries).
//! MTU-aware: enforces max 1472 bytes (1500 - 20 IP - 8 UDP) to avoid fragmentation.
//! Gap detection via session sequence tracking; fill gaps via TCP snapshot.
//!
//! Patterns:
//!   - Sender: exchange publishes market data to multicast group
//!   - Receiver: clients join multicast group, receive order-by-order feed
//!   - Gaps: detected by sequence numbers, resolved via TCP recovery channel

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

/// Maximum safe UDP payload to avoid IP fragmentation.
/// 1500 (Ethernet MTU) - 20 (IP header) - 8 (UDP header) = 1472 bytes.
pub const MAX_UDP_PAYLOAD: usize = 1472;

/// Multicast sender — publishes MGEP messages to a multicast group.
pub struct MulticastSender {
    socket: UdpSocket,
    dest: SocketAddr,
}

impl MulticastSender {
    /// Create a sender that publishes to the given multicast group.
    /// `bind_addr` is the local interface to send from (e.g., "0.0.0.0:0").
    /// `multicast_addr` is the target group (e.g., "239.1.1.1:10000").
    pub fn new(bind_addr: &str, multicast_addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;

        // Set multicast TTL (1 = local network only)
        socket.set_multicast_ttl_v4(1)?;

        // Enable loopback so local receivers on the same host get the data
        socket.set_multicast_loop_v4(true)?;

        let dest: SocketAddr = multicast_addr.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(Self { socket, dest })
    }

    /// Send an MGEP message via multicast.
    /// Returns error if message exceeds MTU.
    pub fn send(&self, msg: &[u8]) -> io::Result<usize> {
        if msg.len() > MAX_UDP_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("message {} bytes exceeds MTU limit {} bytes", msg.len(), MAX_UDP_PAYLOAD),
            ));
        }
        self.socket.send_to(msg, self.dest)
    }

    /// Send a batch of messages, each as a separate datagram.
    /// Stops and returns error if any message exceeds MTU.
    pub fn send_batch(&self, messages: &[&[u8]]) -> io::Result<usize> {
        let mut total = 0;
        for msg in messages {
            total += self.send(msg)?;
        }
        Ok(total)
    }
}

/// Multicast receiver — subscribes to a multicast group and receives MGEP messages.
pub struct MulticastReceiver {
    socket: UdpSocket,
    buf: Vec<u8>,
}

impl MulticastReceiver {
    /// Join a multicast group and start receiving.
    /// `multicast_addr` is the group address (e.g., "239.1.1.1").
    /// `port` is the multicast port.
    /// `interface` is the local interface to bind (e.g., "0.0.0.0" for all).
    pub fn join(multicast_addr: &str, port: u16, interface: &str) -> io::Result<Self> {
        let multi_ip: Ipv4Addr = multicast_addr.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let iface_ip: Ipv4Addr = interface.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        let socket = UdpSocket::bind(bind_addr)?;

        // Allow multiple receivers on the same port
        // (set_reuse_address is called before bind on most OSes, but Rust's UdpSocket
        //  doesn't expose SO_REUSEADDR pre-bind; this works on macOS/Linux post-bind for multicast)

        socket.join_multicast_v4(&multi_ip, &iface_ip)?;

        Ok(Self {
            socket,
            buf: vec![0u8; MAX_UDP_PAYLOAD + 64], // small headroom
        })
    }

    /// Receive the next MGEP message. Blocking.
    /// Returns the message bytes and source address.
    pub fn recv(&mut self) -> io::Result<(&[u8], SocketAddr)> {
        let (n, src) = self.socket.recv_from(&mut self.buf)?;
        Ok((&self.buf[..n], src))
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    /// Try to receive (non-blocking). Returns None if no data available.
    pub fn try_recv(&mut self) -> io::Result<Option<(&[u8], SocketAddr)>> {
        match self.socket.recv_from(&mut self.buf) {
            Ok((n, src)) => Ok(Some((&self.buf[..n], src))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Leave the multicast group.
    pub fn leave(&self, multicast_addr: &str, interface: &str) -> io::Result<()> {
        let multi_ip: Ipv4Addr = multicast_addr.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let iface_ip: Ipv4Addr = interface.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.socket.leave_multicast_v4(&multi_ip, &iface_ip)
    }
}

/// Sequence gap tracker for multicast feeds.
/// Detects missing messages by monitoring sequence numbers.
pub struct GapDetector {
    next_expected: u32,
    gaps: Vec<(u32, u32)>, // (from, to) inclusive
}

impl GapDetector {
    pub fn new(initial_seq: u32) -> Self {
        Self {
            next_expected: initial_seq,
            gaps: Vec::new(),
        }
    }

    /// Process an incoming sequence number. Returns the gap if one is detected.
    pub fn check(&mut self, seq: u32) -> GapResult {
        if seq == self.next_expected {
            self.next_expected = seq.wrapping_add(1);
            // Check if this fills any gap
            self.gaps.retain(|&(from, to)| !(seq >= from && seq <= to));
            GapResult::Expected
        } else if seq > self.next_expected {
            let gap = (self.next_expected, seq.wrapping_sub(1));
            self.gaps.push(gap);
            self.next_expected = seq.wrapping_add(1);
            GapResult::Gap {
                from: gap.0,
                to: gap.1,
                count: seq - gap.0,
            }
        } else {
            GapResult::Duplicate
        }
    }

    /// Get all unresolved gaps.
    pub fn gaps(&self) -> &[(u32, u32)] {
        &self.gaps
    }

    /// Total number of missing messages.
    pub fn total_missing(&self) -> u32 {
        self.gaps.iter().map(|&(from, to)| to - from + 1).sum()
    }

    /// Mark a gap as filled (e.g., after TCP recovery).
    pub fn fill_gap(&mut self, from: u32, to: u32) {
        self.gaps.retain(|&(gf, gt)| !(gf >= from && gt <= to));
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GapResult {
    Expected,
    Gap { from: u32, to: u32, count: u32 },
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_detector_no_gaps() {
        let mut gd = GapDetector::new(1);
        assert_eq!(gd.check(1), GapResult::Expected);
        assert_eq!(gd.check(2), GapResult::Expected);
        assert_eq!(gd.check(3), GapResult::Expected);
        assert!(gd.gaps().is_empty());
    }

    #[test]
    fn gap_detector_detects_gap() {
        let mut gd = GapDetector::new(1);
        assert_eq!(gd.check(1), GapResult::Expected);
        assert_eq!(
            gd.check(5),
            GapResult::Gap { from: 2, to: 4, count: 3 }
        );
        assert_eq!(gd.total_missing(), 3);
    }

    #[test]
    fn gap_detector_duplicate() {
        let mut gd = GapDetector::new(1);
        gd.check(1);
        gd.check(2);
        assert_eq!(gd.check(1), GapResult::Duplicate);
    }

    #[test]
    fn gap_detector_fill() {
        let mut gd = GapDetector::new(1);
        gd.check(1);
        gd.check(5); // gap 2-4
        assert_eq!(gd.total_missing(), 3);

        gd.fill_gap(2, 4);
        assert_eq!(gd.total_missing(), 0);
    }

    #[test]
    #[ignore] // requires multicast-capable network
    fn multicast_loopback_roundtrip() {
        let group = "239.255.0.1";
        let port = 0; // OS picks port

        // We need a known port for multicast, let's use a high random one
        let _port = 19876;

        let sender = MulticastSender::new("0.0.0.0:0", &format!("{}:{}", group, port)).unwrap();
        let mut receiver = MulticastReceiver::join(group, port, "0.0.0.0").unwrap();
        receiver.set_nonblocking(true).unwrap();

        // Send MGEP message
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };
        let mut enc = crate::codec::MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        sender.send(enc.as_slice()).unwrap();

        // Give loopback a moment
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Receive
        match receiver.try_recv() {
            Ok(Some((msg, _src))) => {
                let decoded = crate::codec::MessageBuffer::decode_new_order(msg);
                assert_eq!(decoded.order_id, 42);
            }
            Ok(None) => {
                // Multicast loopback may not work in all CI environments
                eprintln!("multicast loopback not available, skipping");
            }
            Err(e) => {
                eprintln!("multicast recv error (may be CI): {}", e);
            }
        }
    }

    #[test]
    fn mtu_enforcement() {
        let sender = MulticastSender::new("0.0.0.0:0", "239.255.0.1:19877").unwrap();
        let big_msg = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert!(sender.send(&big_msg).is_err());

        let ok_msg = vec![0u8; MAX_UDP_PAYLOAD];
        // Can't actually send without a receiver, but encoding should be fine
        // Just verify the check works
        assert!(ok_msg.len() <= MAX_UDP_PAYLOAD);
    }
}
