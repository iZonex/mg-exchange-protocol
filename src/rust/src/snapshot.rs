//! Market-data snapshot & gap-fill.
//!
//! Solves the "multicast gap larger than the retransmit journal" problem. When a
//! client detects a sequence gap it cannot recover from the replay journal, it
//! asks the server for a full book snapshot over the TCP recovery channel.
//!
//! Wire protocol (message types are defined in `market_data` schema, 0x30..0x34):
//!
//!   client → server:  BookSnapshotRequest
//!   server → client:  BookSnapshotBegin
//!                     BookSnapshotLevel × level_count
//!                     BookSnapshotEnd        (CRC32 over level payloads)
//!   on refusal:       BookSnapshotReject
//!
//! Client stitching:
//!   1. On gap detected, buffer all real-time updates, send a snapshot request.
//!   2. While the snapshot streams in, continue buffering real-time updates.
//!   3. On `BookSnapshotEnd`, validate CRC + level_count. If good, apply the
//!      snapshot, then drain the buffer discarding anything with
//!      `seq <= last_applied_seq`, applying the rest in order.
//!   4. Mark the gap filled in `GapDetector`.
//!
//! Slow-consumer protection: the server tracks per-subscriber send backlog. If a
//! subscriber cannot keep up, the server emits `SequenceReset` and disconnects
//! rather than let the client silently miss data.

use crate::codec::MessageBuffer;
use crate::frame::crc32;
use crate::header::FullHeader;
#[cfg(test)]
use crate::header::CORE_BLOCK_OFFSET;
use crate::messages::{
    BookSnapshotBeginCore, BookSnapshotEndCore, BookSnapshotLevelCore,
    BookSnapshotRejectCore, SnapshotRejectReason,
};
use crate::orderbook::OrderBook;
use crate::types::{Decimal, Side};

/// Errors produced by the snapshot machinery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Snapshot payload exceeded the configured hard cap.
    TooManyLevels { requested: u32, limit: u32 },
    /// Client received a Level for a snapshot it did not start.
    UnknownSnapshotId(u64),
    /// Level arrived out of order or skipped an index.
    LevelOutOfOrder { expected: u32, got: u32 },
    /// CRC mismatch on End — snapshot is corrupt, caller should retry.
    ChecksumMismatch { expected: u32, got: u32 },
    /// `Begin.level_count` did not match `End.level_count`.
    LevelCountMismatch { begin: u32, end: u32 },
    /// `Begin.last_applied_seq` did not match `End.final_seq`.
    SeqMismatch { begin: u64, end: u64 },
    /// End arrived before the full level stream.
    TruncatedStream { expected: u32, received: u32 },
    /// Encoded Side byte was not Buy/Sell.
    BadSide(u8),
}

// ─── Server: Snapshot Generator ───────────────────────────────

/// Server-side snapshot generator.
///
/// Walks an `OrderBook` and emits a sequence of encoded MGEP messages
/// (`BookSnapshotBegin`, `BookSnapshotLevel × N`, `BookSnapshotEnd`) ready to
/// be written to the recovery channel.
pub struct SnapshotGenerator {
    /// Hard cap on levels per side. Prevents a malicious request for a deep
    /// book from OOMing the server or starving other recovery requests.
    pub max_levels_hard_cap: u32,
}

impl Default for SnapshotGenerator {
    fn default() -> Self {
        Self { max_levels_hard_cap: 10_000 }
    }
}

/// Output of `SnapshotGenerator::generate`.
#[derive(Debug)]
pub struct SnapshotStream {
    /// Ordered: `[begin, level_0, level_1, ..., level_{n-1}, end]`.
    pub messages: Vec<Vec<u8>>,
    pub snapshot_id: u64,
    pub level_count: u32,
    pub checksum: u32,
}

impl SnapshotGenerator {
    pub fn new(max_levels_hard_cap: u32) -> Self {
        Self { max_levels_hard_cap }
    }

    /// Build an encoded snapshot stream for the given order book.
    ///
    /// * `sender_comp_id`  — server comp id for the outgoing messages.
    /// * `start_seq`       — first seq number to use. Every emitted message
    ///                       gets `start_seq + i`. Caller is responsible for
    ///                       advancing its own session counter afterwards.
    /// * `request_id`      — echoed from `BookSnapshotRequest` (0 for
    ///                       unsolicited broadcast snapshots).
    /// * `last_applied_seq`— market-data seq this snapshot is consistent with.
    ///                       Clients discard all updates with seq ≤ this.
    /// * `snapshot_id`     — unique identifier (typically monotonic counter).
    /// * `max_levels`      — per-side cap; 0 means "full depth". Clamped to
    ///                       `self.max_levels_hard_cap`.
    pub fn generate(
        &self,
        book: &OrderBook,
        sender_comp_id: u32,
        start_seq: u64,
        request_id: u64,
        last_applied_seq: u64,
        snapshot_id: u64,
        max_levels: u32,
    ) -> Result<SnapshotStream, SnapshotError> {
        let effective_cap = if max_levels == 0 {
            self.max_levels_hard_cap
        } else if max_levels > self.max_levels_hard_cap {
            return Err(SnapshotError::TooManyLevels {
                requested: max_levels,
                limit: self.max_levels_hard_cap,
            });
        } else {
            max_levels
        };

        let levels: Vec<(Side, Decimal, Decimal, u32)> =
            book.iter_snapshot_levels(effective_cap).collect();
        let level_count = levels.len() as u32;

        let mut messages: Vec<Vec<u8>> = Vec::with_capacity(levels.len() + 2);

        // ── Begin ─────────────────────────────────────────────
        let begin = BookSnapshotBeginCore {
            request_id,
            instrument_id: book.instrument_id,
            _pad: [0; 4],
            last_applied_seq,
            level_count,
            _pad2: [0; 4],
            snapshot_id,
        };
        messages.push(encode_one(sender_comp_id, start_seq, &begin));

        // ── Levels ────────────────────────────────────────────
        // CRC is computed over the concatenated Level core-block payloads,
        // in order. This lets the client verify no level was dropped or
        // reordered even if message-level transport is reliable.
        let mut crc_buf: Vec<u8> = Vec::with_capacity(levels.len() * BookSnapshotLevelCore::SIZE);
        for (idx, (side, price, qty, order_count)) in levels.iter().enumerate() {
            let level = BookSnapshotLevelCore {
                snapshot_id,
                level_index: idx as u32,
                side: *side as u8,
                _pad: [0; 3],
                price: *price,
                quantity: *qty,
                order_count: *order_count,
                _pad2: [0; 4],
            };
            crc_buf.extend_from_slice(level.as_bytes());
            let seq = start_seq + 1 + idx as u64;
            messages.push(encode_one(sender_comp_id, seq, &level));
        }

        let checksum = crc32(&crc_buf);

        // ── End ───────────────────────────────────────────────
        let end = BookSnapshotEndCore {
            snapshot_id,
            final_seq: last_applied_seq,
            checksum: checksum as u64,
            level_count,
            _pad: [0; 4],
        };
        let end_seq = start_seq + 1 + level_count as u64;
        messages.push(encode_one(sender_comp_id, end_seq, &end));

        Ok(SnapshotStream {
            messages,
            snapshot_id,
            level_count,
            checksum,
        })
    }

    /// Build a `BookSnapshotReject` in response to an invalid request.
    pub fn reject(
        &self,
        sender_comp_id: u32,
        seq: u64,
        request_id: u64,
        reason: SnapshotRejectReason,
    ) -> Vec<u8> {
        let reject = BookSnapshotRejectCore {
            request_id,
            reason_code: reason as u8,
            _pad: [0; 7],
        };
        encode_one(sender_comp_id, seq, &reject)
    }
}

fn encode_one<T: crate::codec::CoreBlock>(sender_comp_id: u32, seq: u64, core: &T) -> Vec<u8> {
    let size = FullHeader::SIZE + T::SIZE;
    let mut buf = MessageBuffer::with_capacity(size);
    buf.encode(sender_comp_id, seq, core, None);
    buf.as_slice().to_vec()
}

// ─── Client: Snapshot Assembler ──────────────────────────────

/// Client-side state machine that consumes snapshot messages and, on success,
/// produces a fully-validated book view.
///
/// Typical use:
/// ```ignore
/// let mut asm = SnapshotAssembler::new();
/// asm.on_begin(begin_core)?;
/// for level in level_cores { asm.on_level(level)?; }
/// let book = asm.on_end(end_core)?;
/// ```
pub struct SnapshotAssembler {
    state: AssemblerState,
}

#[derive(Default)]
struct AssemblerState {
    snapshot_id: Option<u64>,
    instrument_id: u32,
    last_applied_seq: u64,
    expected_level_count: u32,
    next_level_index: u32,
    levels: Vec<SnapshotLevelView>,
    crc_buf: Vec<u8>,
}

/// A single price-level view inside a completed snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLevelView {
    pub side: Side,
    pub price: Decimal,
    pub quantity: Decimal,
    pub order_count: u32,
}

/// Fully-validated snapshot — what `on_end` returns on success.
#[derive(Clone, Debug)]
pub struct SnapshotView {
    pub snapshot_id: u64,
    pub instrument_id: u32,
    /// Drop all real-time updates whose seq is ≤ this value; they are
    /// already reflected in `levels`.
    pub last_applied_seq: u64,
    pub levels: Vec<SnapshotLevelView>,
}

impl SnapshotAssembler {
    pub fn new() -> Self {
        Self { state: AssemblerState::default() }
    }

    /// Accept the `BookSnapshotBegin` core. Resets any in-progress assembly.
    pub fn on_begin(&mut self, begin: &BookSnapshotBeginCore) -> Result<(), SnapshotError> {
        self.state = AssemblerState {
            snapshot_id: Some(begin.snapshot_id),
            instrument_id: begin.instrument_id,
            last_applied_seq: begin.last_applied_seq,
            expected_level_count: begin.level_count,
            next_level_index: 0,
            levels: Vec::with_capacity(begin.level_count as usize),
            crc_buf: Vec::with_capacity(
                begin.level_count as usize * BookSnapshotLevelCore::SIZE,
            ),
        };
        Ok(())
    }

    /// Accept a `BookSnapshotLevel` core. Levels must arrive in strict
    /// `level_index` order (0, 1, 2, ...).
    pub fn on_level(&mut self, level: &BookSnapshotLevelCore) -> Result<(), SnapshotError> {
        match self.state.snapshot_id {
            Some(id) if id == level.snapshot_id => {}
            _ => return Err(SnapshotError::UnknownSnapshotId(level.snapshot_id)),
        }

        if level.level_index != self.state.next_level_index {
            return Err(SnapshotError::LevelOutOfOrder {
                expected: self.state.next_level_index,
                got: level.level_index,
            });
        }

        let side = Side::from_u8(level.side).ok_or(SnapshotError::BadSide(level.side))?;
        self.state.levels.push(SnapshotLevelView {
            side,
            price: level.price,
            quantity: level.quantity,
            order_count: level.order_count,
        });
        self.state.crc_buf.extend_from_slice(level.as_bytes());
        self.state.next_level_index += 1;
        Ok(())
    }

    /// Accept the `BookSnapshotEnd` core. On success, consumes the assembler
    /// state and returns the validated `SnapshotView`.
    pub fn on_end(mut self, end: &BookSnapshotEndCore) -> Result<SnapshotView, SnapshotError> {
        match self.state.snapshot_id {
            Some(id) if id == end.snapshot_id => {}
            _ => return Err(SnapshotError::UnknownSnapshotId(end.snapshot_id)),
        }

        if end.level_count != self.state.expected_level_count {
            return Err(SnapshotError::LevelCountMismatch {
                begin: self.state.expected_level_count,
                end: end.level_count,
            });
        }

        if self.state.next_level_index != self.state.expected_level_count {
            return Err(SnapshotError::TruncatedStream {
                expected: self.state.expected_level_count,
                received: self.state.next_level_index,
            });
        }

        if end.final_seq != self.state.last_applied_seq {
            return Err(SnapshotError::SeqMismatch {
                begin: self.state.last_applied_seq,
                end: end.final_seq,
            });
        }

        let computed = crc32(&self.state.crc_buf);
        let declared = end.checksum as u32;
        if computed != declared {
            return Err(SnapshotError::ChecksumMismatch { expected: computed, got: declared });
        }

        Ok(SnapshotView {
            snapshot_id: end.snapshot_id,
            instrument_id: self.state.instrument_id,
            last_applied_seq: self.state.last_applied_seq,
            levels: std::mem::take(&mut self.state.levels),
        })
    }
}

impl Default for SnapshotAssembler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Client: Recovery Coordinator ────────────────────────────

/// Coordinates the client-side recovery flow:
///
/// * detects gaps via sequence numbers
/// * emits a `BookSnapshotRequest` when a gap is detected
/// * buffers real-time market-data updates while a snapshot is in flight
/// * applies the snapshot on completion, then drains the buffer discarding
///   updates already reflected in the snapshot
///
/// This is a **single-instrument** coordinator; a client running multiple
/// subscriptions owns one coordinator per instrument_id.
///
/// The coordinator is transport-agnostic: callers feed it incoming
/// seq+payload pairs and ask it what to do next. Keeping I/O out keeps this
/// trivially testable.
pub struct RecoveryCoordinator {
    instrument_id: u32,
    /// Next market-data seq expected on the real-time feed.
    next_expected_seq: u64,
    /// In-progress snapshot assembly, if any.
    pending: Option<PendingSnapshot>,
    /// Max messages to buffer while waiting for snapshot. Beyond this,
    /// enter `Stalled` — caller must tear down & resubscribe.
    pub max_buffered: usize,
    /// Monotonic ID allocator for outgoing snapshot requests.
    next_request_id: u64,
    stalled: bool,
}

struct PendingSnapshot {
    request_id: u64,
    /// Real-time updates buffered while we wait for the snapshot.
    /// Tuples: (seq, owned-message-bytes).
    buffer: Vec<(u64, Vec<u8>)>,
    assembler: SnapshotAssembler,
    /// True once `Begin` arrived.
    begun: bool,
}

/// What the coordinator asks the caller to do after a `feed_realtime` call.
#[derive(Debug)]
pub enum RecoveryAction {
    /// Apply this real-time message to the book as-is.
    Apply,
    /// Drop this message (it's a duplicate of data already in the snapshot).
    Drop,
    /// Buffer this message; we're mid-recovery.
    Buffer,
    /// Gap detected. Send this snapshot request to the server.
    RequestSnapshot(Vec<u8>),
    /// Buffer overflowed. Caller must reconnect/resubscribe.
    Stall,
}

/// Returned by `on_snapshot_end` after a successful snapshot application.
/// Contains the book view plus any buffered updates that should now be
/// applied in order (seq > last_applied_seq).
#[derive(Debug)]
pub struct RecoveryCompletion {
    pub view: SnapshotView,
    /// Messages to apply in order after the view. Entries with
    /// `seq ≤ view.last_applied_seq` have already been dropped.
    pub replay: Vec<(u64, Vec<u8>)>,
}

impl RecoveryCoordinator {
    pub fn new(instrument_id: u32, initial_seq: u64) -> Self {
        Self {
            instrument_id,
            next_expected_seq: initial_seq,
            pending: None,
            max_buffered: 100_000,
            next_request_id: 1,
            stalled: false,
        }
    }

    /// Build a snapshot-request message (encoded, ready for the TCP recovery
    /// channel).
    fn build_request(&mut self, sender_comp_id: u32, session_seq: u64) -> Vec<u8> {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let req = crate::messages::BookSnapshotRequestCore {
            request_id,
            instrument_id: self.instrument_id,
            max_levels: 0,
        };
        let mut buf = MessageBuffer::with_capacity(FullHeader::SIZE + crate::messages::BookSnapshotRequestCore::SIZE);
        buf.encode(sender_comp_id, session_seq, &req, None);

        // Stash the request_id on the pending-snapshot record so we can
        // match the server's `Begin` back to it.
        self.pending = Some(PendingSnapshot {
            request_id,
            buffer: Vec::new(),
            assembler: SnapshotAssembler::new(),
            begun: false,
        });

        buf.as_slice().to_vec()
    }

    /// Feed an incoming real-time market-data message (already seq-decoded).
    /// `payload` is the full message bytes; coordinator will hand it back
    /// later for replay if it needs to be buffered.
    pub fn feed_realtime(
        &mut self,
        seq: u64,
        payload: &[u8],
        sender_comp_id: u32,
        session_seq: u64,
    ) -> RecoveryAction {
        if self.stalled {
            return RecoveryAction::Stall;
        }

        // Already recovering? Just buffer.
        if self.pending.is_some() {
            if self.push_buffer(seq, payload) {
                return RecoveryAction::Buffer;
            }
            self.stalled = true;
            return RecoveryAction::Stall;
        }

        // Normal path.
        if seq == self.next_expected_seq {
            self.next_expected_seq = seq + 1;
            RecoveryAction::Apply
        } else if seq < self.next_expected_seq {
            RecoveryAction::Drop // duplicate
        } else {
            // Gap. Buffer this message, request a snapshot.
            let request = self.build_request(sender_comp_id, session_seq);
            let pending = self.pending.as_mut().unwrap();
            pending.buffer.push((seq, payload.to_vec()));
            RecoveryAction::RequestSnapshot(request)
        }
    }

    fn push_buffer(&mut self, seq: u64, payload: &[u8]) -> bool {
        let pending = self.pending.as_mut().expect("called during recovery");
        if pending.buffer.len() >= self.max_buffered {
            return false;
        }
        pending.buffer.push((seq, payload.to_vec()));
        true
    }

    /// Accept `BookSnapshotBegin` from the recovery channel.
    pub fn on_snapshot_begin(
        &mut self,
        begin: &BookSnapshotBeginCore,
    ) -> Result<(), SnapshotError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(SnapshotError::UnknownSnapshotId(begin.snapshot_id))?;

        if begin.request_id != pending.request_id {
            return Err(SnapshotError::UnknownSnapshotId(begin.snapshot_id));
        }
        pending.assembler.on_begin(begin)?;
        pending.begun = true;
        Ok(())
    }

    /// Accept a `BookSnapshotLevel` from the recovery channel.
    pub fn on_snapshot_level(
        &mut self,
        level: &BookSnapshotLevelCore,
    ) -> Result<(), SnapshotError> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(SnapshotError::UnknownSnapshotId(level.snapshot_id))?;
        if !pending.begun {
            return Err(SnapshotError::UnknownSnapshotId(level.snapshot_id));
        }
        pending.assembler.on_level(level)
    }

    /// Accept `BookSnapshotEnd`. On success the snapshot is applied and any
    /// buffered real-time updates with `seq > view.last_applied_seq` are
    /// returned for replay (in order). The coordinator is ready to resume
    /// normal operation on the returned `next_expected_seq`.
    pub fn on_snapshot_end(
        &mut self,
        end: &BookSnapshotEndCore,
    ) -> Result<RecoveryCompletion, SnapshotError> {
        let pending = self
            .pending
            .take()
            .ok_or(SnapshotError::UnknownSnapshotId(end.snapshot_id))?;

        let view = pending.assembler.on_end(end)?;

        let mut replay = pending.buffer;
        replay.sort_by_key(|(seq, _)| *seq);
        replay.retain(|(seq, _)| *seq > view.last_applied_seq);
        // Dedup (buffer may contain duplicate seqs if sender retransmitted).
        replay.dedup_by_key(|(seq, _)| *seq);

        self.next_expected_seq = if let Some((last_seq, _)) = replay.last() {
            last_seq + 1
        } else {
            view.last_applied_seq + 1
        };

        Ok(RecoveryCompletion { view, replay })
    }

    /// Current expected next market-data seq.
    pub fn next_expected_seq(&self) -> u64 {
        self.next_expected_seq
    }

    /// True while the coordinator is waiting for a snapshot to complete.
    pub fn recovering(&self) -> bool {
        self.pending.is_some()
    }

    pub fn stalled(&self) -> bool {
        self.stalled
    }
}

// ─── Slow-Consumer Protection ────────────────────────────────

/// Tracks per-subscriber send backlog on the server. When a subscriber falls
/// too far behind, the server disconnects rather than let them silently miss
/// data. This is the dual of the client-side `GapDetector`.
pub struct SlowConsumerGuard {
    pub max_queued_messages: usize,
    pub max_queued_bytes: usize,
}

impl SlowConsumerGuard {
    pub fn new(max_queued_messages: usize, max_queued_bytes: usize) -> Self {
        Self { max_queued_messages, max_queued_bytes }
    }

    /// Returns `true` if the backlog is within limits; `false` means the
    /// caller should disconnect the subscriber.
    #[inline]
    pub fn check(&self, queued_messages: usize, queued_bytes: usize) -> bool {
        queued_messages <= self.max_queued_messages
            && queued_bytes <= self.max_queued_bytes
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::NewOrderSingleCore;
    use crate::types::{Decimal, OrderType, TimeInForce};

    fn populate_book(book: &mut OrderBook) {
        // 3 bids at 100/99/98, 2 asks at 101/102
        let orders = [
            (1u64, Side::Buy, 100.0, 5.0),
            (2, Side::Buy, 100.0, 3.0), // second order at 100 → level qty 8
            (3, Side::Buy, 99.0, 10.0),
            (4, Side::Buy, 98.0, 1.0),
            (5, Side::Sell, 101.0, 4.0),
            (6, Side::Sell, 102.0, 7.0),
        ];
        for (id, side, price, qty) in orders {
            let order = NewOrderSingleCore {
                order_id: id,
                client_order_id: 0,
                instrument_id: book.instrument_id,
                side: side as u8,
                order_type: OrderType::Limit as u8,
                time_in_force: TimeInForce::Day as u16,
                price: Decimal::from_f64(price),
                quantity: Decimal::from_f64(qty),
                stop_price: Decimal::NULL,
            };
            let fills = book.submit(&order);
            // These prices don't cross, so no fills expected.
            assert!(fills.is_empty(), "unexpected fill at seed stage");
        }
    }

    #[test]
    fn roundtrip_snapshot_applies_cleanly() {
        let mut book = OrderBook::new(42);
        populate_book(&mut book);

        let sg = SnapshotGenerator::default();
        let stream = sg
            .generate(&book, 1, 1000, 777, 5000, 0xdead_beef, 0)
            .expect("generate");

        // Decode each message and feed it into the assembler.
        let mut asm = SnapshotAssembler::new();

        for (i, msg) in stream.messages.iter().enumerate() {
            let hdr = MessageBuffer::decode_full_header(msg);
            let body = &msg[CORE_BLOCK_OFFSET..];

            if i == 0 {
                assert_eq!(hdr.message.message_type, BookSnapshotBeginCore::MESSAGE_TYPE);
                asm.on_begin(BookSnapshotBeginCore::from_bytes(body)).unwrap();
            } else if i == stream.messages.len() - 1 {
                assert_eq!(hdr.message.message_type, BookSnapshotEndCore::MESSAGE_TYPE);
                let view = asm.on_end(BookSnapshotEndCore::from_bytes(body)).unwrap();
                assert_eq!(view.snapshot_id, 0xdead_beef);
                assert_eq!(view.last_applied_seq, 5000);
                assert_eq!(view.instrument_id, 42);

                // Bids first (high→low): 100, 99, 98. Then asks (low→high): 101, 102.
                assert_eq!(view.levels.len(), 5);
                assert_eq!(view.levels[0].side, Side::Buy);
                assert_eq!(view.levels[0].price, Decimal::from_f64(100.0));
                // qty at 100 is aggregate of two orders (5 + 3 = 8)
                assert_eq!(view.levels[0].quantity, Decimal::from_f64(8.0));
                assert_eq!(view.levels[0].order_count, 2);

                assert_eq!(view.levels[3].side, Side::Sell);
                assert_eq!(view.levels[3].price, Decimal::from_f64(101.0));

                // Asm is consumed by on_end — break out of iteration.
                return;
            } else {
                assert_eq!(hdr.message.message_type, BookSnapshotLevelCore::MESSAGE_TYPE);
                asm.on_level(BookSnapshotLevelCore::from_bytes(body)).unwrap();
            }
        }
        unreachable!("on_end should have returned");
    }

    #[test]
    fn corrupted_level_fails_crc() {
        let mut book = OrderBook::new(1);
        populate_book(&mut book);
        let sg = SnapshotGenerator::default();
        let stream = sg.generate(&book, 1, 100, 1, 200, 99, 0).unwrap();

        let mut asm = SnapshotAssembler::new();
        for (i, msg) in stream.messages.iter().enumerate() {
            let body = &msg[CORE_BLOCK_OFFSET..];
            if i == 0 {
                asm.on_begin(BookSnapshotBeginCore::from_bytes(body)).unwrap();
            } else if i == stream.messages.len() - 1 {
                // Tamper the End.checksum.
                let mut tampered = BookSnapshotEndCore::from_bytes(body).clone();
                tampered.checksum ^= 0xFFFF_FFFF;
                let err = asm.on_end(&tampered).unwrap_err();
                assert!(matches!(err, SnapshotError::ChecksumMismatch { .. }));
                return;
            } else {
                asm.on_level(BookSnapshotLevelCore::from_bytes(body)).unwrap();
            }
        }
        unreachable!();
    }

    #[test]
    fn out_of_order_level_rejected() {
        let mut book = OrderBook::new(1);
        populate_book(&mut book);
        let sg = SnapshotGenerator::default();
        let stream = sg.generate(&book, 1, 100, 1, 200, 42, 0).unwrap();

        let mut asm = SnapshotAssembler::new();
        let begin_body = &stream.messages[0][CORE_BLOCK_OFFSET..];
        asm.on_begin(BookSnapshotBeginCore::from_bytes(begin_body)).unwrap();

        // Skip index 0, try to feed index 1 first.
        let level1 = &stream.messages[2][CORE_BLOCK_OFFSET..];
        let err = asm
            .on_level(BookSnapshotLevelCore::from_bytes(level1))
            .unwrap_err();
        assert!(matches!(err, SnapshotError::LevelOutOfOrder { expected: 0, got: 1 }));
    }

    #[test]
    fn level_count_mismatch_rejected() {
        let mut book = OrderBook::new(1);
        populate_book(&mut book);
        let sg = SnapshotGenerator::default();
        let stream = sg.generate(&book, 1, 100, 1, 200, 11, 0).unwrap();

        let mut asm = SnapshotAssembler::new();
        let begin_body = &stream.messages[0][CORE_BLOCK_OFFSET..];
        asm.on_begin(BookSnapshotBeginCore::from_bytes(begin_body)).unwrap();

        // Only feed the first level, then send End.
        let level0 = &stream.messages[1][CORE_BLOCK_OFFSET..];
        asm.on_level(BookSnapshotLevelCore::from_bytes(level0)).unwrap();

        let end_body = &stream.messages.last().unwrap()[CORE_BLOCK_OFFSET..];
        let err = asm.on_end(BookSnapshotEndCore::from_bytes(end_body)).unwrap_err();
        assert!(matches!(err, SnapshotError::TruncatedStream { .. }));
    }

    #[test]
    fn max_levels_over_hard_cap_rejected() {
        let book = OrderBook::new(1);
        let sg = SnapshotGenerator::new(10);
        let err = sg.generate(&book, 1, 0, 0, 0, 1, 11).unwrap_err();
        assert!(matches!(err, SnapshotError::TooManyLevels { requested: 11, limit: 10 }));
    }

    #[test]
    fn reject_message_encodes() {
        let sg = SnapshotGenerator::default();
        let msg = sg.reject(1, 42, 99, SnapshotRejectReason::UnknownInstrument);
        let body = &msg[CORE_BLOCK_OFFSET..];
        let reject = BookSnapshotRejectCore::from_bytes(body);
        assert_eq!(reject.request_id, 99);
        assert_eq!(
            SnapshotRejectReason::from_u8(reject.reason_code),
            Some(SnapshotRejectReason::UnknownInstrument)
        );
    }

    #[test]
    fn empty_book_snapshot() {
        let book = OrderBook::new(7);
        let sg = SnapshotGenerator::default();
        let stream = sg.generate(&book, 1, 0, 0, 0, 1, 0).unwrap();
        assert_eq!(stream.level_count, 0);
        assert_eq!(stream.messages.len(), 2); // Begin + End only

        let mut asm = SnapshotAssembler::new();
        let begin = BookSnapshotBeginCore::from_bytes(&stream.messages[0][CORE_BLOCK_OFFSET..]);
        asm.on_begin(begin).unwrap();
        let end = BookSnapshotEndCore::from_bytes(&stream.messages[1][CORE_BLOCK_OFFSET..]);
        let view = asm.on_end(end).unwrap();
        assert!(view.levels.is_empty());
    }

    #[test]
    fn slow_consumer_guard_thresholds() {
        let g = SlowConsumerGuard::new(1000, 1_000_000);
        assert!(g.check(500, 500_000));
        assert!(g.check(1000, 1_000_000));
        assert!(!g.check(1001, 500_000));
        assert!(!g.check(500, 1_000_001));
    }

    // ─── End-to-end recovery: packet loss simulation ──────────

    /// Real-time market-data feed simulation. Drops every N-th message to
    /// force the client into recovery; client asks for snapshot; client
    /// then replays buffered updates and stays consistent with server.
    #[test]
    fn recovery_coordinator_packet_loss_e2e() {
        // Server-side book with some resting orders.
        let mut server_book = OrderBook::new(42);
        populate_book(&mut server_book);

        // Client-side coordinator starts at seq 1 (first real-time msg).
        let mut coord = RecoveryCoordinator::new(42, 1);

        // Simulate 10 real-time updates (seq 1..=10) — any bytes work here,
        // coordinator treats payloads as opaque blobs.
        let realtime: Vec<(u64, Vec<u8>)> =
            (1u64..=10).map(|seq| (seq, vec![seq as u8; 16])).collect();

        // Drop seq=4 and seq=5 to force a gap.
        let mut applied: Vec<u64> = Vec::new();
        let mut snapshot_req_sent = false;

        for (seq, payload) in &realtime {
            if *seq == 4 || *seq == 5 {
                continue; // dropped on the wire
            }
            let action = coord.feed_realtime(*seq, payload, 99, 1000 + *seq);
            match action {
                RecoveryAction::Apply => applied.push(*seq),
                RecoveryAction::Drop => {}
                RecoveryAction::Buffer => {}
                RecoveryAction::RequestSnapshot(req_bytes) => {
                    // Verify request header.
                    let hdr = MessageBuffer::decode_full_header(&req_bytes);
                    assert_eq!(
                        hdr.message.message_type,
                        crate::messages::BookSnapshotRequestCore::MESSAGE_TYPE
                    );
                    snapshot_req_sent = true;
                }
                RecoveryAction::Stall => panic!("unexpected stall"),
            }
        }

        assert!(snapshot_req_sent, "client must request a snapshot on gap");
        assert_eq!(applied, vec![1, 2, 3], "only pre-gap updates applied");
        assert!(coord.recovering());

        // Server generates snapshot consistent with seq=5 (having seen 1..=5).
        // NOTE: in a real system the server applies 1..=5 to its book first;
        //       here we just use the pre-populated book and pretend.
        let sg = SnapshotGenerator::default();
        let stream = sg.generate(&server_book, 1, 2000, 1, 5, 0xabc, 0).unwrap();

        // Drive the coordinator through the snapshot messages.
        for (i, msg) in stream.messages.iter().enumerate() {
            let body = &msg[CORE_BLOCK_OFFSET..];
            if i == 0 {
                coord.on_snapshot_begin(BookSnapshotBeginCore::from_bytes(body)).unwrap();
            } else if i == stream.messages.len() - 1 {
                let completion = coord
                    .on_snapshot_end(BookSnapshotEndCore::from_bytes(body))
                    .unwrap();

                // After recovery: replay should contain seq 6..=10 in order.
                // Seq 1..=5 are absorbed by the snapshot (last_applied_seq=5).
                let replay_seqs: Vec<u64> =
                    completion.replay.iter().map(|(s, _)| *s).collect();
                assert_eq!(replay_seqs, vec![6, 7, 8, 9, 10]);

                // Snapshot view itself.
                assert_eq!(completion.view.last_applied_seq, 5);
                assert_eq!(completion.view.instrument_id, 42);
                assert!(!completion.view.levels.is_empty());

                // Coordinator's next expected seq advances past the replay.
                assert_eq!(coord.next_expected_seq(), 11);
                assert!(!coord.recovering());
                return;
            } else {
                coord.on_snapshot_level(BookSnapshotLevelCore::from_bytes(body)).unwrap();
            }
        }
        unreachable!();
    }

    #[test]
    fn coordinator_drops_duplicates() {
        let mut coord = RecoveryCoordinator::new(1, 5);
        // Duplicate of seq=3 (already below next_expected)
        let action = coord.feed_realtime(3, &[0; 8], 1, 100);
        assert!(matches!(action, RecoveryAction::Drop));
    }

    #[test]
    fn coordinator_stalls_on_buffer_overflow() {
        let mut coord = RecoveryCoordinator::new(1, 1);
        coord.max_buffered = 3;

        // seq=1 applies normally; seq=2 is skipped → gap at 3.
        let _ = coord.feed_realtime(1, &[0; 8], 1, 100);
        // Trigger gap at seq=3 (missing 2).
        let _ = coord.feed_realtime(3, &[0; 8], 1, 101);
        assert!(coord.recovering());

        // Fill the buffer to the cap.
        for seq in 4..=6 {
            let _ = coord.feed_realtime(seq, &[0; 8], 1, 100 + seq);
        }
        // Next one must push past the cap → Stall.
        let action = coord.feed_realtime(7, &[0; 8], 1, 107);
        assert!(matches!(action, RecoveryAction::Stall));
        assert!(coord.stalled());
    }

    #[test]
    fn coordinator_rejects_mismatched_request_id_on_begin() {
        let mut coord = RecoveryCoordinator::new(1, 1);
        // Trigger recovery — this allocates request_id=1.
        let _ = coord.feed_realtime(5, &[0; 8], 1, 100);

        // Server replies with wrong request_id in Begin.
        let wrong_begin = BookSnapshotBeginCore {
            request_id: 999,
            instrument_id: 1,
            _pad: [0; 4],
            last_applied_seq: 4,
            level_count: 0,
            _pad2: [0; 4],
            snapshot_id: 42,
        };
        let err = coord.on_snapshot_begin(&wrong_begin).unwrap_err();
        assert!(matches!(err, SnapshotError::UnknownSnapshotId(42)));
    }
}
