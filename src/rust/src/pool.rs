//! Buffer Pool — zero-allocation reusable message buffers.
//!
//! Pre-allocates a fixed number of buffers at startup. Encode/decode
//! borrows a buffer from the pool, uses it, returns it. No malloc on hot path.
//!
//! Thread-safe: uses a lock-free stack (Treiber stack with AtomicPtr).
//! Single-threaded: use `LocalPool` for even lower overhead.

use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::ptr;

/// A pooled buffer — returned to pool on drop.
pub struct PooledBuffer {
    data: Vec<u8>,
    len: usize,
    pool: *const BufferPool, // null if detached
}

impl PooledBuffer {
    /// Written portion of the buffer.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Mutable access to the full buffer for encoding.
    #[inline(always)]
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Set the length of valid data (after encoding).
    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.data.len());
        self.len = len;
    }

    /// Buffer capacity.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Reset for reuse.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Detach from pool — caller owns this buffer permanently.
    pub fn detach(mut self) -> Vec<u8> {
        self.pool = ptr::null();
        let mut v = std::mem::take(&mut self.data);
        v.truncate(self.len);
        std::mem::forget(self); // don't return to pool
        v
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if !self.pool.is_null() {
            let pool = unsafe { &*self.pool };
            self.len = 0;
            let buf = std::mem::take(&mut self.data);
            pool.return_buf(buf);
        }
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] { self.as_slice() }
}

/// Thread-safe buffer pool using a lock-free stack.
pub struct BufferPool {
    // Lock-free stack of available buffers
    head: AtomicPtr<PoolNode>,
    buf_size: usize,
    stats: PoolStats,
}

struct PoolNode {
    buf: Vec<u8>,
    next: *mut PoolNode,
}

/// Pool statistics.
pub struct PoolStats {
    pub acquired: AtomicU64,
    pub returned: AtomicU64,
    pub allocated: AtomicU64, // fallback allocations when pool empty
}

impl BufferPool {
    /// Create a pool with `count` pre-allocated buffers of `buf_size` bytes each.
    pub fn new(count: usize, buf_size: usize) -> Self {
        let pool = Self {
            head: AtomicPtr::new(ptr::null_mut()),
            buf_size,
            stats: PoolStats {
                acquired: AtomicU64::new(0),
                returned: AtomicU64::new(0),
                allocated: AtomicU64::new(0),
            },
        };

        // Pre-allocate buffers
        for _ in 0..count {
            let buf = vec![0u8; buf_size];
            pool.return_buf(buf);
        }

        pool
    }

    /// Acquire a buffer from the pool.
    /// If pool is empty, allocates a new buffer (tracked in stats).
    pub fn acquire(&self) -> PooledBuffer {
        self.stats.acquired.fetch_add(1, Ordering::Relaxed);

        let data = self.try_pop().unwrap_or_else(|| {
            self.stats.allocated.fetch_add(1, Ordering::Relaxed);
            vec![0u8; self.buf_size]
        });

        PooledBuffer {
            data,
            len: 0,
            pool: self as *const Self,
        }
    }

    /// Pool buffer size.
    pub fn buf_size(&self) -> usize { self.buf_size }

    /// Number of buffers acquired.
    pub fn acquired_count(&self) -> u64 {
        self.stats.acquired.load(Ordering::Relaxed)
    }

    /// Number of buffers returned.
    pub fn returned_count(&self) -> u64 {
        self.stats.returned.load(Ordering::Relaxed)
    }

    /// Number of fallback allocations (pool was empty).
    pub fn fallback_allocs(&self) -> u64 {
        self.stats.allocated.load(Ordering::Relaxed)
    }

    fn return_buf(&self, buf: Vec<u8>) {
        self.stats.returned.fetch_add(1, Ordering::Relaxed);
        let node = Box::into_raw(Box::new(PoolNode {
            buf,
            next: ptr::null_mut(),
        }));

        loop {
            let head = self.head.load(Ordering::Acquire);
            unsafe { (*node).next = head; }
            if self.head.compare_exchange_weak(head, node, Ordering::Release, Ordering::Relaxed).is_ok() {
                break;
            }
        }
    }

    fn try_pop(&self) -> Option<Vec<u8>> {
        loop {
            let head = self.head.load(Ordering::Acquire);
            if head.is_null() {
                return None;
            }
            let next = unsafe { (*head).next };
            if self.head.compare_exchange_weak(head, next, Ordering::Release, Ordering::Relaxed).is_ok() {
                let node = unsafe { Box::from_raw(head) };
                return Some(node.buf);
            }
        }
    }
}

impl Drop for BufferPool {
    fn drop(&mut self) {
        // Drain all remaining buffers
        while self.try_pop().is_some() {}
    }
}

// Safety: BufferPool uses atomics for all shared state
unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}

/// Single-threaded buffer pool — even lower overhead (no atomics).
#[allow(dead_code)]
pub struct LocalPool {
    buffers: Vec<Vec<u8>>,
    buf_size: usize,
}

impl LocalPool {
    pub fn new(count: usize, buf_size: usize) -> Self {
        let buffers = (0..count).map(|_| vec![0u8; buf_size]).collect();
        Self { buffers, buf_size }
    }

    /// Acquire a buffer. Returns None if pool empty (caller must wait or allocate).
    pub fn acquire(&mut self) -> Option<Vec<u8>> {
        self.buffers.pop()
    }

    /// Return a buffer to the pool.
    pub fn release(&mut self, buf: Vec<u8>) {
        self.buffers.push(buf);
    }

    /// Available buffers count.
    pub fn available(&self) -> usize {
        self.buffers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_acquire_return() {
        let pool = BufferPool::new(4, 256);

        let mut buf = pool.acquire();
        assert_eq!(buf.capacity(), 256);
        buf.as_mut()[..5].copy_from_slice(b"hello");
        buf.set_len(5);
        assert_eq!(buf.as_slice(), b"hello");

        drop(buf); // returns to pool

        assert_eq!(pool.acquired_count(), 1);
        assert_eq!(pool.returned_count(), 5); // 4 initial + 1 returned
    }

    #[test]
    fn pool_reuse_no_alloc() {
        let pool = BufferPool::new(2, 128);

        // Acquire and return 100 times — no new allocations
        for _ in 0..100 {
            let buf = pool.acquire();
            drop(buf);
        }

        assert_eq!(pool.fallback_allocs(), 0);
    }

    #[test]
    fn pool_fallback_when_empty() {
        let pool = BufferPool::new(1, 64);

        let _b1 = pool.acquire();
        let _b2 = pool.acquire(); // pool empty, fallback alloc

        assert_eq!(pool.fallback_allocs(), 1);
    }

    #[test]
    fn pool_thread_safe() {
        let pool = std::sync::Arc::new(BufferPool::new(100, 256));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let pool = pool.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let mut buf = pool.acquire();
                    buf.as_mut()[0] = 42;
                    buf.set_len(1);
                    // buf dropped → returned to pool
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(pool.acquired_count(), 4000);
        assert_eq!(pool.fallback_allocs(), 0);
    }

    #[test]
    fn pool_with_mgep_messages() {
        let pool = BufferPool::new(8, 512);

        let mut buf = pool.acquire();

        // Encode MGEP message into pooled buffer
        let order = crate::messages::NewOrderSingleCore {
            order_id: 42, instrument_id: 7, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: crate::types::Decimal::from_f64(100.0),
            quantity: crate::types::Decimal::from_f64(10.0),
            stop_price: crate::types::Decimal::NULL,
        };

        // Encode directly into pooled buffer.
        // Message size = 32 (FullHeader) + NewOrderSingleCore::SIZE.
        let total_size = 32 + crate::messages::NewOrderSingleCore::SIZE;
        let header = crate::header::FullHeader::new(
            0x0001, 0x01, 1, 1, 0, total_size as u32, crate::frame::FrameFlags::NONE,
        );
        header.write_to(buf.as_mut());
        buf.as_mut()[32..total_size].copy_from_slice(order.as_bytes());
        buf.set_len(total_size);

        // Decode from pooled buffer
        let decoded = crate::codec::MessageBuffer::decode_new_order(buf.as_slice());
        assert_eq!(decoded.order_id, 42);

        // detach to own the data
        let owned = buf.detach();
        assert_eq!(owned.len(), total_size);
    }

    #[test]
    fn local_pool_basic() {
        let mut pool = LocalPool::new(3, 128);
        assert_eq!(pool.available(), 3);

        let buf = pool.acquire().unwrap();
        assert_eq!(pool.available(), 2);

        pool.release(buf);
        assert_eq!(pool.available(), 3);
    }
}
