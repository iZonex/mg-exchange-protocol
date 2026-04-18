//! MGEP — MG Exchange Protocol
//!
//! Ultra-low-latency binary protocol for exchange trading.
//! Zero-copy encode/decode, optional hardware-accelerated security.

#[macro_use]
mod core_macro;

pub mod types;
pub mod frame;
pub mod header;
pub mod messages;
pub mod flex;
pub mod codec;
pub mod session;
pub mod auth;
pub mod transport;
pub mod codegen;
pub mod error;
pub mod crypto;
pub mod batch;
pub mod replication;
pub mod connection;
#[cfg(feature = "experimental-transports")]
pub mod websocket;
pub mod multicast;
pub mod compress;
pub mod multiplex;
pub mod validate;
pub mod pool;
pub mod builder;
pub mod inspect;
pub mod metrics;
pub mod server;
pub mod orderbook;
pub mod snapshot;
pub mod idempotency;
pub mod cancel_on_disconnect;
pub mod rate_limit;
pub mod crypto_session;
pub mod clock_discipline;
pub mod correlation;
pub mod audit;
pub mod kill_switch;
pub mod risk_checks;
pub mod drop_copy;
pub mod client_state;
pub mod client_errors;
pub mod entitlements;
pub mod ha_replication;
pub mod fix_gateway;
#[cfg(all(target_os = "linux", feature = "linux-ptp"))]
pub mod linux_ptp_probe;
pub mod wal;
pub mod aesni;
pub mod ha;
#[cfg(unix)]
pub mod reactor;
#[cfg(unix)]
pub mod async_server;
#[cfg(all(unix, feature = "experimental-transports"))]
pub mod shmem;

pub use types::*;
pub use frame::*;
pub use header::*;
