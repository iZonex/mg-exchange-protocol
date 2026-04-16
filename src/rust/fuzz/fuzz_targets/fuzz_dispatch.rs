#![no_main]
use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes to dispatch_message.
// Must never panic — Malformed or Unknown are valid returns.
fuzz_target!(|data: &[u8]| {
    // Ensure data is aligned (heap allocation)
    let buf = data.to_vec();
    let _ = mgep::codec::dispatch_message(&buf);
});
