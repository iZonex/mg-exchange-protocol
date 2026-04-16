#![no_main]
use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes to LZ4 decompressor.
// Must never panic — just return None for invalid data.
fuzz_target!(|data: &[u8]| {
    // Try decompressing with various max sizes
    let _ = mgep::compress::lz4_decompress(data, 1024);
    let _ = mgep::compress::lz4_decompress(data, 65536);
    let _ = mgep::compress::lz4_decompress(data, 0);

    // Try compressing then decompressing (roundtrip)
    if let Some(compressed) = mgep::compress::lz4_compress(data) {
        if let Some(decompressed) = mgep::compress::lz4_decompress(&compressed, data.len() + 1024) {
            assert_eq!(decompressed, data, "LZ4 roundtrip mismatch!");
        }
    }
});
