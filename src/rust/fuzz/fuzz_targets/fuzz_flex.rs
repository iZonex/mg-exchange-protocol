#![no_main]
use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes to FlexReader and try all field access methods.
// Must never panic.
fuzz_target!(|data: &[u8]| {
    let reader = mgep::flex::FlexReader::new(data);
    let _ = reader.count();

    // Try reading various field IDs
    for id in 0..20u16 {
        let _ = reader.get_string(id);
        let _ = reader.get_u64(id);
        let _ = reader.get_decimal(id);
    }

    let _ = reader.find_field(0);
    let _ = reader.find_field(u16::MAX);
});
