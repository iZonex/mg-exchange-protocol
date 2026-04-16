#![no_main]
use libfuzzer_sys::fuzz_target;

// Feed arbitrary bytes through full decode pipeline:
// frame header → full header → dispatch → try_from_bytes → flex reader
fuzz_target!(|data: &[u8]| {
    let buf = data.to_vec();

    // Try frame header
    if let Some(frame) = mgep::frame::FrameHeader::try_from_bytes(&buf) {
        let _ = frame.message_size;
        let _ = frame.schema_id;
        let _ = frame.flags.has_flex();
        let _ = frame.flags.is_encrypted();
    }

    // Try full header
    if let Some(header) = mgep::header::FullHeader::try_from_bytes(&buf) {
        let _ = header.message.message_type;
        let _ = header.message.sequence_num;
    }

    // Try dispatch (should handle everything safely)
    match mgep::codec::dispatch_message(&buf) {
        mgep::codec::MessageKind::NewOrder(o) => {
            let _ = o.order_id;
            let _ = o.side();
            let _ = o.price;
        }
        mgep::codec::MessageKind::ExecutionReport(r) => {
            let _ = r.order_id;
            let _ = r.exec_type();
        }
        _ => {}
    }

    // Try validation
    let _ = mgep::validate::validate_message(&buf);

    // Try inspect
    let _ = mgep::inspect::format_message(&buf);
});
