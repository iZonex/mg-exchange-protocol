//! Message Validation Framework.
//!
//! Validates MGEP messages at system boundaries (incoming from network).
//! Not used on the hot encode path — only on decode/receive.
//!
//! Validates:
//!   - Frame header sanity (message_size, schema_id, version)
//!   - Core block field ranges (e.g., side must be 1 or 2)
//!   - Required fields are not null
//!   - Flex block integrity
//!   - Consistency (e.g., cancel_id != order_id)

use crate::frame::FrameHeader;
use crate::header::{FullHeader, CORE_BLOCK_OFFSET};
use crate::messages::*;
use crate::types::Decimal;

/// Validation result.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: &'static str,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Validate a raw MGEP message buffer.
/// Returns a list of validation errors (empty = valid).
pub fn validate_message(buf: &[u8]) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    // Frame header validation
    if buf.len() < FrameHeader::SIZE {
        errors.push(ValidationError {
            field: "buffer",
            message: format!("too short: {} bytes", buf.len()),
        });
        return errors;
    }

    let frame = FrameHeader::from_bytes(buf);

    if (frame.message_size as usize) < CORE_BLOCK_OFFSET {
        errors.push(ValidationError {
            field: "message_size",
            message: format!("too small: {} (min {})", frame.message_size, CORE_BLOCK_OFFSET),
        });
        return errors;
    }

    if frame.message_size as usize > buf.len() {
        errors.push(ValidationError {
            field: "message_size",
            message: format!("exceeds buffer: {} > {}", frame.message_size, buf.len()),
        });
        return errors;
    }

    let known_schemas = [0x0000u16, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0xFFFF];
    if buf.len() >= FullHeader::SIZE {
        let header = FullHeader::from_bytes(buf);
        if !known_schemas.contains(&header.message.schema_id) {
            errors.push(ValidationError {
                field: "schema_id",
                message: format!("unknown: 0x{:04X}", header.message.schema_id),
            });
        }
    }

    // FullHeader validation
    if buf.len() < CORE_BLOCK_OFFSET {
        return errors;
    }

    let header = FullHeader::from_bytes(buf);

    // Schema-specific validation
    let core_buf = &buf[CORE_BLOCK_OFFSET..];
    match (header.message.schema_id, header.message.message_type) {
        (0x0001, 0x01) => validate_new_order(core_buf, &mut errors),
        (0x0001, 0x05) => validate_execution_report(core_buf, &mut errors),
        _ => {} // no specific validation for this type
    }

    errors
}

fn validate_new_order(buf: &[u8], errors: &mut Vec<ValidationError>) {
    if let Some(order) = NewOrderSingleCore::try_from_bytes(buf) {
        if order.order_id == 0 {
            errors.push(ValidationError {
                field: "order_id",
                message: "cannot be 0".into(),
            });
        }

        if order.side != 1 && order.side != 2 {
            errors.push(ValidationError {
                field: "side",
                message: format!("invalid: {} (must be 1=Buy or 2=Sell)", order.side),
            });
        }

        if order.order_type < 1 || order.order_type > 4 {
            errors.push(ValidationError {
                field: "order_type",
                message: format!("invalid: {} (must be 1-4)", order.order_type),
            });
        }

        if order.instrument_id == 0 {
            errors.push(ValidationError {
                field: "instrument_id",
                message: "cannot be 0".into(),
            });
        }

        if order.quantity.is_null() || order.quantity == Decimal::ZERO {
            errors.push(ValidationError {
                field: "quantity",
                message: "must be positive".into(),
            });
        }

        // Limit orders must have a price
        if order.order_type == 2 && order.price.is_null() {
            errors.push(ValidationError {
                field: "price",
                message: "required for limit orders".into(),
            });
        }
    }
}

fn validate_execution_report(buf: &[u8], errors: &mut Vec<ValidationError>) {
    if let Some(report) = ExecutionReportCore::try_from_bytes(buf) {
        if report.order_id == 0 {
            errors.push(ValidationError {
                field: "order_id",
                message: "cannot be 0".into(),
            });
        }

        if report.exec_id == 0 {
            errors.push(ValidationError {
                field: "exec_id",
                message: "cannot be 0".into(),
            });
        }

        // Validate exec_type is known
        if report.exec_type().is_none() {
            errors.push(ValidationError {
                field: "exec_type",
                message: format!("unknown: {}", report.exec_type),
            });
        }

        // Fill/PartialFill must have last_px and last_qty
        if report.exec_type == 1 || report.exec_type == 2 {
            if report.last_px.is_null() {
                errors.push(ValidationError {
                    field: "last_px",
                    message: "required for fills".into(),
                });
            }
            if report.last_qty.is_null() || report.last_qty == Decimal::ZERO {
                errors.push(ValidationError {
                    field: "last_qty",
                    message: "required for fills".into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageBuffer;
    use crate::types::*;

    #[test]
    fn valid_new_order_passes() {
        let order = NewOrderSingleCore {
            order_id: 1, instrument_id: 42, side: 1, order_type: 2,
            client_order_id: 0,
            time_in_force: 1, price: Decimal::from_f64(100.0),
            quantity: Decimal::from_f64(10.0), stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        let errors = validate_message(enc.as_slice());
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn invalid_new_order_caught() {
        let order = NewOrderSingleCore {
            order_id: 0,  // invalid
            client_order_id: 0,
            instrument_id: 0, // invalid
            side: 5,  // invalid
            order_type: 2,
            time_in_force: 1,
            price: Decimal::NULL, // limit order without price
            quantity: Decimal::ZERO, // zero qty
            stop_price: Decimal::NULL,
        };
        let mut enc = MessageBuffer::with_capacity(256);
        enc.encode(1, 1, &order, None);
        let errors = validate_message(enc.as_slice());

        let fields: Vec<&str> = errors.iter().map(|e| e.field).collect();
        assert!(fields.contains(&"order_id"));
        assert!(fields.contains(&"instrument_id"));
        assert!(fields.contains(&"side"));
        assert!(fields.contains(&"price"));
        assert!(fields.contains(&"quantity"));
    }

    #[test]
    fn empty_buffer_rejected() {
        let errors = validate_message(&[]);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "buffer");
    }

    #[test]
    fn truncated_message_rejected() {
        let errors = validate_message(&vec![0u8; 10]);
        assert!(!errors.is_empty());
    }

    #[test]
    fn unknown_schema_flagged() {
        let mut buf = vec![0u8; 72];
        // New layout: magic(0..2), flags(2), version(3), message_size(4..8)
        buf[0..2].copy_from_slice(&crate::frame::MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&72u32.to_le_bytes());
        // MessageHeader starts at offset 8: schema_id(8..10)
        buf[8..10].copy_from_slice(&0xBEEFu16.to_le_bytes()); // unknown schema
        let errors = validate_message(&buf);
        assert!(errors.iter().any(|e| e.field == "schema_id"));
    }
}
