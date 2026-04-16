//! C header generator for MGEP schemas.
//!
//! Generates .h files with:
//! - Packed structs for zero-copy compatibility with Rust
//! - Enum definitions
//! - Size constants
//! - from_bytes / as_bytes inline functions

use crate::codegen::parser::*;
use std::collections::HashMap;
use std::fmt::Write;

/// Schema name → schema_id mapping.
fn schema_id_map() -> HashMap<&'static str, u16> {
    [
        ("session", 0x0000),
        ("trading", 0x0001),
        ("market_data", 0x0002),
        ("quotes", 0x0003),
        ("post_trade", 0x0004),
        ("risk", 0x0005),
    ].into()
}

/// Generate a C header from a schema.
pub fn generate_c_header(schema: &Schema) -> String {
    let mut out = String::with_capacity(8192);
    let ids = schema_id_map();
    let schema_id = ids.get(schema.name.as_str()).copied().unwrap_or(0xFFFF);
    let guard = format!("MGEP_{}_H", schema.name.to_uppercase());

    writeln!(out, "/* Auto-generated from {}.mgep — DO NOT EDIT */", schema.name).unwrap();
    writeln!(out, "/* Schema: {} (id=0x{:04X}, version={}) */", schema.name, schema_id, schema.version).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#ifndef {}", guard).unwrap();
    writeln!(out, "#define {}", guard).unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#include <stdint.h>").unwrap();
    writeln!(out, "#include <stddef.h>").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#ifdef __cplusplus").unwrap();
    writeln!(out, "extern \"C\" {{").unwrap();
    writeln!(out, "#endif").unwrap();
    writeln!(out).unwrap();

    // Frame header
    writeln!(out, "/* MGEP magic bytes */").unwrap();
    writeln!(out, "#define MGEP_MAGIC 0x474D").unwrap();
    writeln!(out, "#define MGEP_HEADER_SIZE 32").unwrap();
    writeln!(out, "#define MGEP_CORE_BLOCK_OFFSET 32").unwrap();
    writeln!(out).unwrap();

    // Typedefs
    writeln!(out, "/* Semantic types */").unwrap();
    writeln!(out, "typedef int64_t  mgep_decimal_t;  /* Fixed-point: value * 10^8 */").unwrap();
    writeln!(out, "typedef uint64_t mgep_timestamp_t; /* Nanoseconds since epoch */").unwrap();
    writeln!(out, "typedef uint64_t mgep_id_t;").unwrap();
    writeln!(out, "typedef uint32_t mgep_instrument_t;").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "#define MGEP_SCHEMA_ID_{} 0x{:04X}", schema.name.to_uppercase(), schema_id).unwrap();
    writeln!(out).unwrap();

    // Enums
    for e in &schema.enums {
        generate_c_enum(&mut out, e);
    }

    // Messages
    let msg_types: Vec<u16> = (1..=schema.messages.len() as u16).collect();
    for (i, msg) in schema.messages.iter().enumerate() {
        generate_c_struct(&mut out, msg, msg_types[i]);
    }

    writeln!(out, "#ifdef __cplusplus").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out, "#endif").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#endif /* {} */", guard).unwrap();

    out
}

fn generate_c_enum(out: &mut String, def: &EnumDef) {
    writeln!(out, "typedef enum {{").unwrap();
    for (i, v) in def.variants.iter().enumerate() {
        let prefix = to_screaming_snake(&def.name);
        if let Some(desc) = &v.description {
            writeln!(out, "    {}_{} = {},  /* {} */",
                prefix, to_screaming_snake(&v.name), i + 1, desc).unwrap();
        } else {
            writeln!(out, "    {}_{} = {},",
                prefix, to_screaming_snake(&v.name), i + 1).unwrap();
        }
    }
    writeln!(out, "}} mgep_{}_t;", to_snake(&def.name)).unwrap();
    writeln!(out).unwrap();
}

fn generate_c_struct(out: &mut String, msg: &MessageDef, msg_type: u16) {
    let core_fields: Vec<&FieldDef> = msg.fields.iter()
        .filter(|f| f.field_type.wire_size() > 0)
        .collect();

    if core_fields.is_empty() { return; }

    let struct_name = to_snake(&msg.name);
    let (size, _) = super::rust_gen::calculate_core_size_pub(&msg.fields);

    if let Some(desc) = &msg.description {
        writeln!(out, "/* {} */", desc).unwrap();
    }
    writeln!(out, "#define MGEP_{}_TYPE 0x{:02X}", struct_name.to_uppercase(), msg_type).unwrap();
    writeln!(out, "#define MGEP_{}_SIZE {}", struct_name.to_uppercase(), size).unwrap();
    writeln!(out).unwrap();

    writeln!(out, "typedef struct __attribute__((packed)) {{").unwrap();

    let mut offset = 0usize;
    let mut pad_count = 0;
    for f in &core_fields {
        let wire_size = f.field_type.wire_size();
        let align = wire_size.max(1);
        let padding = (align - (offset % align)) % align;

        if padding > 0 {
            writeln!(out, "    uint8_t _pad{}[{}];", pad_count, padding).unwrap();
            pad_count += 1;
            offset += padding;
        }

        let c_type = semantic_to_c_type(&f.field_type);
        if let Some(desc) = &f.description {
            writeln!(out, "    {} {};  /* {} */", c_type, f.name, desc).unwrap();
        } else {
            writeln!(out, "    {} {};", c_type, f.name).unwrap();
        }
        offset += wire_size;
    }

    let final_pad = (8 - (offset % 8)) % 8;
    if final_pad > 0 {
        writeln!(out, "    uint8_t _pad_end[{}];", final_pad).unwrap();
    }

    writeln!(out, "}} mgep_{}_t;", struct_name).unwrap();
    writeln!(out).unwrap();

    // Static assert
    writeln!(out, "_Static_assert(sizeof(mgep_{}_t) == {}, \"size mismatch\");",
        struct_name, size).unwrap();
    writeln!(out).unwrap();

    // Inline decode
    writeln!(out, "static inline const mgep_{}_t* mgep_{}_from_bytes(const uint8_t* buf) {{",
        struct_name, struct_name).unwrap();
    writeln!(out, "    return (const mgep_{}_t*)(buf + MGEP_CORE_BLOCK_OFFSET);", struct_name).unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn semantic_to_c_type(st: &SemanticType) -> &'static str {
    match st {
        SemanticType::Id | SemanticType::Seq | SemanticType::Timestamp => "uint64_t",
        SemanticType::Instrument | SemanticType::Count => "uint32_t",
        SemanticType::Price | SemanticType::Qty => "int64_t /* decimal */",
        SemanticType::Bool => "uint8_t",
        SemanticType::Enum(_) => "uint8_t",
        _ => "uint8_t",
    }
}

fn to_snake(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_lowercase().next().unwrap());
    }
    result
}

fn to_screaming_snake(s: &str) -> String {
    to_snake(s).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_c_from_trading() {
        let content = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas/trading.mgep")
        ).unwrap();
        let schema = parse_schema(&content).unwrap();
        let code = generate_c_header(&schema);

        assert!(code.contains("#ifndef MGEP_TRADING_H"));
        assert!(code.contains("typedef struct"));
        assert!(code.contains("mgep_new_order_single_t"));
        assert!(code.contains("mgep_execution_report_t"));
        assert!(code.contains("_Static_assert"));
        assert!(code.contains("mgep_new_order_single_from_bytes"));
        assert!(code.contains("MGEP_MAGIC"));
    }

    #[test]
    fn generate_c_from_all() {
        let schema_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
        for entry in std::fs::read_dir(schema_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("mgep") { continue; }
            let content = std::fs::read_to_string(&path).unwrap();
            let schema = parse_schema(&content).unwrap();
            let code = generate_c_header(&schema);
            assert!(code.contains("#ifndef"), "no guard in {}", path.display());
        }
    }
}
