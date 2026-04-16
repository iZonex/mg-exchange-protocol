//! Rust code generator for MGEP schemas.
//!
//! Generates a complete messages module from schema files:
//! - Enum definitions with from_u8 conversions
//! - Core block structs via `define_core!` macro
//! - Optional field accessors (flex)
//! - Schema ID constants
//! - `impl_core_block!` calls for codec integration

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

/// Message type assignment: use explicit @type if set, otherwise auto-increment.
fn assign_message_types(schema: &Schema) -> Vec<u16> {
    let mut next_auto = 1u16;
    schema.messages.iter()
        .map(|msg| {
            if let Some(explicit) = msg.msg_type {
                next_auto = explicit + 1;
                explicit
            } else {
                let t = next_auto;
                next_auto += 1;
                t
            }
        })
        .collect()
}

/// Calculate the wire size of a core block struct including alignment padding.
/// Public version for use by other generators (e.g., c_gen).
pub fn calculate_core_size_pub(fields: &[FieldDef]) -> (usize, Vec<CoreFieldLayout>) {
    calculate_core_size(fields)
}

fn calculate_core_size(fields: &[FieldDef]) -> (usize, Vec<CoreFieldLayout>) {
    let mut offset = 0usize;
    let mut layout = Vec::new();

    for f in fields {
        let wire_size = f.field_type.wire_size();
        if wire_size == 0 { continue; } // skip string/bytes (flex only)

        let align = wire_size.max(1);
        let padding = (align - (offset % align)) % align;

        if padding > 0 {
            layout.push(CoreFieldLayout::Padding(offset, padding));
            offset += padding;
        }

        layout.push(CoreFieldLayout::Field {
            name: f.name.clone(),
            field_type: f.field_type.clone(),
            offset,
            size: wire_size,
            description: f.description.clone(),
        });
        offset += wire_size;
    }

    // Pad to 8-byte alignment
    let final_pad = (8 - (offset % 8)) % 8;
    if final_pad > 0 {
        layout.push(CoreFieldLayout::Padding(offset, final_pad));
        offset += final_pad;
    }

    (offset, layout)
}

pub enum CoreFieldLayout {
    Field {
        name: String,
        field_type: SemanticType,
        offset: usize,
        size: usize,
        description: Option<String>,
    },
    Padding(usize, usize),
}

/// Generate a complete Rust module from a schema.
pub fn generate_rust(schema: &Schema) -> String {
    let mut out = String::with_capacity(16384);
    let ids = schema_id_map();
    let schema_id = ids.get(schema.name.as_str()).copied().unwrap_or(0xFFFF);
    let msg_types = assign_message_types(schema);

    writeln!(out, "// Auto-generated from {}.mgep — DO NOT EDIT", schema.name).unwrap();
    writeln!(out, "// Schema: {} (id=0x{:04X}, version={})", schema.name, schema_id, schema.version).unwrap();
    if !schema.imports.is_empty() {
        writeln!(out, "// Imports: {}", schema.imports.join(", ")).unwrap();
    }
    writeln!(out).unwrap();

    // Enums
    for e in &schema.enums {
        generate_enum(&mut out, e);
    }

    // Messages
    for (i, msg) in schema.messages.iter().enumerate() {
        generate_message_struct(&mut out, msg, schema_id, msg_types[i]);
    }

    out
}

/// Generate complete messages.rs from ALL schemas.
pub fn generate_messages_module(schemas: &[Schema]) -> String {
    let mut out = String::with_capacity(32768);
    let ids = schema_id_map();

    writeln!(out, "//! Auto-generated from MGEP schemas — DO NOT EDIT.").unwrap();
    writeln!(out, "//! Regenerate: cargo run --bin mgep-codegen -- --module").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use crate::types::*;").unwrap();
    writeln!(out).unwrap();

    // Collect all enums (deduplicate by name — common.mgep defines shared ones)
    let mut seen_enums = std::collections::HashSet::new();
    for schema in schemas {
        for e in &schema.enums {
            if seen_enums.insert(e.name.clone()) {
                generate_enum(&mut out, e);
            }
        }
    }

    // Generate structs for all messages across all schemas
    for schema in schemas {
        let schema_id = ids.get(schema.name.as_str()).copied().unwrap_or(0xFFFF);
        let msg_types = assign_message_types(schema);

        if !schema.messages.is_empty() {
            writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
            writeln!(out, "// {} (schema_id = 0x{:04X})", schema.name, schema_id).unwrap();
            writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
            writeln!(out).unwrap();
        }

        for (i, msg) in schema.messages.iter().enumerate() {
            generate_message_struct(&mut out, msg, schema_id, msg_types[i]);
        }
    }

    // ── CoreBlock trait + impl_core_block! ─────────────────
    writeln!(out).unwrap();
    writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
    writeln!(out, "// CoreBlock trait + implementations").unwrap();
    writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "/// Trait for any MGEP core block.").unwrap();
    writeln!(out, "pub trait CoreBlock: Copy {{").unwrap();
    writeln!(out, "    const SIZE: usize;").unwrap();
    writeln!(out, "    const MESSAGE_TYPE: u16;").unwrap();
    writeln!(out, "    const SCHEMA_ID: u16;").unwrap();
    writeln!(out, "    fn as_bytes(&self) -> &[u8];").unwrap();
    writeln!(out, "    fn from_bytes(buf: &[u8]) -> &Self;").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Collect all (schema_id, msg_type, struct_name) for dispatch
    let mut all_messages: Vec<(u16, u16, String)> = Vec::new();

    for schema in schemas {
        let schema_id = ids.get(schema.name.as_str()).copied().unwrap_or(0xFFFF);
        let msg_types = assign_message_types(schema);

        for (i, msg) in schema.messages.iter().enumerate() {
            let struct_name = format!("{}Core", msg.name);
            let has_core = msg.fields.iter().any(|f| f.field_type.wire_size() > 0);
            if !has_core { continue; }

            // impl CoreBlock
            writeln!(out, "impl CoreBlock for {} {{", struct_name).unwrap();
            writeln!(out, "    const SIZE: usize = Self::SIZE;").unwrap();
            writeln!(out, "    const MESSAGE_TYPE: u16 = Self::MESSAGE_TYPE;").unwrap();
            writeln!(out, "    const SCHEMA_ID: u16 = Self::SCHEMA_ID;").unwrap();
            writeln!(out, "    #[inline(always)] fn as_bytes(&self) -> &[u8] {{ Self::as_bytes(self) }}").unwrap();
            writeln!(out, "    #[inline(always)] fn from_bytes(buf: &[u8]) -> &Self {{ Self::from_bytes(buf) }}").unwrap();
            writeln!(out, "}}").unwrap();

            all_messages.push((schema_id, msg_types[i], msg.name.clone()));
        }
    }

    // ── MessageKind enum ─────────────────────────────────
    writeln!(out).unwrap();
    writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
    writeln!(out, "// Dispatch").unwrap();
    writeln!(out, "// ═══════════════════════════════════════════════").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "/// Typed message variants for dispatch.").unwrap();
    writeln!(out, "pub enum MessageKind<'a> {{").unwrap();
    for (_, _, name) in &all_messages {
        writeln!(out, "    {}(&'a {}Core),", name, name).unwrap();
    }
    writeln!(out, "    Unknown {{ schema_id: u16, msg_type: u16 }},").unwrap();
    writeln!(out, "    Malformed,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // ── dispatch_message function ────────────────────────
    writeln!(out, "/// Dispatch a raw MGEP message by schema_id + message_type.").unwrap();
    writeln!(out, "#[inline]").unwrap();
    writeln!(out, "pub fn dispatch_message(buf: &[u8]) -> MessageKind<'_> {{").unwrap();
    writeln!(out, "    let Some(header) = crate::header::FullHeader::try_from_bytes(buf) else {{").unwrap();
    writeln!(out, "        return MessageKind::Malformed;").unwrap();
    writeln!(out, "    }};").unwrap();
    writeln!(out, "    let core_buf = &buf[crate::header::CORE_BLOCK_OFFSET..];").unwrap();
    writeln!(out, "    match (header.message.schema_id, header.message.message_type) {{").unwrap();
    for (schema_id, msg_type, name) in &all_messages {
        writeln!(out, "        (0x{:04X}, 0x{:02X}) => match {}Core::try_from_bytes(core_buf) {{",
            schema_id, msg_type, name).unwrap();
        writeln!(out, "            Some(v) => MessageKind::{}(v),", name).unwrap();
        writeln!(out, "            None => MessageKind::Malformed,").unwrap();
        writeln!(out, "        }},").unwrap();
    }
    writeln!(out, "        _ => MessageKind::Unknown {{ schema_id: header.message.schema_id, msg_type: header.message.message_type }},").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();

    // ── Size assertion tests ─────────────────────────────
    writeln!(out).unwrap();
    writeln!(out, "#[cfg(test)]").unwrap();
    writeln!(out, "mod tests {{").unwrap();
    writeln!(out, "    use super::*;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    #[test]").unwrap();
    writeln!(out, "    fn all_struct_sizes() {{").unwrap();
    for (_, _, name) in &all_messages {
        writeln!(out, "        assert_eq!(core::mem::size_of::<{}Core>(), {}Core::SIZE);", name, name).unwrap();
    }
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();

    out
}

fn generate_enum(out: &mut String, def: &EnumDef) {
    writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]").unwrap();
    writeln!(out, "#[repr(u8)]").unwrap();
    writeln!(out, "pub enum {} {{", def.name).unwrap();
    for (i, v) in def.variants.iter().enumerate() {
        if let Some(desc) = &v.description {
            writeln!(out, "    /// {}", desc).unwrap();
        }
        writeln!(out, "    {} = {},", v.name, i + 1).unwrap();
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl {} {{", def.name).unwrap();
    writeln!(out, "    #[inline(always)]").unwrap();
    writeln!(out, "    pub fn from_u8(v: u8) -> Option<Self> {{").unwrap();
    writeln!(out, "        match v {{").unwrap();
    for (i, v) in def.variants.iter().enumerate() {
        writeln!(out, "            {} => Some(Self::{}),", i + 1, v.name).unwrap();
    }
    writeln!(out, "            _ => None,").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

fn generate_message_struct(out: &mut String, msg: &MessageDef, schema_id: u16, msg_type: u16) {
    let struct_name = format!("{}Core", msg.name);

    // Only core-sized fields go in the struct
    let core_fields: Vec<&FieldDef> = msg.fields.iter()
        .filter(|f| f.field_type.wire_size() > 0)
        .collect();

    if core_fields.is_empty() {
        // Message with only optional/string fields — minimal 8-byte struct
        if let Some(desc) = &msg.description {
            writeln!(out, "/// {}", desc).unwrap();
        }
        writeln!(out, "define_core!(").unwrap();
        writeln!(out, "    {}, schema=0x{:04X}, msg_type=0x{:02X}, size=8,", struct_name, schema_id, msg_type).unwrap();
        writeln!(out, "    {{ pub _reserved: u64 }}").unwrap();
        writeln!(out, ");").unwrap();
        writeln!(out).unwrap();
        return;
    }

    let (size, layout) = calculate_core_size(&msg.fields);

    writeln!(out, "define_core!(").unwrap();
    if let Some(desc) = &msg.description {
        writeln!(out, "    /// {} — {} bytes.", desc, size).unwrap();
    }
    writeln!(out, "    {}, schema=0x{:04X}, msg_type=0x{:02X}, size={},", struct_name, schema_id, msg_type, size).unwrap();
    writeln!(out, "    {{").unwrap();

    for item in &layout {
        match item {
            CoreFieldLayout::Padding(off, n) => {
                writeln!(out, "        pub _pad_{}: [u8; {}],", off, n).unwrap();
            }
            CoreFieldLayout::Field { name, field_type, description, .. } => {
                let _rust_type = match field_type {
                    SemanticType::Enum(ename) => format!("u8 /* {} */", ename),
                    other => other.rust_type().to_string(),
                };
                if let Some(desc) = description {
                    writeln!(out, "        /// {}", desc).unwrap();
                }
                // Handle enum fields — they're stored as the underlying type
                let type_str = match field_type {
                    SemanticType::Enum(_) => "u8".to_string(),
                    other => other.rust_type().to_string(),
                };
                writeln!(out, "        pub {}: {},", name, type_str).unwrap();
            }
        }
    }

    writeln!(out, "    }}").unwrap();
    writeln!(out, ");").unwrap();
    writeln!(out).unwrap();

    // Optional fields accessor
    if !msg.optional_fields.is_empty() {
        generate_optional_accessor(out, msg);
    }
}

fn generate_optional_accessor(out: &mut String, msg: &MessageDef) {
    let name = format!("{}Optional", msg.name);

    writeln!(out, "/// Optional field accessor for `{}`.", msg.name).unwrap();
    writeln!(out, "pub struct {}<'a> {{", name).unwrap();
    writeln!(out, "    reader: crate::flex::FlexReader<'a>,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "impl<'a> {}<'a> {{", name).unwrap();
    writeln!(out, "    pub fn new(buf: &'a [u8]) -> Self {{").unwrap();
    writeln!(out, "        Self {{ reader: crate::flex::FlexReader::new(buf) }}").unwrap();
    writeln!(out, "    }}").unwrap();

    for (i, f) in msg.optional_fields.iter().enumerate() {
        let field_id = (i + 1) as u16;
        writeln!(out).unwrap();
        if let Some(desc) = &f.description {
            writeln!(out, "    /// {}", desc).unwrap();
        }

        let method = match &f.field_type {
            SemanticType::String => format!(
                "    pub fn {}(&self) -> Option<&'a str> {{ self.reader.get_string({}) }}", f.name, field_id
            ),
            SemanticType::Id | SemanticType::Seq | SemanticType::Timestamp => format!(
                "    pub fn {}(&self) -> Option<u64> {{ self.reader.get_u64({}) }}", f.name, field_id
            ),
            SemanticType::Price | SemanticType::Qty => format!(
                "    pub fn {}(&self) -> Option<crate::types::Decimal> {{ self.reader.get_decimal({}) }}", f.name, field_id
            ),
            SemanticType::Bytes => format!(
                "    // TODO: bytes accessor for {}", f.name
            ),
            _ => format!(
                "    pub fn {}(&self) -> Option<u64> {{ self.reader.get_u64({}) }}", f.name, field_id
            ),
        };
        writeln!(out, "{}", method).unwrap();
    }

    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_from_trading_schema() {
        let content = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas/trading.mgep")
        ).unwrap();
        let schema = parse_schema(&content).unwrap();
        let code = generate_rust(&schema);

        assert!(code.contains("define_core!"));
        assert!(code.contains("NewOrderSingleCore"));
        assert!(code.contains("ExecutionReportCore"));
        assert!(code.contains("schema=0x0001"));
        assert!(code.contains("pub struct NewOrderSingleOptional"));
    }

    #[test]
    fn generate_full_module() {
        let schema_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
        let mut schemas = Vec::new();

        for entry in std::fs::read_dir(schema_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("mgep") { continue; }
            let content = std::fs::read_to_string(&path).unwrap();
            schemas.push(parse_schema(&content).unwrap());
        }

        let code = generate_messages_module(&schemas);

        // Should have all schemas
        assert!(code.contains("trading"));
        assert!(code.contains("market_data"));
        assert!(code.contains("quotes"));
        assert!(code.contains("post_trade"));
        assert!(code.contains("risk"));

        // Should have enums
        assert!(code.contains("pub enum Side"));
        assert!(code.contains("pub enum OrderType"));
        assert!(code.contains("pub enum ExecType"));

        // Should have size tests
        assert!(code.contains("all_struct_sizes"));

        println!("Generated module: {} bytes, {} lines",
            code.len(), code.lines().count());
    }

    #[test]
    fn generate_from_all_schemas() {
        let schema_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
        for entry in std::fs::read_dir(schema_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("mgep") { continue; }
            let content = std::fs::read_to_string(&path).unwrap();
            let schema = parse_schema(&content).unwrap();
            let code = generate_rust(&schema);

            for msg in &schema.messages {
                assert!(code.contains(&format!("{}Core", msg.name)),
                    "missing {}Core in {}", msg.name, path.display());
            }
        }
    }
}
