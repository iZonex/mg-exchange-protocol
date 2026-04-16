//! MGEP Schema Parser
//!
//! Parses the new schema format:
//!   schema trading
//!   version 1
//!   import common
//!
//!   enum Side { Buy; Sell }
//!
//!   message NewOrderSingle {
//!       "Description"
//!       field_name  type  required  "doc"
//!       optional { ... }
//!   }

/// Parsed schema file.
#[derive(Debug, Clone)]
pub struct Schema {
    pub name: String,
    pub version: u8,
    pub imports: Vec<String>,
    pub enums: Vec<EnumDef>,
    pub messages: Vec<MessageDef>,
}

/// Enum definition.
#[derive(Debug, Clone)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub description: Option<String>,
}

/// Message definition.
#[derive(Debug, Clone)]
pub struct MessageDef {
    pub name: String,
    pub description: Option<String>,
    pub msg_type: Option<u16>,  // explicit @type, or auto-assigned
    pub fields: Vec<FieldDef>,
    pub optional_fields: Vec<FieldDef>,
}

/// Semantic field types — maps to wire types in codegen.
#[derive(Debug, Clone, PartialEq)]
pub enum SemanticType {
    Id,             // u64
    Instrument,     // u32
    Price,          // Decimal (i64 * 10^8)
    Qty,            // Decimal
    Count,          // u32
    Seq,            // u64
    Timestamp,      // u64 nanoseconds
    Bool,           // u8
    String,         // flex string
    Bytes,          // flex bytes
    Enum(String),   // named enum
}

impl SemanticType {
    /// Wire size in bytes for core block fields.
    pub fn wire_size(&self) -> usize {
        match self {
            Self::Id | Self::Seq | Self::Timestamp | Self::Price | Self::Qty => 8,
            Self::Instrument | Self::Count => 4,
            Self::Bool => 1,
            Self::String | Self::Bytes => 0, // variable, flex only
            Self::Enum(_) => 1, // default u8, resolved during codegen
        }
    }

    /// Rust type name for codegen.
    pub fn rust_type(&self) -> &str {
        match self {
            Self::Id | Self::Seq => "u64",
            Self::Instrument | Self::Count => "u32",
            Self::Price | Self::Qty => "Decimal",
            Self::Timestamp => "Timestamp",
            Self::Bool => "u8",
            Self::String => "&str",
            Self::Bytes => "&[u8]",
            Self::Enum(_) => "u8",
        }
    }
}

/// Field definition.
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub field_type: SemanticType,
    pub required: bool,
    pub nullable: bool,
    pub description: Option<String>,
}

/// Parse error.
#[derive(Debug)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parse a `.mgep` schema file.
pub fn parse_schema(input: &str) -> Result<Schema, ParseError> {
    let mut schema = Schema {
        name: String::new(),
        version: 1,
        imports: Vec::new(),
        enums: Vec::new(),
        messages: Vec::new(),
    };

    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        let _line_num = i + 1;

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('─') {
            i += 1;
            continue;
        }

        if let Some(rest) = line.strip_prefix("schema ") {
            schema.name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("version ") {
            schema.version = rest.trim().parse().unwrap_or(1);
        } else if let Some(rest) = line.strip_prefix("import ") {
            schema.imports.push(rest.trim().to_string());
        } else if line.starts_with("enum ") {
            let (enum_def, consumed) = parse_enum(&lines, i)?;
            schema.enums.push(enum_def);
            i += consumed;
            continue;
        } else if line.starts_with("message ") {
            let (msg_def, consumed) = parse_message(&lines, i)?;
            schema.messages.push(msg_def);
            i += consumed;
            continue;
        }

        i += 1;
    }

    Ok(schema)
}

fn parse_enum(lines: &[&str], start: usize) -> Result<(EnumDef, usize), ParseError> {
    let header = lines[start].trim();
    // enum Name {
    let name = header
        .strip_prefix("enum ")
        .and_then(|s| s.strip_suffix('{').or(Some(s)))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ParseError { line: start + 1, message: "invalid enum".into() })?;

    let mut variants = Vec::new();
    let mut i = start + 1;

    while i < lines.len() {
        let line = lines[i].trim();
        if line == "}" {
            return Ok((EnumDef { name, variants }, i - start + 1));
        }
        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // Variant   "optional description"
        let (variant_name, desc) = parse_name_and_description(line);
        if !variant_name.is_empty() {
            variants.push(EnumVariant {
                name: variant_name,
                description: desc,
            });
        }

        i += 1;
    }

    Err(ParseError { line: start + 1, message: "unclosed enum".into() })
}

fn parse_message(lines: &[&str], start: usize) -> Result<(MessageDef, usize), ParseError> {
    let header = lines[start].trim();
    let name = header
        .strip_prefix("message ")
        .and_then(|s| s.strip_suffix('{').or(Some(s)))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ParseError { line: start + 1, message: "invalid message".into() })?;

    let mut msg = MessageDef {
        name,
        description: None,
        msg_type: None,
        fields: Vec::new(),
        optional_fields: Vec::new(),
    };

    let mut i = start + 1;
    let mut in_optional = false;

    while i < lines.len() {
        let line = lines[i].trim();

        if line == "}" {
            if in_optional {
                in_optional = false;
                i += 1;
                continue;
            }
            return Ok((msg, i - start + 1));
        }

        if line.is_empty() || line.starts_with('#') {
            i += 1;
            continue;
        }

        // @type directive
        if let Some(rest) = line.strip_prefix("@type") {
            let val = rest.trim();
            if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
                msg.msg_type = u16::from_str_radix(hex, 16).ok();
            } else {
                msg.msg_type = val.parse().ok();
            }
            i += 1;
            continue;
        }

        // Message description: first quoted string
        if line.starts_with('"') && msg.description.is_none() && msg.fields.is_empty() {
            msg.description = Some(line.trim_matches('"').to_string());
            i += 1;
            continue;
        }

        // Optional block
        if line.starts_with("optional {") || line == "optional" {
            in_optional = true;
            i += 1;
            continue;
        }

        // Parse field line
        if let Some(field) = parse_field(line) {
            if in_optional {
                msg.optional_fields.push(field);
            } else {
                msg.fields.push(field);
            }
        }

        i += 1;
    }

    Err(ParseError { line: start + 1, message: "unclosed message".into() })
}

fn parse_field(line: &str) -> Option<FieldDef> {
    // field_name  type  [required|nullable]  ["description"]
    // Tokens are whitespace-separated, description is last quoted string
    let line = line.split('#').next()?.trim();
    if line.is_empty() { return None; }

    // Extract description (last quoted string)
    let (line_no_desc, description) = extract_description(line);
    let tokens: Vec<&str> = line_no_desc.split_whitespace().collect();

    if tokens.len() < 2 { return None; }

    let name = tokens[0].to_string();
    let field_type = parse_semantic_type(tokens[1]);

    let mut required = false;
    let mut nullable = false;

    for &tok in &tokens[2..] {
        match tok {
            "required" => required = true,
            "nullable" => nullable = true,
            _ => {}
        }
    }

    Some(FieldDef {
        name,
        field_type,
        required,
        nullable,
        description,
    })
}

fn parse_semantic_type(s: &str) -> SemanticType {
    match s {
        "id" => SemanticType::Id,
        "instrument" => SemanticType::Instrument,
        "price" => SemanticType::Price,
        "qty" => SemanticType::Qty,
        "count" => SemanticType::Count,
        "seq" => SemanticType::Seq,
        "timestamp" => SemanticType::Timestamp,
        "bool" => SemanticType::Bool,
        "string" => SemanticType::String,
        "bytes" => SemanticType::Bytes,
        other => SemanticType::Enum(other.to_string()),
    }
}

fn parse_name_and_description(line: &str) -> (String, Option<String>) {
    let (no_desc, desc) = extract_description(line);
    let name = no_desc.split_whitespace().next().unwrap_or("").to_string();
    (name, desc)
}

fn extract_description(line: &str) -> (&str, Option<String>) {
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start + 1..].find('"') {
            let desc = line[start + 1..start + 1 + end].to_string();
            let rest = line[..start].trim();
            return (rest, Some(desc));
        }
    }
    (line, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
schema trading
version 1
import common

enum Side {
    Buy
    Sell
}

enum OrderType {
    Market
    Limit
    Stop     "Stop order"
}

message NewOrderSingle {
    "Submit a new order to the exchange."

    order_id        id          required    "Exchange-assigned order ID"
    instrument_id   instrument  required
    side            Side        required
    price           price       nullable
    quantity        qty         required

    optional {
        account         string      "Trading account"
        client_order_id string
    }
}
"#;

    #[test]
    fn parse_schema_basic() {
        let schema = parse_schema(SAMPLE).unwrap();
        assert_eq!(schema.name, "trading");
        assert_eq!(schema.version, 1);
        assert_eq!(schema.imports, vec!["common"]);
    }

    #[test]
    fn parse_enums() {
        let schema = parse_schema(SAMPLE).unwrap();
        assert_eq!(schema.enums.len(), 2);

        let side = &schema.enums[0];
        assert_eq!(side.name, "Side");
        assert_eq!(side.variants.len(), 2);
        assert_eq!(side.variants[0].name, "Buy");
        assert_eq!(side.variants[1].name, "Sell");

        let ot = &schema.enums[1];
        assert_eq!(ot.variants[2].name, "Stop");
        assert_eq!(ot.variants[2].description, Some("Stop order".into()));
    }

    #[test]
    fn parse_message() {
        let schema = parse_schema(SAMPLE).unwrap();
        assert_eq!(schema.messages.len(), 1);

        let msg = &schema.messages[0];
        assert_eq!(msg.name, "NewOrderSingle");
        assert_eq!(msg.description, Some("Submit a new order to the exchange.".into()));
        assert_eq!(msg.fields.len(), 5);
        assert_eq!(msg.optional_fields.len(), 2);
    }

    #[test]
    fn parse_fields() {
        let schema = parse_schema(SAMPLE).unwrap();
        let msg = &schema.messages[0];

        let f0 = &msg.fields[0];
        assert_eq!(f0.name, "order_id");
        assert_eq!(f0.field_type, SemanticType::Id);
        assert!(f0.required);
        assert_eq!(f0.description, Some("Exchange-assigned order ID".into()));

        let f3 = &msg.fields[3];
        assert_eq!(f3.name, "price");
        assert_eq!(f3.field_type, SemanticType::Price);
        assert!(f3.nullable);
        assert!(!f3.required);

        let f2 = &msg.fields[2];
        assert_eq!(f2.field_type, SemanticType::Enum("Side".into()));
    }

    #[test]
    fn parse_optional_fields() {
        let schema = parse_schema(SAMPLE).unwrap();
        let msg = &schema.messages[0];

        assert_eq!(msg.optional_fields[0].name, "account");
        assert_eq!(msg.optional_fields[0].field_type, SemanticType::String);
        assert_eq!(msg.optional_fields[0].description, Some("Trading account".into()));

        assert_eq!(msg.optional_fields[1].name, "client_order_id");
    }

    #[test]
    fn parse_real_trading_schema() {
        let content = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas/trading.mgep")
        ).unwrap();
        let schema = parse_schema(&content).unwrap();

        assert_eq!(schema.name, "trading");
        assert_eq!(schema.version, 1);
        assert!(schema.imports.contains(&"common".to_string()));
        assert!(schema.messages.len() >= 8, "expected at least 8 messages, got {}", schema.messages.len());

        // Check NewOrderSingle
        let nos = schema.messages.iter().find(|m| m.name == "NewOrderSingle").unwrap();
        assert!(nos.description.is_some());
        assert!(nos.fields.len() >= 5);
        assert!(nos.optional_fields.len() >= 3);
    }

    #[test]
    fn parse_all_schemas() {
        let schema_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schemas");
        for entry in std::fs::read_dir(schema_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("mgep") { continue; }
            let content = std::fs::read_to_string(&path).unwrap();
            let result = parse_schema(&content);
            assert!(result.is_ok(), "failed to parse {}: {:?}", path.display(), result.err());
            let schema = result.unwrap();
            assert!(!schema.name.is_empty(), "empty name in {}", path.display());
        }
    }
}
