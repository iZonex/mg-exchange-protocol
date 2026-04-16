//! MGEP Schema Parser and Code Generator
//!
//! Parses `.mgep` schema files and generates code:
//! - Rust: zero-copy structs, enums, flex accessors
//! - C: packed structs, enums, inline decoders
//!
//! Usage:
//!   mgep-codegen schemas/trading.mgep                    # Rust to stdout
//!   mgep-codegen --c schemas/trading.mgep                # C header to stdout
//!   mgep-codegen --module schemas/*.mgep                 # Full Rust module
//!   mgep-codegen --out-dir generated/ schemas/*.mgep     # Files to directory

pub mod parser;
pub mod rust_gen;
pub mod c_gen;

pub use parser::{parse_schema, Schema};
pub use rust_gen::{generate_rust, generate_messages_module};
pub use c_gen::generate_c_header;
