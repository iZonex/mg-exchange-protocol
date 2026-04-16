//! MGEP Code Generator CLI
//!
//! Generates typed code from .mgep schema files.
//!
//! Usage:
//!   mgep-codegen schemas/trading.mgep                     # Rust to stdout
//!   mgep-codegen --c schemas/trading.mgep                 # C header to stdout
//!   mgep-codegen --module schemas/*.mgep                  # Full Rust messages module
//!   mgep-codegen --out-dir generated/ schemas/*.mgep      # Write files to directory
//!   mgep-codegen --c --out-dir include/ schemas/*.mgep    # C headers to directory

use std::fs;
use std::path::Path;

use mgep::codegen::{generate_c_header, generate_messages_module, generate_rust, parse_schema};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("mgep-codegen: MGEP schema code generator");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  mgep-codegen <schema.mgep> [...]           Rust code to stdout");
        eprintln!("  mgep-codegen --c <schema.mgep> [...]       C header to stdout");
        eprintln!("  mgep-codegen --module <schema.mgep> [...]  Full Rust module (all schemas)");
        eprintln!("  mgep-codegen --out-dir <dir> [...]         Write to directory");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  mgep-codegen schemas/trading.mgep");
        eprintln!("  mgep-codegen --c schemas/trading.mgep > mgep_trading.h");
        eprintln!("  mgep-codegen --module schemas/*.mgep > src/generated_messages.rs");
        std::process::exit(1);
    }

    let mut out_dir: Option<String> = None;
    let mut c_mode = false;
    let mut module_mode = false;
    let mut schema_files: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--c" => c_mode = true,
            "--module" => module_mode = true,
            "--out-dir" => {
                i += 1;
                if i < args.len() { out_dir = Some(args[i].clone()); }
            }
            other => schema_files.push(other.to_string()),
        }
        i += 1;
    }

    if schema_files.is_empty() {
        eprintln!("error: no schema files");
        std::process::exit(1);
    }

    // Parse all schemas
    let mut schemas = Vec::new();
    for path_str in &schema_files {
        let path = Path::new(path_str);
        let content = fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("error: {}: {}", path_str, e);
            std::process::exit(1);
        });
        let schema = parse_schema(&content).unwrap_or_else(|e| {
            eprintln!("error: {}: {}", path_str, e);
            std::process::exit(1);
        });
        schemas.push((path.to_path_buf(), schema));
    }

    if module_mode {
        // Generate combined module from all schemas
        let all_schemas: Vec<_> = schemas.iter().map(|(_, s)| s.clone()).collect();
        let code = generate_messages_module(&all_schemas);
        match &out_dir {
            Some(dir) => {
                fs::create_dir_all(dir).unwrap();
                let out_path = Path::new(dir).join("messages_generated.rs");
                fs::write(&out_path, &code).unwrap();
                eprintln!("wrote {} ({} bytes)", out_path.display(), code.len());
            }
            None => print!("{}", code),
        }
        return;
    }

    // Per-schema generation
    for (_path, schema) in &schemas {
        let code = if c_mode {
            generate_c_header(schema)
        } else {
            generate_rust(schema)
        };

        let ext = if c_mode { "h" } else { "rs" };

        match &out_dir {
            Some(dir) => {
                fs::create_dir_all(dir).unwrap();
                let filename = if c_mode {
                    format!("mgep_{}.{}", schema.name, ext)
                } else {
                    format!("{}.{}", schema.name, ext)
                };
                let out_path = Path::new(dir).join(filename);
                fs::write(&out_path, &code).unwrap();
                eprintln!("wrote {} ({} bytes)", out_path.display(), code.len());
            }
            None => print!("{}", code),
        }
    }
}
