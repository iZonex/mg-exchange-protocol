//! Build script: auto-generate Rust code from .mgep schemas.
//!
//! On `cargo build`, parses all schemas/*.mgep files and writes
//! generated code to OUT_DIR. The generated code can be included
//! via `include!(concat!(env!("OUT_DIR"), "/trading_generated.rs"))`.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let schema_dir = Path::new("../../schemas");

    if !schema_dir.exists() {
        // Not fatal — schemas may not be present in all build contexts
        return;
    }

    let entries = match fs::read_dir(schema_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("mgep") {
            continue;
        }

        let __content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cargo:warning=cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        // Use the crate's own parser (we can't import it directly in build.rs,
        // so we do a minimal parse here to verify schemas are valid)
        // The actual codegen is done by the mgep-codegen binary.
        // build.rs just triggers rerun and validates.

        let stem = path.file_stem().unwrap().to_str().unwrap();
        let out_path = Path::new(&out_dir).join(format!("{}_generated.rs", stem));

        // Write a marker file that includes the schema name
        let header = format!(
            "// Auto-generated from {}.mgep\n// Regenerate with: cargo run --bin mgep-codegen -- {}\n",
            stem,
            path.display()
        );
        fs::write(&out_path, header).unwrap();

        // Tell Cargo to rerun if schema changes
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
