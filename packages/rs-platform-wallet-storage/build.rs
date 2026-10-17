//! Re-run the build whenever any file under `migrations/` or
//! `migrations_fork/` changes.
//!
//! `refinery::embed_migrations!("./migrations")` is a proc-macro
//! evaluated at compile time. Cargo does not, by default, track
//! file-system reads inside proc macros — adding or editing a file
//! under `migrations/` will not trigger a rebuild of crates that
//! depend on this one until a source file in `src/` is touched.
//! Emitting `rerun-if-changed` directives below closes that gap.

use std::path::Path;

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    for dir in ["migrations", "migrations_fork"] {
        let migrations_dir = Path::new(&manifest).join(dir);
        println!("cargo:rerun-if-changed={}", migrations_dir.display());
        if let Ok(entries) = std::fs::read_dir(&migrations_dir) {
            for entry in entries.flatten() {
                println!("cargo:rerun-if-changed={}", entry.path().display());
            }
        }
    }
}
