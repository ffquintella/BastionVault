use std::{env, fs, path::Path};

use toml::Value;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cargo_toml_path = Path::new(&manifest_dir).join("Cargo.toml");
    let content = match fs::read_to_string(cargo_toml_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let cargo_toml: Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };

    if let Some(bin_table_value) = cargo_toml.get("bin") {
        if let Some(bin_table_array) = bin_table_value.as_array() {
            for bin_entry in bin_table_array {
                if let Some(bin_entry_table) = bin_entry.as_table() {
                    if let Some(name_value) = bin_entry_table.get("name") {
                        if let Some(name_str) = name_value.as_str() {
                            println!("cargo:rustc-env=CARGO_BIN_NAME={name_str}");
                        }
                    }
                }
            }
        }
    }
}
