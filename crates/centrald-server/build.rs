//! Stages the built web app (`web/dist`) for embedding. Without a build, a
//! placeholder page explains how to produce one.

use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("ui");
    let dist = manifest.join("../../web/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    println!("cargo:rerun-if-env-changed=CENTRALD_REQUIRE_UI");

    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap_or_else(|e| panic!("create {}: {e}", out.display()));
    if dist.join("index.html").is_file() {
        copy_tree(&dist, &out);
    } else {
        assert!(
            std::env::var_os("CENTRALD_REQUIRE_UI").is_none(),
            "web/dist is missing; run `npm run build:web` first"
        );
        std::fs::write(out.join("index.html"), PLACEHOLDER)
            .unwrap_or_else(|e| panic!("write placeholder: {e}"));
    }
}

fn copy_tree(from: &Path, to: &Path) {
    let entries =
        std::fs::read_dir(from).unwrap_or_else(|e| panic!("read {}: {e}", from.display()));
    for entry in entries.flatten() {
        let source = entry.path();
        let target = to.join(entry.file_name());
        println!("cargo:rerun-if-changed={}", source.display());
        if source.is_dir() {
            std::fs::create_dir_all(&target).unwrap_or_else(|e| panic!("mkdir: {e}"));
            copy_tree(&source, &target);
        } else {
            std::fs::copy(&source, &target)
                .unwrap_or_else(|e| panic!("copy {}: {e}", source.display()));
        }
    }
}

const PLACEHOLDER: &str = "<!doctype html><meta charset=utf-8><title>CentralD</title>\
<p>This server was built without its web app. Run <code>npm run build:web</code> \
and rebuild the server.</p>";
