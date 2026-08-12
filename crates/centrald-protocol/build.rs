#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        // SAFETY: Cargo build scripts execute single-threaded for this package before codegen.
        // Setting PROTOC only selects the vendored executable for this child build process.
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["../../proto/centrald/v1/centrald.proto"],
            &["../../proto"],
        )?;

    println!("cargo:rerun-if-changed=../../proto/centrald/v1/centrald.proto");
    Ok(())
}
