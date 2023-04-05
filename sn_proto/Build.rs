use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(out_dir.clone())
        .compile(&["src/proto/messages.proto"], &["src/proto/"])
        .unwrap();

    println!("cargo:rerun-if-changed=src/proto/messages.proto");
}