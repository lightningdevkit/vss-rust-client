extern crate prost_build;

use std::fs;
use std::fs::File;
use std::path::Path;

// Use this test-case to generate rust-proto objects from proto file.
// 1. Enable test case by commenting/removing `#[ignore]`
// 2. Run command :
// ```
// cargo build && OUT_DIR=../target/tmp/ cargo test generate_protos -- --exact
// ```
#[test]
#[ignore]
fn generate_protos() {
	download_file(
        "https://raw.githubusercontent.com/lightningdevkit/vss-server/ff4b5fc6a079ed8719eb8be7ec35ca1d01c1cc55/app/src/main/proto/vss.proto",
        "src/proto/vss.proto",
    ).unwrap();

	prost_build::compile_protos(&["src/proto/vss.proto"], &["src/"]).unwrap();
	fs::copy(concat!(env!("OUT_DIR"), "/org.vss.rs"), "src/generated-src/org.vss.rs").unwrap();
}

fn download_file(url: &str, save_to: &str) -> Result<(), Box<dyn std::error::Error>> {
	let mut response = reqwest::blocking::get(url)?;
	fs::create_dir_all(Path::new(save_to).parent().unwrap())?;
	let mut out_file = File::create(save_to)?;
	response.copy_to(&mut out_file)?;
	Ok(())
}
