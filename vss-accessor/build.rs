extern crate prost_build;

use std::fs::File;
use std::path::Path;
use std::{env, fs};

/// To generate updated proto objects:
/// 1. Place `vss.proto` file in `src/proto/`
/// 2. run `cargo build --features=genproto`
fn main() {
	#[cfg(feature = "genproto")]
	generate_protos();
}

#[cfg(feature = "genproto")]
fn generate_protos() {
	download_file(
				"https://raw.githubusercontent.com/lightningdevkit/vss-server/ff4b5fc6a079ed8719eb8be7ec35ca1d01c1cc55/app/src/main/proto/vss.proto",
				"src/proto/vss.proto",
		).unwrap();

	prost_build::compile_protos(&["src/proto/vss.proto"], &["src/"]).unwrap();
	let from_path = Path::new(&env::var("OUT_DIR").unwrap()).join("org.vss.rs");
	fs::copy(from_path, "src/generated-src/org.vss.rs").unwrap();
}

#[cfg(feature = "genproto")]
fn download_file(url: &str, save_to: &str) -> Result<(), Box<dyn std::error::Error>> {
	let mut response = reqwest::blocking::get(url)?;
	fs::create_dir_all(Path::new(save_to).parent().unwrap())?;
	let mut out_file = File::create(save_to)?;
	response.copy_to(&mut out_file)?;
	Ok(())
}
