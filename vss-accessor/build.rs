extern crate prost_build;

use std::fs;
use std::fs::File;
use std::path::Path;

fn main() {
	download_file(
		"https://raw.githubusercontent.com/lightningdevkit/vss-server/main/app/src/main/proto/vss.proto",
		"src/proto/vss.proto",
	)
	.unwrap();

	prost_build::compile_protos(&["src/proto/vss.proto"], &["src/"]).unwrap();
}

fn download_file(url: &str, save_to: &str) -> Result<(), Box<dyn std::error::Error>> {
	let mut response = reqwest::blocking::get(url)?;
	fs::create_dir_all(Path::new(save_to).parent().unwrap())?;
	let mut out_file = File::create(save_to)?;
	response.copy_to(&mut out_file)?;
	Ok(())
}
