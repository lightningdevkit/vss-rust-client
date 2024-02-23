// ring has a garbage API so its use is avoided, but rust-crypto doesn't have RFC-variant poly1305
// Instead, we steal rust-crypto's implementation and tweak it to match the RFC.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
//
// This is a port of Andrew Moons poly1305-donna
// https://github.com/floodyberry/poly1305-donna

mod real_chachapoly {
	use crate::crypto::chacha20::ChaCha20;
	use crate::crypto::poly1305::Poly1305;
	use core::ptr::{read_volatile, write_volatile};

	#[derive(Clone, Copy)]
	pub struct ChaCha20Poly1305 {
		cipher: ChaCha20,
		mac: Poly1305,
		finished: bool,
		data_len: usize,
		aad_len: u64,
	}

	#[allow(dead_code, unused)]
	impl ChaCha20Poly1305 {
		#[inline]
		fn pad_mac_16(mac: &mut Poly1305, len: usize) {
			if len % 16 != 0 {
				mac.input(&[0; 16][0..16 - (len % 16)]);
			}
		}
		pub fn new(key: &[u8], nonce: &[u8], aad: &[u8]) -> ChaCha20Poly1305 {
			assert!(key.len() == 16 || key.len() == 32);
			assert!(nonce.len() == 12);

			// Ehh, I'm too lazy to *also* tweak ChaCha20 to make it RFC-compliant
			assert!(nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0);

			let mut cipher = ChaCha20::new(key, &nonce[4..]);
			let mut mac_key = [0u8; 64];
			let zero_key = [0u8; 64];
			cipher.process(&zero_key, &mut mac_key);

			let mut mac = Poly1305::new(&mac_key[..32]);
			mac.input(aad);
			ChaCha20Poly1305::pad_mac_16(&mut mac, aad.len());

			ChaCha20Poly1305 {
				cipher,
				mac,
				finished: false,
				data_len: 0,
				aad_len: aad.len() as u64,
			}
		}

		pub fn encrypt(&mut self, input: &[u8], output: &mut [u8], out_tag: &mut [u8]) {
			assert!(input.len() == output.len());
			assert!(self.finished == false);
			self.cipher.process(input, output);
			self.data_len += input.len();
			self.mac.input(output);
			ChaCha20Poly1305::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn encrypt_inplace(&mut self, input_output: &mut [u8], out_tag: &mut [u8]) {
			assert!(self.finished == false);
			self.encrypt_in_place(input_output);
			self.finish_and_get_tag(out_tag);
		}

		pub fn decrypt_inplace(&mut self, input_output: &mut [u8], tag: &[u8]) -> bool {
			assert!(self.finished == false);
			self.decrypt_in_place(input_output);
			self.finish_and_check_tag(tag)
		}

		// Encrypt `input_output` in-place. To finish and calculate the tag, use `finish_and_get_tag`
		// below.
		pub(super) fn encrypt_in_place(&mut self, input_output: &mut [u8]) {
			debug_assert!(self.finished == false);
			self.cipher.process_in_place(input_output);
			self.data_len += input_output.len();
			self.mac.input(input_output);
		}

		// If we were previously encrypting with `encrypt_in_place`, this method can be used to finish
		// encrypting and calculate the tag.
		pub(super) fn finish_and_get_tag(&mut self, out_tag: &mut [u8]) {
			debug_assert!(self.finished == false);
			ChaCha20Poly1305::pad_mac_16(&mut self.mac, self.data_len);
			self.finished = true;
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());
			self.mac.raw_result(out_tag);
		}

		pub fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> bool {
			assert!(input.len() == output.len());
			assert!(self.finished == false);

			self.finished = true;

			self.mac.input(input);

			self.data_len += input.len();
			ChaCha20Poly1305::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());

			let mut calc_tag = [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			if ChaCha20Poly1305::fixed_time_eq(&calc_tag, tag) {
				self.cipher.process(input, output);
				true
			} else {
				false
			}
		}

		// Decrypt in place, without checking the tag. Use `finish_and_check_tag` to check it
		// later when decryption finishes.
		//
		// Should never be `pub` because the public API should always enforce tag checking.
		pub(super) fn decrypt_in_place(&mut self, input_output: &mut [u8]) {
			debug_assert!(self.finished == false);
			self.mac.input(input_output);
			self.data_len += input_output.len();
			self.cipher.process_in_place(input_output);
		}

		// If we were previously decrypting with `decrypt_in_place`, this method must be used to finish
		// decrypting and check the tag. Returns whether the tag is valid.
		pub(super) fn finish_and_check_tag(&mut self, tag: &[u8]) -> bool {
			debug_assert!(self.finished == false);
			self.finished = true;
			ChaCha20Poly1305::pad_mac_16(&mut self.mac, self.data_len);
			self.mac.input(&self.aad_len.to_le_bytes());
			self.mac.input(&(self.data_len as u64).to_le_bytes());

			let mut calc_tag = [0u8; 16];
			self.mac.raw_result(&mut calc_tag);
			if ChaCha20Poly1305::fixed_time_eq(&calc_tag, tag) {
				true
			} else {
				false
			}
		}
		pub(super) fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
			assert!(a.len() == b.len());
			let count = a.len();
			let lhs = &a[..count];
			let rhs = &b[..count];

			let mut r: u8 = 0;
			for i in 0..count {
				let mut rs = unsafe { read_volatile(&r) };
				rs |= lhs[i] ^ rhs[i];
				unsafe {
					write_volatile(&mut r, rs);
				}
			}
			{
				let mut t = unsafe { read_volatile(&r) };
				t |= t >> 4;
				unsafe {
					write_volatile(&mut r, t);
				}
			}
			{
				let mut t = unsafe { read_volatile(&r) };
				t |= t >> 2;
				unsafe {
					write_volatile(&mut r, t);
				}
			}
			{
				let mut t = unsafe { read_volatile(&r) };
				t |= t >> 1;
				unsafe {
					write_volatile(&mut r, t);
				}
			}
			unsafe { (read_volatile(&r) & 1) == 0 }
		}
	}
}

pub use self::real_chachapoly::ChaCha20Poly1305;
