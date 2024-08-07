use std::io::{Error, ErrorKind};

use base64::prelude::BASE64_STANDARD_NO_PAD;
use base64::Engine;
use bitcoin_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};

use crate::crypto::chacha20poly1305::ChaCha20Poly1305;

/// [`KeyObfuscator`] is a utility to obfuscate and deobfuscate storage
/// keys to be used for VSS operations.
///
/// It provides client-side deterministic encryption of given keys using ChaCha20-Poly1305.
pub struct KeyObfuscator {
	obfuscation_key: [u8; 32],
	hashing_key: [u8; 32],
}

impl KeyObfuscator {
	/// Constructs a new instance.
	pub fn new(obfuscation_master_key: [u8; 32]) -> KeyObfuscator {
		let (obfuscation_key, hashing_key) =
			Self::derive_obfuscation_and_hashing_keys(&obfuscation_master_key);
		Self { obfuscation_key, hashing_key }
	}
}

const TAG_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;

impl KeyObfuscator {
	/// Obfuscates the given key.
	pub fn obfuscate(&self, key: &str) -> String {
		let key_bytes = key.as_bytes();
		let mut ciphertext =
			Vec::with_capacity(key_bytes.len() + TAG_LENGTH + NONCE_LENGTH + TAG_LENGTH);
		ciphertext.extend_from_slice(&key_bytes);

		// Encrypt key in-place using a synthetic nonce.
		let (mut nonce, tag) = self.encrypt(&mut ciphertext, key.as_bytes());

		// Wrap the synthetic nonce to store along-side key.
		let (_, nonce_tag) = self.encrypt(&mut nonce, &ciphertext);

		debug_assert_eq!(tag.len(), TAG_LENGTH);
		ciphertext.extend_from_slice(&tag);
		debug_assert_eq!(nonce.len(), NONCE_LENGTH);
		ciphertext.extend_from_slice(&nonce);
		debug_assert_eq!(nonce_tag.len(), TAG_LENGTH);
		ciphertext.extend_from_slice(&nonce_tag);
		BASE64_STANDARD_NO_PAD.encode(ciphertext)
	}

	/// Deobfuscates the given obfuscated_key.
	pub fn deobfuscate(&self, obfuscated_key: &str) -> Result<String, Error> {
		let obfuscated_key_bytes = BASE64_STANDARD_NO_PAD.decode(obfuscated_key).map_err(|e| {
			let msg = format!(
				"Failed to decode base64 while deobfuscating key: {}, Error: {}",
				obfuscated_key, e
			);
			Error::new(ErrorKind::InvalidData, msg)
		})?;

		if obfuscated_key_bytes.len() < TAG_LENGTH + NONCE_LENGTH + TAG_LENGTH {
			let msg = format!(
				"Failed to deobfuscate, obfuscated_key was of invalid length. \
			Obfuscated key should at least have {} bytes, found: {}. Key: {}.",
				(TAG_LENGTH + NONCE_LENGTH + TAG_LENGTH),
				obfuscated_key_bytes.len(),
				obfuscated_key
			);
			return Err(Error::new(ErrorKind::InvalidData, msg));
		}

		// Split obfuscated_key into ciphertext, tag(for ciphertext), wrapped_nonce, tag(for wrapped_nonce).
		let (ciphertext, remaining) = obfuscated_key_bytes
			.split_at(obfuscated_key_bytes.len() - TAG_LENGTH - NONCE_LENGTH - TAG_LENGTH);
		let (tag, remaining) = remaining.split_at(TAG_LENGTH);
		let (wrapped_nonce_bytes, wrapped_nonce_tag) = remaining.split_at(NONCE_LENGTH);
		debug_assert_eq!(wrapped_nonce_tag.len(), TAG_LENGTH);

		// Unwrap wrapped_nonce to get nonce.
		let mut wrapped_nonce = [0u8; NONCE_LENGTH];
		wrapped_nonce.clone_from_slice(&wrapped_nonce_bytes);
		self.decrypt(&mut wrapped_nonce, ciphertext, wrapped_nonce_tag).map_err(|_| {
			let msg = format!(
				"Failed to decrypt wrapped nonce, for key: {}, Invalid Tag.",
				obfuscated_key
			);
			Error::new(ErrorKind::InvalidData, msg)
		})?;

		// Decrypt ciphertext using nonce.
		let mut cipher = ChaCha20Poly1305::new(&self.obfuscation_key, &wrapped_nonce, &[]);
		let mut ciphertext = ciphertext.to_vec();
		cipher.decrypt_inplace(&mut ciphertext, tag).map_err(|_| {
			let msg = format!("Failed to decrypt key: {}, Invalid Tag.", obfuscated_key);
			Error::new(ErrorKind::InvalidData, msg)
		})?;

		let original_key = String::from_utf8(ciphertext).map_err(|e| {
			let msg = format!(
				"Input was not valid utf8 while deobfuscating key: {}, Error: {}",
				obfuscated_key, e
			);
			Error::new(ErrorKind::InvalidData, msg)
		})?;
		Ok(original_key)
	}

	/// Encrypts the given plaintext in-place using a HMAC generated nonce.
	fn encrypt(
		&self, mut plaintext: &mut [u8], initial_nonce_material: &[u8],
	) -> ([u8; 12], [u8; 16]) {
		let nonce = self.generate_synthetic_nonce(initial_nonce_material);
		let mut cipher = ChaCha20Poly1305::new(&self.obfuscation_key, &nonce, &[]);
		let mut tag = [0u8; TAG_LENGTH];
		cipher.encrypt_inplace(&mut plaintext, &mut tag);
		(nonce, tag)
	}

	/// Decrypts the given ciphertext in-place using a HMAC generated nonce.
	fn decrypt(
		&self, mut ciphertext: &mut [u8], initial_nonce_material: &[u8], tag: &[u8],
	) -> Result<(), ()> {
		let nonce = self.generate_synthetic_nonce(initial_nonce_material);
		let mut cipher = ChaCha20Poly1305::new(&self.obfuscation_key, &nonce, &[]);
		cipher.decrypt_inplace(&mut ciphertext, tag)
	}

	/// Generate a HMAC based nonce using provided `initial_nonce_material`.
	fn generate_synthetic_nonce(&self, initial_nonce_material: &[u8]) -> [u8; 12] {
		let hmac = Self::hkdf(&self.hashing_key, initial_nonce_material);
		let mut nonce = [0u8; NONCE_LENGTH];
		nonce[4..].copy_from_slice(&hmac[..8]);
		nonce
	}

	/// Derives the obfuscation and hashing keys from the master key.
	fn derive_obfuscation_and_hashing_keys(
		obfuscation_master_key: &[u8; 32],
	) -> ([u8; 32], [u8; 32]) {
		let prk = Self::hkdf(obfuscation_master_key, "pseudo_random_key".as_bytes());
		let k1 = Self::hkdf(&prk, "obfuscation_key".as_bytes());
		let k2 = Self::hkdf(&prk, &[&k1[..], "hashing_key".as_bytes()].concat());
		(k1, k2)
	}
	fn hkdf(initial_key_material: &[u8], salt: &[u8]) -> [u8; 32] {
		let mut engine = HmacEngine::<sha256::Hash>::new(salt);
		engine.input(initial_key_material);
		Hmac::from_engine(engine).to_byte_array()
	}
}

#[cfg(test)]
mod tests {
	use crate::util::key_obfuscator::KeyObfuscator;

	#[test]
	fn obfuscate_deobfuscate_deterministic() {
		let obfuscation_master_key = [42u8; 32];
		let key_obfuscator = KeyObfuscator::new(obfuscation_master_key);
		let expected_key = "a_semi_secret_key";
		let obfuscated_key = key_obfuscator.obfuscate(expected_key);

		let actual_key = key_obfuscator.deobfuscate(obfuscated_key.as_str()).unwrap();
		assert_eq!(actual_key, expected_key);
		assert_eq!(
			obfuscated_key,
			"cMoet5WTvl0nYds+VW7JPCtXUq24DtMG2dR9apAi/T5jy8eNIEyDrUAJBS4geeUuX+XGXPqlizIByOip2g"
		);
	}

	use proptest::prelude::*;

	proptest! {
		#[test]
		fn obfuscate_deobfuscate_proptest(expected_key in "[a-zA-Z0-9_!@#,;:%\\s\\*\\$\\^&\\(\\)\\[\\]\\{\\}\\.]*", obfuscation_master_key in any::<[u8; 32]>()) {
			let key_obfuscator = KeyObfuscator::new(obfuscation_master_key);
			let obfuscated_key = key_obfuscator.obfuscate(&expected_key);
			let actual_key = key_obfuscator.deobfuscate(obfuscated_key.as_str()).unwrap();
			assert_eq!(actual_key, expected_key);
		}
	}
}
