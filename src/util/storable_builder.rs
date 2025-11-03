use crate::types::{EncryptionMetadata, PlaintextBlob, Storable};
use ::prost::Message;

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

use std::io;
use std::io::{Error, ErrorKind};

/// [`StorableBuilder`] is a utility to build and deconstruct [`Storable`] objects.
///
/// It provides client-side Encrypt-then-MAC using ChaCha20-Poly1305.
pub struct StorableBuilder<T: EntropySource> {
	entropy_source: T,
}

impl<T: EntropySource> StorableBuilder<T> {
	/// Constructs a new instance.
	pub fn new(entropy_source: T) -> StorableBuilder<T> {
		Self { entropy_source }
	}
}

/// A trait representing a source for generating entropy/randomness.
pub trait EntropySource {
	/// Fills a buffer with random bytes.
	///
	/// This method must generate the specified number of random bytes and write them into the given
	/// buffer. It is expected that this method will be cryptographically secure and suitable for use
	/// cases requiring strong randomness, such as generating nonces or secret keys.
	fn fill_bytes(&self, buffer: &mut [u8]);
}

const CHACHA20_CIPHER_NAME: &'static str = "ChaCha20Poly1305";
const TAG_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;

impl<T: EntropySource> StorableBuilder<T> {
	/// Creates a [`Storable`] that can be serialized and stored as `value` in [`PutObjectRequest`].
	///
	/// Uses ChaCha20 for encrypting `input` and Poly1305 for generating a mac/tag with associated
	/// data `aad` (usually the storage key).
	///
	/// Refer to docs on [`Storable`] for more information.
	///
	/// [`PutObjectRequest`]: crate::types::PutObjectRequest
	pub fn build(
		&self, input: Vec<u8>, version: i64, data_encryption_key: &[u8; 32], aad: &[u8],
	) -> Storable {
		let mut nonce = [0u8; NONCE_LENGTH];
		self.entropy_source.fill_bytes(&mut nonce[4..]);

		let mut data_blob = PlaintextBlob { value: input, version }.encode_to_vec();

		let cipher = ChaCha20Poly1305::new(Key::new(*data_encryption_key), Nonce::new(nonce));
		let tag = cipher.encrypt(&mut data_blob, Some(aad));
		Storable {
			data: data_blob,
			encryption_metadata: Some(EncryptionMetadata {
				nonce: nonce.to_vec(),
				tag: tag.to_vec(),
				cipher_format: CHACHA20_CIPHER_NAME.to_string(),
			}),
		}
	}

	/// Deconstructs the provided [`Storable`] and returns constituent decrypted data and its
	/// corresponding version as stored at the time of [`PutObjectRequest`].
	///
	/// [`PutObjectRequest`]: crate::types::PutObjectRequest
	pub fn deconstruct(
		&self, mut storable: Storable, data_encryption_key: &[u8; 32], aad: &[u8],
	) -> io::Result<(Vec<u8>, i64)> {
		let encryption_metadata = storable
			.encryption_metadata
			.ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid Metadata"))?;

		if encryption_metadata.nonce.len() != NONCE_LENGTH {
			return Err(Error::new(ErrorKind::InvalidData, "Invalid Metadata"));
		}
		let mut nonce = [0u8; NONCE_LENGTH];
		nonce.copy_from_slice(&encryption_metadata.nonce);

		let cipher = ChaCha20Poly1305::new(Key::new(*data_encryption_key), Nonce::new(nonce));

		if encryption_metadata.tag.len() != TAG_LENGTH {
			return Err(Error::new(ErrorKind::InvalidData, "Invalid Metadata"));
		}
		let mut tag = [0u8; TAG_LENGTH];
		tag.copy_from_slice(&encryption_metadata.tag);

		cipher
			.decrypt(&mut storable.data, tag, Some(aad))
			.map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid Tag"))?;

		let data_blob = PlaintextBlob::decode(&storable.data[..])
			.map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
		Ok((data_blob.value, data_blob.version))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	pub struct TestEntropyProvider;
	impl EntropySource for TestEntropyProvider {
		/// A terrible implementation which fills a buffer with bytes from a simple counter for testing
		/// purposes.
		fn fill_bytes(&self, buffer: &mut [u8]) {
			for (i, byte) in buffer.iter_mut().enumerate() {
				*byte = (i % 256) as u8;
			}
		}
	}

	#[test]
	fn encrypt_decrypt() {
		let test_entropy_provider = TestEntropyProvider;
		let mut data_key = [0u8; 32];
		test_entropy_provider.fill_bytes(&mut data_key);
		let storable_builder = StorableBuilder::new(test_entropy_provider);
		let expected_data = b"secret".to_vec();
		let expected_version = 8;
		let aad = b"A";
		let storable =
			storable_builder.build(expected_data.clone(), expected_version, &data_key, aad);

		let (actual_data, actual_version) =
			storable_builder.deconstruct(storable, &data_key, aad).unwrap();
		assert_eq!(actual_data, expected_data);
		assert_eq!(actual_version, expected_version);
	}

	#[test]
	fn decrypt_key_mismatch_fails() {
		let test_entropy_provider = TestEntropyProvider;
		let mut data_key = [0u8; 32];
		test_entropy_provider.fill_bytes(&mut data_key);
		let storable_builder = StorableBuilder::new(test_entropy_provider);

		let expected_data_a = b"secret_a".to_vec();
		let expected_version_a = 8;
		let aad_a = b"A";
		let storable_a =
			storable_builder.build(expected_data_a.clone(), expected_version_a, &data_key, aad_a);

		let expected_data_b = b"secret_b".to_vec();
		let expected_version_b = 8;
		let aad_b = b"B";
		let storable_b =
			storable_builder.build(expected_data_b.clone(), expected_version_b, &data_key, aad_b);

		let (actual_data, actual_version) =
			storable_builder.deconstruct(storable_a, &data_key, aad_a).unwrap();
		assert_eq!(actual_data, expected_data_a);
		assert_eq!(actual_version, expected_version_a);
		assert!(storable_builder.deconstruct(storable_b, &data_key, aad_a).is_err());
	}

	#[test]
	fn decrypt_v031_storable() {
		// This test ensures backward compatibility with v0.3.1 Storables.
		// In v0.3.1, the AAD was hardcoded to empty (&[]), so we must pass an empty AAD
		// when decrypting v0.3.1 Storables to maintain compatibility.
		let test_entropy_provider = TestEntropyProvider;
		let mut data_key = [0u8; 32];
		test_entropy_provider.fill_bytes(&mut data_key);
		let storable_builder = StorableBuilder::new(test_entropy_provider);

		// This Storable was generated using v0.3.1 with:
		// - data: b"backward_compat_test_data"
		// - version: 42
		// - data_encryption_key: same as data_key above
		// - aad: &[] (hardcoded in v0.3.1)
		let v031_serialized = vec![
			0x0a, 0x1d, 0x32, 0x19, 0xe9, 0xfb, 0x45, 0xd7, 0x42, 0xf5, 0x6c, 0x40, 0x1b, 0x74,
			0x13, 0xe7, 0xae, 0x07, 0xfd, 0x81, 0xe1, 0x43, 0x3a, 0xf2, 0x86, 0x3c, 0xe8, 0x8f,
			0x01, 0xf8, 0x6c, 0x12, 0x32, 0x0a, 0x10, 0x43, 0x68, 0x61, 0x43, 0x68, 0x61, 0x32,
			0x30, 0x50, 0x6f, 0x6c, 0x79, 0x31, 0x33, 0x30, 0x35, 0x12, 0x0c, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x1a, 0x10, 0x87, 0x16, 0x35,
			0x02, 0x26, 0x1e, 0x30, 0xec, 0x7c, 0xf1, 0x4b, 0x79, 0x70, 0xa2, 0x41, 0x16,
		];

		let v031_storable = Storable::decode(&v031_serialized[..]).unwrap();

		// Decrypt with empty AAD to match v0.3.1 behavior
		let (actual_data, actual_version) =
			storable_builder.deconstruct(v031_storable, &data_key, &[]).unwrap();

		assert_eq!(actual_data, b"backward_compat_test_data".to_vec());
		assert_eq!(actual_version, 42);
	}
}
