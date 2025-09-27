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
}
