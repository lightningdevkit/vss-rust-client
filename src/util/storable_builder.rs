use crate::crypto::chacha20poly1305::ChaCha20Poly1305;
use crate::types::{EncryptionMetadata, PlaintextBlob, Storable};
use ::prost::Message;
use std::borrow::Borrow;
use std::io;
use std::io::{Error, ErrorKind};

/// [`StorableBuilder`] is a utility to build and deconstruct [`Storable`] objects.
/// It provides client-side Encrypt-then-MAC using ChaCha20-Poly1305.
pub struct StorableBuilder<T: EntropySource> {
	data_encryption_key: [u8; 32],
	entropy_source: T,
}

impl<T: EntropySource> StorableBuilder<T> {
	/// Constructs a new instance.
	pub fn new(data_encryption_key: [u8; 32], entropy_source: T) -> StorableBuilder<T> {
		Self { data_encryption_key, entropy_source }
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

impl<T: EntropySource> StorableBuilder<T> {
	/// Creates a [`Storable`] that can be serialized and stored as `value` in [`PutObjectRequest`].
	///
	/// Uses ChaCha20 for encrypting `input` and Poly1305 for generating a mac/tag.
	///
	/// Refer to docs on [`Storable`] for more information.
	///
	/// [`PutObjectRequest`]: crate::types::PutObjectRequest
	pub fn build(&self, input: Vec<u8>, version: i64) -> Storable {
		let mut nonce = vec![0u8; 12];
		self.entropy_source.fill_bytes(&mut nonce[4..]);

		let mut data_blob = PlaintextBlob { value: input, version }.encode_to_vec();

		let mut cipher = ChaCha20Poly1305::new(&self.data_encryption_key, &nonce, &[]);
		let mut tag = vec![0u8; 16];
		cipher.encrypt_inplace(&mut data_blob, &mut tag);
		Storable {
			data: data_blob,
			encryption_metadata: Some(EncryptionMetadata {
				nonce,
				tag,
				cipher_format: CHACHA20_CIPHER_NAME.to_string(),
			}),
		}
	}

	/// Deconstructs the provided [`Storable`] and returns constituent decrypted data and its
	/// corresponding version as stored at the time of [`PutObjectRequest`].
	///
	/// [`PutObjectRequest`]: crate::types::PutObjectRequest
	pub fn deconstruct(&self, mut storable: Storable) -> io::Result<(Vec<u8>, i64)> {
		let encryption_metadata = storable.encryption_metadata.unwrap();
		let mut cipher =
			ChaCha20Poly1305::new(&self.data_encryption_key, &encryption_metadata.nonce, &[]);

		cipher
			.decrypt_inplace(&mut storable.data, encryption_metadata.tag.borrow())
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
		let storable_builder = StorableBuilder {
			data_encryption_key: data_key,
			entropy_source: test_entropy_provider,
		};
		let expected_data = b"secret".to_vec();
		let expected_version = 8;
		let storable = storable_builder.build(expected_data.clone(), expected_version);

		let (actual_data, actual_version) = storable_builder.deconstruct(storable).unwrap();
		assert_eq!(actual_data, expected_data);
		assert_eq!(actual_version, expected_version);
	}
}
