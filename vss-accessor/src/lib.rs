use ::prost::Message;
use reqwest;
use reqwest::Client;
use std::error::Error;

use crate::vss::{
	GetObjectRequest, GetObjectResponse, KeyValue, ListKeyVersionsRequest, ListKeyVersionsResponse, PutObjectRequest,
	PutObjectResponse,
};
use crate::vss_error::VssError;

pub mod vss_error;

pub mod vss {
	include!("generated-src/org.vss.rs");
}

pub struct VssAccessor {
	base_url: String,
	client: Client,
}

impl VssAccessor {
	pub fn new(base_url: &str) -> Result<Self, Box<dyn Error>> {
		let client = Client::new();
		Ok(Self { base_url: String::from(base_url), client })
	}

	pub async fn get(&self, store: String, key: String) -> Result<GetObjectResponse, VssError> {
		let url = format!("{}/getObject", self.base_url);

		let request = GetObjectRequest { store_id: store, key };

		let response_raw = self.client.post(url).body(request.encode_to_vec()).send().await?;
		let status = response_raw.status();
		let payload = response_raw.bytes().await?;

		if status.is_success() {
			let response = GetObjectResponse::decode(&payload[..])?;
			Ok(response)
		} else {
			Err(VssError::new(status, payload))
		}
	}

	pub async fn put(
		&self, store: String, global_version: Option<i64>, key: String, version: i64, value: &[u8],
	) -> Result<PutObjectResponse, VssError> {
		let kv = KeyValue { key: String::from(key), version, value: value.to_vec() };
		return self.put_tx(store, global_version, vec![kv]).await;
	}

	pub async fn put_tx(
		&self, store: String, global_version: Option<i64>, transaction_items: Vec<KeyValue>,
	) -> Result<PutObjectResponse, VssError> {
		let url = format!("{}/putObjects", self.base_url);

		let request = PutObjectRequest { store_id: store, global_version, transaction_items };

		let response_raw = self.client.post(url).body(request.encode_to_vec()).send().await?;
		let status = response_raw.status();
		let payload = response_raw.bytes().await?;

		if status.is_success() {
			let response = PutObjectResponse::decode(&payload[..])?;
			Ok(response)
		} else {
			Err(VssError::new(status, payload))
		}
	}

	pub async fn list_key_versions(
		&self, store: String, key_prefix: String, page_size: Option<i32>, page_token: Option<String>,
	) -> Result<ListKeyVersionsResponse, VssError> {
		let url = format!("{}/listKeyVersions", self.base_url);

		let request = ListKeyVersionsRequest { store_id: store, key_prefix: Some(key_prefix), page_size, page_token };

		let response_raw = self.client.post(url).body(request.encode_to_vec()).send().await?;
		let status = response_raw.status();
		let payload = response_raw.bytes().await?;

		if status.is_success() {
			let response = ListKeyVersionsResponse::decode(&payload[..])?;
			Ok(response)
		} else {
			Err(VssError::new(status, payload))
		}
	}
}
