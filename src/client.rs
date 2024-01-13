use prost::Message;
use reqwest;
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use std::default::Default;

use crate::error::VssError;
use crate::types::{
	DeleteObjectRequest, DeleteObjectResponse, GetObjectRequest, GetObjectResponse, ListKeyVersionsRequest,
	ListKeyVersionsResponse, PutObjectRequest, PutObjectResponse,
};
use crate::util::retry::{retry, RetryPolicy};

const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

/// Thin-client to access a hosted instance of Versioned Storage Service (VSS).
/// The provided [`VssClient`] API is minimalistic and is congruent to the VSS server-side API.
#[derive(Clone)]
pub struct VssClient<R>
where
	R: RetryPolicy<E = VssError>,
{
	base_url: String,
	client: Client,
	retry_policy: R,
}

impl<R: RetryPolicy<E = VssError>> VssClient<R> {
	/// Constructs a [`VssClient`] using `base_url` as the VSS server endpoint.
	pub fn new(base_url: &str, retry_policy: R) -> Self {
		let client = Client::new();
		Self::from_client(base_url, client, retry_policy)
	}

	/// Constructs a [`VssClient`] from a given [`reqwest::Client`], using `base_url` as the VSS server endpoint.
	pub fn from_client(base_url: &str, client: Client, retry_policy: R) -> Self {
		Self { base_url: String::from(base_url), client, retry_policy }
	}

	/// Returns the underlying base URL.
	pub fn base_url(&self) -> &str {
		&self.base_url
	}

	/// Fetches a value against a given `key` in `request`.
	/// Makes a service call to the `GetObject` endpoint of the VSS server.
	/// For API contract/usage, refer to docs for [`GetObjectRequest`] and [`GetObjectResponse`].
	pub async fn get_object(&self, request: &GetObjectRequest) -> Result<GetObjectResponse, VssError> {
		retry(
			|| async {
				let url = format!("{}/getObject", self.base_url);
				self.post_request(request, &url).await.and_then(|response: GetObjectResponse| {
					if response.value.is_none() {
						Err(VssError::InternalServerError(
							"VSS Server API Violation, expected value in GetObjectResponse but found none".to_string(),
						))
					} else {
						Ok(response)
					}
				})
			},
			&self.retry_policy,
		)
		.await
	}

	/// Writes multiple [`PutObjectRequest::transaction_items`] as part of a single transaction.
	/// Makes a service call to the `PutObject` endpoint of the VSS server, with multiple items.
	/// Items in the `request` are written in a single all-or-nothing transaction.
	/// For API contract/usage, refer to docs for [`PutObjectRequest`] and [`PutObjectResponse`].
	pub async fn put_object(&self, request: &PutObjectRequest) -> Result<PutObjectResponse, VssError> {
		retry(
			|| async {
				let url = format!("{}/putObjects", self.base_url);
				self.post_request(request, &url).await
			},
			&self.retry_policy,
		)
		.await
	}

	/// Deletes the given `key` and `value` in `request`.
	/// Makes a service call to the `DeleteObject` endpoint of the VSS server.
	/// For API contract/usage, refer to docs for [`DeleteObjectRequest`] and [`DeleteObjectResponse`].
	pub async fn delete_object(&self, request: &DeleteObjectRequest) -> Result<DeleteObjectResponse, VssError> {
		retry(
			|| async {
				let url = format!("{}/deleteObject", self.base_url);
				self.post_request(request, &url).await
			},
			&self.retry_policy,
		)
		.await
	}

	/// Lists keys and their corresponding version for a given [`ListKeyVersionsRequest::store_id`].
	/// Makes a service call to the `ListKeyVersions` endpoint of the VSS server.
	/// For API contract/usage, refer to docs for [`ListKeyVersionsRequest`] and [`ListKeyVersionsResponse`].
	pub async fn list_key_versions(
		&self, request: &ListKeyVersionsRequest,
	) -> Result<ListKeyVersionsResponse, VssError> {
		retry(
			|| async {
				let url = format!("{}/listKeyVersions", self.base_url);
				self.post_request(request, &url).await
			},
			&self.retry_policy,
		)
		.await
	}

	async fn post_request<Rq: Message, Rs: Message + Default>(&self, request: &Rq, url: &str) -> Result<Rs, VssError> {
		let request_body = request.encode_to_vec();
		let response_raw = self
			.client
			.post(url)
			.header(CONTENT_TYPE, APPLICATION_OCTET_STREAM)
			.body(request_body)
			.send()
			.await?;
		let status = response_raw.status();
		let payload = response_raw.bytes().await?;

		if status.is_success() {
			let response = Rs::decode(&payload[..])?;
			Ok(response)
		} else {
			Err(VssError::new(status, payload))
		}
	}
}
