#[cfg(test)]
mod tests {
	use mockito::{self, Matcher};
	use prost::Message;
	use reqwest::header::CONTENT_TYPE;
	use std::time::Duration;
	use vss_client::client::VssClient;
	use vss_client::error::VssError;

	use vss_client::types::{
		DeleteObjectRequest, DeleteObjectResponse, ErrorCode, ErrorResponse, GetObjectRequest, GetObjectResponse,
		KeyValue, ListKeyVersionsRequest, ListKeyVersionsResponse, PutObjectRequest, PutObjectResponse,
	};
	use vss_client::util::retry::{ExponentialBackoffRetryPolicy, RetryPolicy};

	const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";

	const GET_OBJECT_ENDPOINT: &'static str = "/getObject";
	const PUT_OBJECT_ENDPOINT: &'static str = "/putObjects";
	const DELETE_OBJECT_ENDPOINT: &'static str = "/deleteObject";
	const LIST_KEY_VERSIONS_ENDPOINT: &'static str = "/listKeyVersions";

	#[tokio::test]
	async fn test_get() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let get_request = GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() };
		let mock_response = GetObjectResponse {
			value: Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v2".to_vec() }),
			..Default::default()
		};

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", GET_OBJECT_ENDPOINT)
			.match_header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM)
			.match_body(get_request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssClient with the mock server URL.
		let client = VssClient::new(&base_url, retry_policy());

		let actual_result = client.get_object(&get_request).await.unwrap();

		let expected_result = &mock_response;
		assert_eq!(actual_result, *expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_put() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let request = PutObjectRequest {
			store_id: "store".to_string(),
			global_version: Some(4),
			transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
			delete_items: vec![],
		};
		let mock_response = PutObjectResponse::default();

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", PUT_OBJECT_ENDPOINT)
			.match_header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM)
			.match_body(request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssClient with the mock server URL.
		let vss_client = VssClient::new(&base_url, retry_policy());
		let actual_result = vss_client.put_object(&request).await.unwrap();

		let expected_result = &mock_response;
		assert_eq!(actual_result, *expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_delete() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let request = DeleteObjectRequest {
			store_id: "store".to_string(),
			key_value: Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }),
		};
		let mock_response = DeleteObjectResponse::default();

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", DELETE_OBJECT_ENDPOINT)
			.match_header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM)
			.match_body(request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssClient with the mock server URL.
		let vss_client = VssClient::new(&base_url, retry_policy());
		let actual_result = vss_client.delete_object(&request).await.unwrap();

		let expected_result = &mock_response;
		assert_eq!(actual_result, *expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_list_key_versions() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let request = ListKeyVersionsRequest {
			store_id: "store".to_string(),
			page_size: Some(5),
			page_token: None,
			key_prefix: Some("k".into()),
		};

		let mock_response = ListKeyVersionsResponse {
			key_versions: vec![
				KeyValue { key: "k1".to_string(), version: 3, value: vec![] },
				KeyValue { key: "k2".to_string(), version: 1, value: vec![] },
			],
			global_version: Some(4),
			next_page_token: Some("k2".into()),
		};

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", LIST_KEY_VERSIONS_ENDPOINT)
			.match_header(CONTENT_TYPE.as_str(), APPLICATION_OCTET_STREAM)
			.match_body(request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssClient with the mock server URL.
		let client = VssClient::new(&base_url, retry_policy());

		let actual_result = client.list_key_versions(&request).await.unwrap();

		let expected_result = &mock_response;
		assert_eq!(actual_result, *expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_no_such_key_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// NoSuchKeyError
		let error_response = ErrorResponse {
			error_code: ErrorCode::NoSuchKeyException.into(),
			message: "NoSuchKeyException".to_string(),
		};
		let mock_server = mockito::mock("POST", GET_OBJECT_ENDPOINT)
			.with_status(409)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_client
			.get_object(&GetObjectRequest { store_id: "store".to_string(), key: "non_existent_key".to_string() })
			.await;
		assert!(matches!(get_result.unwrap_err(), VssError::NoSuchKeyError { .. }));

		// Verify 1 request hit the server
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_get_response_without_value() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// GetObjectResponse with None value
		let mock_response = GetObjectResponse { value: None, ..Default::default() };
		let mock_server = mockito::mock("POST", GET_OBJECT_ENDPOINT)
			.with_status(200)
			.with_body(&mock_response.encode_to_vec())
			.create();

		let get_result = vss_client
			.get_object(&GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() })
			.await;
		assert!(matches!(get_result.unwrap_err(), VssError::InternalServerError { .. }));

		// Verify 1 request hit the server
		mock_server.expect(3).assert();
	}

	#[tokio::test]
	async fn test_invalid_request_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// Invalid Request Error
		let error_response = ErrorResponse {
			error_code: ErrorCode::InvalidRequestException.into(),
			message: "InvalidRequestException".to_string(),
		};
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(400)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_client
			.get_object(&GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() })
			.await;
		assert!(matches!(get_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		let put_result = vss_client
			.put_object(&PutObjectRequest {
				store_id: "store".to_string(),
				global_version: Some(4),
				transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
				delete_items: vec![],
			})
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		let delete_result = vss_client
			.delete_object(&DeleteObjectRequest {
				store_id: "store".to_string(),
				key_value: Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }),
			})
			.await;
		assert!(matches!(delete_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		let list_result = vss_client
			.list_key_versions(&ListKeyVersionsRequest {
				store_id: "store".to_string(),
				page_size: Some(5),
				page_token: None,
				key_prefix: Some("k".into()),
			})
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		// Verify 4 requests hit the server
		mock_server.expect(4).assert();
	}

	#[tokio::test]
	async fn test_auth_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// Invalid Request Error
		let error_response =
			ErrorResponse { error_code: ErrorCode::AuthException.into(), message: "AuthException".to_string() };
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(401)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_client
			.get_object(&GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() })
			.await;
		assert!(matches!(get_result.unwrap_err(), VssError::AuthError { .. }));

		let put_result = vss_client
			.put_object(&PutObjectRequest {
				store_id: "store".to_string(),
				global_version: Some(4),
				transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
				delete_items: vec![],
			})
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::AuthError { .. }));

		let delete_result = vss_client
			.delete_object(&DeleteObjectRequest {
				store_id: "store".to_string(),
				key_value: Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }),
			})
			.await;
		assert!(matches!(delete_result.unwrap_err(), VssError::AuthError { .. }));

		let list_result = vss_client
			.list_key_versions(&ListKeyVersionsRequest {
				store_id: "store".to_string(),
				page_size: Some(5),
				page_token: None,
				key_prefix: Some("k".into()),
			})
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::AuthError { .. }));

		// Verify 4 requests hit the server
		mock_server.expect(4).assert();
	}

	#[tokio::test]
	async fn test_conflict_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// Conflict Error
		let error_response =
			ErrorResponse { error_code: ErrorCode::ConflictException.into(), message: "ConflictException".to_string() };
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(409)
			.with_body(&error_response.encode_to_vec())
			.create();

		let put_result = vss_client
			.put_object(&PutObjectRequest {
				store_id: "store".to_string(),
				global_version: Some(4),
				transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
				delete_items: vec![],
			})
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::ConflictError { .. }));

		// Verify 1 requests hit the server
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_internal_server_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		// Internal Server Error
		let error_response = ErrorResponse {
			error_code: ErrorCode::InternalServerException.into(),
			message: "InternalServerException".to_string(),
		};
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(500)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_client
			.get_object(&GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() })
			.await;
		assert!(matches!(get_result.unwrap_err(), VssError::InternalServerError { .. }));

		let put_result = vss_client
			.put_object(&PutObjectRequest {
				store_id: "store".to_string(),
				global_version: Some(4),
				transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
				delete_items: vec![],
			})
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::InternalServerError { .. }));

		let delete_result = vss_client
			.delete_object(&DeleteObjectRequest {
				store_id: "store".to_string(),
				key_value: Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }),
			})
			.await;
		assert!(matches!(delete_result.unwrap_err(), VssError::InternalServerError { .. }));

		let list_result = vss_client
			.list_key_versions(&ListKeyVersionsRequest {
				store_id: "store".to_string(),
				page_size: Some(5),
				page_token: None,
				key_prefix: Some("k".into()),
			})
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::InternalServerError { .. }));

		// Verify 4 requests hit the server
		mock_server.expect(12).assert();
	}

	#[tokio::test]
	async fn test_internal_err_handling() {
		let base_url = mockito::server_url();
		let vss_client = VssClient::new(&base_url, retry_policy());

		let error_response = ErrorResponse { error_code: 999, message: "UnknownException".to_string() };
		let mut _mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(999)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_request = GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() };
		let get_result = vss_client.get_object(&get_request).await;
		assert!(matches!(get_result.unwrap_err(), VssError::InternalError { .. }));

		let put_request = PutObjectRequest {
			store_id: "store".to_string(),
			global_version: Some(4),
			transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
			delete_items: vec![],
		};
		let put_result = vss_client.put_object(&put_request).await;
		assert!(matches!(put_result.unwrap_err(), VssError::InternalError { .. }));

		let list_request = ListKeyVersionsRequest {
			store_id: "store".to_string(),
			page_size: Some(5),
			page_token: None,
			key_prefix: Some("k".into()),
		};
		let list_result = vss_client.list_key_versions(&list_request).await;
		assert!(matches!(list_result.unwrap_err(), VssError::InternalError { .. }));

		let malformed_error_response = b"malformed";
		_mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(409)
			.with_body(&malformed_error_response)
			.create();

		let get_malformed_err_response = vss_client.get_object(&get_request).await;
		assert!(matches!(get_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		let put_malformed_err_response = vss_client.put_object(&put_request).await;
		assert!(matches!(put_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		let list_malformed_err_response = vss_client.list_key_versions(&list_request).await;
		assert!(matches!(list_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		// Requests to endpoints are no longer mocked and will result in network error.
		drop(_mock_server);

		let get_network_err = vss_client.get_object(&get_request).await;
		assert!(matches!(get_network_err.unwrap_err(), VssError::InternalError { .. }));

		let put_network_err = vss_client.put_object(&put_request).await;
		assert!(matches!(put_network_err.unwrap_err(), VssError::InternalError { .. }));

		let list_network_err = vss_client.list_key_versions(&list_request).await;
		assert!(matches!(list_network_err.unwrap_err(), VssError::InternalError { .. }));
	}

	fn retry_policy() -> impl RetryPolicy<E = VssError> {
		ExponentialBackoffRetryPolicy::new(Duration::from_millis(1))
			.with_max_attempts(3)
			.skip_retry_on_error(|e| {
				matches!(
					e,
					VssError::NoSuchKeyError(..)
						| VssError::InvalidRequestError(..)
						| VssError::ConflictError(..)
						| VssError::AuthError(..)
				)
			})
	}
}
