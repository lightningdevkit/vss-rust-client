#[cfg(test)]
mod tests {
	use mockito::{self, Matcher};
	use prost::Message;

	use vss_accessor::vss::{
		ErrorCode, ErrorResponse, GetObjectRequest, GetObjectResponse, KeyValue, ListKeyVersionsRequest,
		ListKeyVersionsResponse, PutObjectRequest, PutObjectResponse,
	};
	use vss_accessor::vss_error::VssError;
	use vss_accessor::VssAccessor;

	const GET_OBJECT_ENDPOINT: &'static str = "/getObject";
	const PUT_OBJECT_ENDPOINT: &'static str = "/putObjects";
	const LIST_KEY_VERSIONS_ENDPOINT: &'static str = "/listKeyVersions";

	#[tokio::test]
	async fn test_get() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let mock_request = GetObjectRequest { store_id: "store".to_string(), key: "k1".to_string() };
		let mut mock_response = GetObjectResponse::default();
		mock_response.value = Some(KeyValue { key: "k1".to_string(), version: 2, value: b"k1v2".to_vec() });

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", GET_OBJECT_ENDPOINT)
			.match_body(mock_request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssAccessor with the mock server URL.
		let vss_acc = VssAccessor::new(&base_url).unwrap();
		let actual_result = vss_acc.get("store".to_string(), "k1".to_string()).await.unwrap();

		let expected_result = &mock_response;
		assert_eq!(&actual_result, expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_put() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let mock_request = PutObjectRequest {
			store_id: "store".to_string(),
			global_version: Some(4),
			transaction_items: vec![KeyValue { key: "k1".to_string(), version: 2, value: b"k1v3".to_vec() }],
		};
		let mock_response = PutObjectResponse::default();

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", PUT_OBJECT_ENDPOINT)
			.match_body(mock_request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssAccessor with the mock server URL.
		let vss_acc = VssAccessor::new(&base_url).unwrap();
		let actual_result = vss_acc
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await
			.unwrap();

		let expected_result = &mock_response;
		assert_eq!(&actual_result, expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_put_tx() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let mock_request = PutObjectRequest {
			store_id: "store".to_string(),
			global_version: Some(5),
			transaction_items: vec![
				KeyValue { key: "k1".to_string(), version: 3, value: b"k1v4".to_vec() },
				KeyValue { key: "k2".to_string(), version: 1, value: b"k2v2".to_vec() },
			],
		};
		let mock_response = PutObjectResponse {};

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", PUT_OBJECT_ENDPOINT)
			.match_body(mock_request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssAccessor with the mock server URL.
		let vss_acc = VssAccessor::new(&base_url).unwrap();

		let actual_result = vss_acc
			.put_tx(
				"store".to_string(),
				Some(5),
				vec![
					KeyValue { key: "k1".to_string(), version: 3, value: b"k1v4".to_vec() },
					KeyValue { key: "k2".to_string(), version: 1, value: b"k2v2".to_vec() },
				],
			)
			.await
			.unwrap();

		let expected_result = &mock_response;
		assert_eq!(&actual_result, expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_list_key_versions() {
		// Spin-up mock server with mock response for given request.
		let base_url = mockito::server_url().to_string();

		// Set up the mock request/response.
		let mock_request = ListKeyVersionsRequest {
			store_id: "store".to_string(),
			page_size: Some(5),
			page_token: None,
			key_prefix: Some("k".into()),
		};
		let key_versions = vec![
			KeyValue { key: "k1".to_string(), version: 3, value: b"".to_vec() },
			KeyValue { key: "k2".to_string(), version: 1, value: b"".to_vec() },
		];

		let mock_response =
			ListKeyVersionsResponse { key_versions, global_version: Some(4), next_page_token: Some("k2".into()) };

		// Register the mock endpoint with the mockito server.
		let mock_server = mockito::mock("POST", LIST_KEY_VERSIONS_ENDPOINT)
			.match_body(mock_request.encode_to_vec())
			.with_status(200)
			.with_body(mock_response.encode_to_vec())
			.create();

		// Create a new VssAccessor with the mock server URL.
		let vss_acc = VssAccessor::new(&base_url).unwrap();

		let actual_result = vss_acc
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await
			.unwrap();

		let expected_result = &mock_response;
		assert_eq!(&actual_result, expected_result);

		// Verify server endpoint was called exactly once.
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_invalid_request_err_handling() {
		let base_url = mockito::server_url();
		let vss_accessor = VssAccessor::new(&base_url).unwrap();

		// Invalid Request Error
		let error_response = ErrorResponse {
			error_code: ErrorCode::InvalidRequestException.into(),
			message: "InvalidRequestException".to_string(),
		};
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(400)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_accessor.get("store".to_string(), "key1".to_string()).await;
		assert!(matches!(get_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		let put_result = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		let list_result = vss_accessor
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::InvalidRequestError { .. }));

		// Verify 3 requests hit the server
		mock_server.expect(3).assert();
	}

	#[tokio::test]
	async fn test_conflict_err_handling() {
		let base_url = mockito::server_url();
		let vss_accessor = VssAccessor::new(&base_url).unwrap();

		// Conflict Error
		let error_response =
			ErrorResponse { error_code: ErrorCode::ConflictException.into(), message: "ConflictException".to_string() };
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(409)
			.with_body(&error_response.encode_to_vec())
			.create();

		let put_result = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::ConflictError { .. }));

		// Verify 1 requests hit the server
		mock_server.expect(1).assert();
	}

	#[tokio::test]
	async fn test_internal_server_err_handling() {
		let base_url = mockito::server_url();
		let vss_accessor = VssAccessor::new(&base_url).unwrap();

		// Internal Server Error
		let error_response = ErrorResponse {
			error_code: ErrorCode::InternalServerException.into(),
			message: "InternalServerException".to_string(),
		};
		let mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(500)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_accessor.get("store".to_string(), "key1".to_string()).await;
		assert!(matches!(get_result.unwrap_err(), VssError::InternalServerError { .. }));

		let put_result = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::InternalServerError { .. }));

		let list_result = vss_accessor
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::InternalServerError { .. }));

		// Verify 3 requests hit the server
		mock_server.expect(3).assert();
	}

	#[tokio::test]
	async fn test_internal_err_handling() {
		let base_url = mockito::server_url();
		let vss_accessor = VssAccessor::new(&base_url).unwrap();

		let error_response = ErrorResponse { error_code: 999, message: "UnknownException".to_string() };
		let mut mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(999)
			.with_body(&error_response.encode_to_vec())
			.create();

		let get_result = vss_accessor.get("store".to_string(), "key1".to_string()).await;
		assert!(matches!(get_result.unwrap_err(), VssError::InternalError { .. }));

		let put_result = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_result.unwrap_err(), VssError::InternalError { .. }));

		let list_result = vss_accessor
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await;
		assert!(matches!(list_result.unwrap_err(), VssError::InternalError { .. }));

		let malformed_error_response = b"malformed";
		mock_server = mockito::mock("POST", Matcher::Any)
			.with_status(409)
			.with_body(&malformed_error_response)
			.create();

		let get_malformed_err_response = vss_accessor.get("store".to_string(), "key1".to_string()).await;
		assert!(matches!(get_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		let put_malformed_err_response = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		let list_malformed_err_response = vss_accessor
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await;
		assert!(matches!(list_malformed_err_response.unwrap_err(), VssError::InternalError { .. }));

		// Requests to endpoints are no longer mocked and will result in network error.
		drop(mock_server);

		let get_network_err = vss_accessor.get("store".to_string(), "key1".to_string()).await;
		assert!(matches!(get_network_err.unwrap_err(), VssError::InternalError { .. }));

		let put_network_err = vss_accessor
			.put("store".to_string(), Some(4), "k1".to_string(), 2, b"k1v3")
			.await;
		assert!(matches!(put_network_err.unwrap_err(), VssError::InternalError { .. }));

		let list_network_err = vss_accessor
			.list_key_versions("store".to_string(), "k".to_string(), Some(5), None)
			.await;
		assert!(matches!(list_network_err.unwrap_err(), VssError::InternalError { .. }));
	}
}
