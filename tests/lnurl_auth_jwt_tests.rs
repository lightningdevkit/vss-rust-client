#[cfg(feature = "lnurl-auth")]
mod lnurl_auth_jwt_tests {
	use base64::engine::general_purpose::URL_SAFE_NO_PAD;
	use base64::Engine;
	use bitcoin::bip32::Xpriv;
	use bitcoin::Network;
	use mockito::Matcher;
	use serde_json::json;
	use std::collections::HashMap;
	use std::time::SystemTime;
	use vss_client::headers::LnurlAuthToJwtProvider;
	use vss_client::headers::VssHeaderProvider;

	const APPLICATION_JSON: &'static str = "application/json";

	fn lnurl_auth_response(jwt: &str) -> String {
		json!({
			"status": "OK",
			"token": jwt,
		})
		.to_string()
	}

	fn jwt_with_expiry(exp: u64) -> String {
		let claims = json!({
			"exp": exp,
		})
		.to_string();
		let ignored = URL_SAFE_NO_PAD.encode("ignored");
		let encoded = URL_SAFE_NO_PAD.encode(claims);
		format!("{}.{}.{}", ignored, encoded, ignored)
	}

	#[tokio::test]
	async fn test_lnurl_auth_jwt() {
		// Initialize LNURL Auth JWT provider connecting to the mock server.
		let addr = mockito::server_address();
		let base_url = format!("http://localhost:{}", addr.port());
		let parent_key = Xpriv::new_master(Network::Testnet, &[0; 32]).unwrap();
		let lnurl_auth_jwt =
			LnurlAuthToJwtProvider::new(parent_key, base_url.clone(), HashMap::new()).unwrap();
		{
			// First request will be provided with an expired JWT token.
			let k1 = "0000000000000000000000000000000000000000000000000000000000000000";
			let expired_jwt = jwt_with_expiry(0);
			let lnurl = mockito::mock("GET", "/")
				.expect(1)
				.with_status(200)
				.with_body(format!("{}/verify?tag=login&k1={}", base_url, k1))
				.create();
			let lnurl_verification = mockito::mock("GET", "/verify")
				.match_query(Matcher::AllOf(vec![
					Matcher::UrlEncoded("k1".into(), k1.into()),
					Matcher::Regex("sig=".into()),
					Matcher::Regex("key=".into()),
				]))
				.expect(1)
				.with_status(200)
				.with_header(reqwest::header::CONTENT_TYPE.as_str(), APPLICATION_JSON)
				.with_body(lnurl_auth_response(&expired_jwt))
				.create();
			assert_eq!(
				lnurl_auth_jwt.get_headers(&[]).await.unwrap().get("Authorization").unwrap(),
				&format!("Bearer {}", expired_jwt),
			);
			lnurl.assert();
			lnurl_verification.assert();
		}
		{
			// Second request will be provided with a non-expired JWT token.
			// This will be cached.
			let k1 = "1000000000000000000000000000000000000000000000000000000000000000";
			let valid_jwt = jwt_with_expiry(
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
					+ 60 * 60 * 24 * 365,
			);
			let lnurl = mockito::mock("GET", "/")
				.expect(1)
				.with_status(200)
				.with_body(format!("{}/verify?tag=login&k1={}", base_url, k1))
				.create();
			let lnurl_verification = mockito::mock("GET", "/verify")
				.match_query(Matcher::AllOf(vec![
					Matcher::UrlEncoded("k1".into(), k1.into()),
					Matcher::Regex("sig=".to_string()),
					Matcher::Regex("key=".to_string()),
				]))
				.expect(1)
				.with_status(200)
				.with_header(reqwest::header::CONTENT_TYPE.as_str(), APPLICATION_JSON)
				.with_body(lnurl_auth_response(&valid_jwt))
				.create();
			assert_eq!(
				lnurl_auth_jwt.get_headers(&[]).await.unwrap().get("Authorization").unwrap(),
				&format!("Bearer {}", valid_jwt),
			);
			assert_eq!(
				lnurl_auth_jwt.get_headers(&[]).await.unwrap().get("Authorization").unwrap(),
				&format!("Bearer {}", valid_jwt),
			);
			lnurl.assert();
			lnurl_verification.assert();
		}
	}
}
