use crate::headers::HeaderProvider;
use crate::headers::HeaderProviderError;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::Network;
use bitcoin::PrivateKey;
use reqwest::header::HeaderMap;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::SystemTime;
use url::Url;

// Derivation index of the parent extended private key as defined by LUD-05.
const PARENT_DERIVATION_INDEX: u32 = 138;
// Derivation index of the hashing private key as defined by LUD-05.
const HASHING_DERIVATION_INDEX: u32 = 0;
// The JWT token will be refreshed by the given amount before its expiry.
const EXPIRY_BUFFER_SECS: u64 = 60;
// The key of the LNURL k1 query parameter.
const K1_QUERY_PARAM: &str = "k1";
// The key of the LNURL sig query parameter.
const SIG_QUERY_PARAM: &str = "sig";
// The key of the LNURL key query parameter.
const KEY_QUERY_PARAM: &str = "key";

/// Provides a JWT token based on LNURL Auth.
/// The LNURL and JWT token are exchanged over a Websocket connection.
pub struct LnurlAuthJwt {
	engine: Secp256k1<All>,
	parent_key: ExtendedPrivKey,
	url: String,
	headers: HeaderMap,
	client: reqwest::Client,
	jwt_token: Mutex<Option<String>>,
	expiry: Mutex<Option<u64>>,
}

impl LnurlAuthJwt {
	/// Creates a new JWT provider based on LNURL Auth.
	///
	/// The LNURL Auth keys are derived based on the wallet seed according to LUD-05.
	/// The LNURL with the challenge will be retrieved by making a request to the given URL.
	/// The JWT token will be returned in response to the signed LNURL request under a token field.
	/// The given set of headers will be used for LNURL requests, and will also be returned together
	/// with the JWT authorization header for VSS requests.
	pub fn new(seed: &[u8], url: String, headers: Vec<(String, String)>) -> Result<LnurlAuthJwt, HeaderProviderError> {
		let engine = Secp256k1::new();
		let master = ExtendedPrivKey::new_master(Network::Testnet, seed).map_err(HeaderProviderError::from)?;
		let child_number =
			ChildNumber::from_hardened_idx(PARENT_DERIVATION_INDEX).map_err(HeaderProviderError::from)?;
		let parent_key = master
			.derive_priv(&engine, &vec![child_number])
			.map_err(HeaderProviderError::from)?;
		let mut headermap = HeaderMap::new();
		for (name, value) in headers {
			headermap.insert(
				reqwest::header::HeaderName::from_str(&name).map_err(HeaderProviderError::from)?,
				reqwest::header::HeaderValue::from_str(&value).map_err(HeaderProviderError::from)?,
			);
		}
		let client = reqwest::Client::builder()
			.default_headers(headermap.clone())
			.build()
			.map_err(HeaderProviderError::from)?;

		Ok(LnurlAuthJwt {
			engine,
			parent_key,
			url,
			headers: headermap,
			client,
			jwt_token: Mutex::new(None),
			expiry: Mutex::new(None),
		})
	}

	async fn fetch_jwt_token(&self) -> Result<String, HeaderProviderError> {
		// Fetch the LNURL.
		let lnurl_str = self
			.client
			.get(&self.url)
			.send()
			.await
			.map_err(HeaderProviderError::from)?
			.text()
			.await
			.map_err(HeaderProviderError::from)?;

		// Sign the LNURL and perform the request.
		let signed_lnurl = sign_lnurl(&self.engine, &self.parent_key, &lnurl_str)?;
		let lnurl_auth_response: LnurlAuthResponse = self
			.client
			.get(&signed_lnurl)
			.send()
			.await
			.map_err(HeaderProviderError::from)?
			.json()
			.await
			.map_err(HeaderProviderError::from)?;

		match lnurl_auth_response {
			LnurlAuthResponse { token: Some(token), .. } => Ok(token),
			LnurlAuthResponse { reason: Some(reason), .. } => {
				Err(HeaderProviderError::ApplicationError(format!("LNURL Auth failed, reason is: {}", reason)))
			}
			_ => Err(HeaderProviderError::InvalidData(
				"LNURL Auth response did not contain a token nor an error".to_string(),
			)),
		}
	}

	async fn get_jwt_token(&self, force_refresh: bool) -> Result<String, HeaderProviderError> {
		if !self.is_expired() && !force_refresh {
			let jwt_token = self.jwt_token.lock().unwrap();
			if let Some(jwt_token) = jwt_token.as_deref() {
				return Ok(jwt_token.to_string());
			}
		}
		let jwt_token = self.fetch_jwt_token().await?;
		let expiry = parse_expiry(&jwt_token)?;
		*self.jwt_token.lock().unwrap() = Some(jwt_token.clone());
		*self.expiry.lock().unwrap() = expiry;
		Ok(jwt_token)
	}

	fn is_expired(&self) -> bool {
		self.expiry
			.lock()
			.unwrap()
			.map(|expiry| {
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + EXPIRY_BUFFER_SECS
					> expiry
			})
			.unwrap_or(false)
	}
}

#[async_trait]
impl HeaderProvider for LnurlAuthJwt {
	async fn get_headers(&self) -> Result<HeaderMap, HeaderProviderError> {
		let jwt_token = self.get_jwt_token(false).await?;
		let mut headers = self.headers.clone();
		let value = format!("Bearer {}", jwt_token).parse().map_err(HeaderProviderError::from)?;
		headers.insert(AUTHORIZATION, value);
		Ok(headers)
	}
}

fn hashing_key(engine: &Secp256k1<All>, parent_key: &ExtendedPrivKey) -> Result<PrivateKey, HeaderProviderError> {
	let hashing_child_number =
		ChildNumber::from_normal_idx(HASHING_DERIVATION_INDEX).map_err(HeaderProviderError::from)?;
	parent_key
		.derive_priv(engine, &vec![hashing_child_number])
		.map(|xpriv| xpriv.to_priv())
		.map_err(HeaderProviderError::from)
}

fn linking_key_path(hashing_key: &PrivateKey, domain_name: &str) -> Result<DerivationPath, HeaderProviderError> {
	let mut engine = HmacEngine::<sha256::Hash>::new(&hashing_key.inner[..]);
	engine.input(domain_name.as_bytes());
	let result = Hmac::<sha256::Hash>::from_engine(engine).to_byte_array();
	let children: Vec<ChildNumber> = (0..4)
		.map(|i| u32::from_be_bytes(result[(i * 4)..((i + 1) * 4)].try_into().unwrap()))
		.map(ChildNumber::from)
		.collect::<Vec<_>>();
	Ok(DerivationPath::from(children))
}

fn sign_lnurl(
	engine: &Secp256k1<All>, parent_key: &ExtendedPrivKey, lnurl_str: &str,
) -> Result<String, HeaderProviderError> {
	// Parse k1 parameter to sign.
	let invalid_lnurl = || HeaderProviderError::InvalidData(format!("invalid lnurl: {}", lnurl_str));
	let mut lnurl = Url::parse(lnurl_str).map_err(|_| invalid_lnurl())?;
	let domain = lnurl.domain().ok_or(invalid_lnurl())?;
	let k1_str = lnurl
		.query_pairs()
		.find(|(k, _)| k == K1_QUERY_PARAM)
		.ok_or(invalid_lnurl())?
		.1
		.to_string();
	let k1: [u8; 32] = FromHex::from_hex(&k1_str).map_err(|_| invalid_lnurl())?;

	// Sign k1 parameter with linking key.
	let hashing_key = hashing_key(engine, parent_key)?;
	let linking_key_path = linking_key_path(&hashing_key, domain)?;
	let private_key = parent_key
		.derive_priv(engine, &linking_key_path)
		.map_err(HeaderProviderError::from)?
		.to_priv();
	let public_key = private_key.public_key(engine);
	let message =
		Message::from_slice(&k1).map_err(|_| HeaderProviderError::InvalidData(format!("invalid k1: {:?}", k1)))?;
	let sig = engine.sign_ecdsa(&message, &private_key.inner);

	// Compose LNURL with signature and linking key.
	lnurl
		.query_pairs_mut()
		.append_pair(SIG_QUERY_PARAM, &sig.serialize_der().to_string())
		.append_pair(KEY_QUERY_PARAM, &public_key.to_string());
	Ok(lnurl.to_string())
}

#[derive(Deserialize)]
struct LnurlAuthResponse {
	reason: Option<String>,
	token: Option<String>,
}

#[derive(Deserialize)]
struct ExpiryClaim {
	exp: Option<u64>,
}

fn parse_expiry(jwt_token: &str) -> Result<Option<u64>, HeaderProviderError> {
	let parts: Vec<&str> = jwt_token.split('.').collect();
	let invalid = || HeaderProviderError::InvalidData(format!("invalid JWT token: {}", jwt_token));
	if parts.len() != 3 {
		return Err(invalid());
	}
	let bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?;
	let claim: ExpiryClaim = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
	Ok(claim.exp)
}

impl From<bitcoin::bip32::Error> for HeaderProviderError {
	fn from(e: bitcoin::bip32::Error) -> HeaderProviderError {
		HeaderProviderError::InvalidData(e.to_string())
	}
}

impl From<reqwest::header::InvalidHeaderName> for HeaderProviderError {
	fn from(e: reqwest::header::InvalidHeaderName) -> HeaderProviderError {
		HeaderProviderError::InvalidData(e.to_string())
	}
}

impl From<reqwest::header::InvalidHeaderValue> for HeaderProviderError {
	fn from(e: reqwest::header::InvalidHeaderValue) -> HeaderProviderError {
		HeaderProviderError::InvalidData(e.to_string())
	}
}

impl From<reqwest::Error> for HeaderProviderError {
	fn from(e: reqwest::Error) -> HeaderProviderError {
		HeaderProviderError::RequestError(e.to_string())
	}
}

#[cfg(test)]
mod test {
	use crate::headers::lnurl_auth_jwt::{linking_key_path, sign_lnurl};
	use bitcoin::bip32::ExtendedPrivKey;
	use bitcoin::hashes::hex::FromHex;
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::SecretKey;
	use bitcoin::Network;
	use bitcoin::PrivateKey;
	use std::str::FromStr;

	#[test]
	fn test_linking_key_path() {
		// Test vector from:
		// https://github.com/lnurl/luds/blob/43cf7754de2033987a7661afc8b4a3998914a536/05.md
		let hashing_key = PrivateKey::new(
			SecretKey::from_str("7d417a6a5e9a6a4a879aeaba11a11838764c8fa2b959c242d43dea682b3e409b").unwrap(),
			Network::Testnet, // The network only matters for serialization.
		);
		let path = linking_key_path(&hashing_key, "site.com").unwrap();
		let numbers: Vec<u32> = path.into_iter().map(|c| u32::from(c.clone())).collect();
		assert_eq!(numbers, vec![1588488367, 2659270754, 38110259, 4136336762]);
	}

	#[test]
	fn test_sign_lnurl() {
		let engine = Secp256k1::new();
		let seed: [u8; 32] =
			FromHex::from_hex("abababababababababababababababababababababababababababababababab").unwrap();
		let master = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
		let signed = sign_lnurl(
			&engine,
			&master,
			"https://example.com/path?tag=login&k1=e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e",
		)
		.unwrap();
		assert_eq!(
			signed,
			"https://example.com/path?tag=login&k1=e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e&sig=3045022100a75df468de452e618edb8030016eb0894204655c7d93ece1be007fcf36843522022048bc2f00a0a5a30601d274b49cfaf9ef4c76176e5401d0dfb195f5d6ab8ab4c4&key=02d9eb1b467517d685e3b5439082c14bb1a2c9ae672df4d9046d208c193a5846e0",
		);
	}
}
