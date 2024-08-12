use crate::headers::{get_headermap, VssHeaderProvider, VssHeaderProviderError};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{Message, Secp256k1, SignOnly};
use bitcoin::Network;
use bitcoin::PrivateKey;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use url::Url;

// Derivation index of the parent extended private key as defined by LUD-05.
const PARENT_DERIVATION_INDEX: u32 = 138;
// Derivation index of the hashing private key as defined by LUD-05.
const HASHING_DERIVATION_INDEX: u32 = 0;
// The JWT token will be refreshed by the given amount before its expiry.
const EXPIRY_BUFFER: Duration = Duration::from_secs(60);
// The key of the LNURL k1 query parameter.
const K1_QUERY_PARAM: &str = "k1";
// The key of the LNURL sig query parameter.
const SIG_QUERY_PARAM: &str = "sig";
// The key of the LNURL key query parameter.
const KEY_QUERY_PARAM: &str = "key";
// The authorization header name.
const AUTHORIZATION: &str = "Authorization";

#[derive(Debug, Clone)]
struct JwtToken {
	token_str: String,
	expiry: Option<SystemTime>,
}

impl JwtToken {
	fn is_expired(&self) -> bool {
		self.expiry
			.and_then(|expiry| {
				SystemTime::now()
					.checked_add(EXPIRY_BUFFER)
					.map(|now_with_buffer| now_with_buffer > expiry)
			})
			.unwrap_or(false)
	}
}

/// Provides a JWT token based on LNURL Auth.
pub struct LnurlAuthToJwtProvider {
	engine: Secp256k1<SignOnly>,
	parent_key: Xpriv,
	url: String,
	default_headers: HashMap<String, String>,
	client: reqwest::Client,
	cached_jwt_token: RwLock<Option<JwtToken>>,
}

impl LnurlAuthToJwtProvider {
	/// Creates a new JWT provider based on LNURL Auth.
	///
	/// The LNURL Auth keys are derived from a seed according to LUD-05.
	/// The user is free to choose a consistent seed, such as a hardened derivation from the wallet
	/// master key or otherwise for compatibility reasons.
	/// The LNURL with the challenge will be retrieved by making a request to the given URL.
	/// The JWT token will be returned in response to the signed LNURL request under a token field.
	/// The given set of headers will be used for LNURL requests, and will also be returned together
	/// with the JWT authorization header for VSS requests.
	pub fn new(
		seed: &[u8], url: String, default_headers: HashMap<String, String>,
	) -> Result<LnurlAuthToJwtProvider, VssHeaderProviderError> {
		let engine = Secp256k1::signing_only();
		let master =
			Xpriv::new_master(Network::Testnet, seed).map_err(VssHeaderProviderError::from)?;
		let child_number = ChildNumber::from_hardened_idx(PARENT_DERIVATION_INDEX)
			.map_err(VssHeaderProviderError::from)?;
		let parent_key = master
			.derive_priv(&engine, &vec![child_number])
			.map_err(VssHeaderProviderError::from)?;
		let default_headermap = get_headermap(&default_headers)?;
		let client = reqwest::Client::builder()
			.default_headers(default_headermap)
			.build()
			.map_err(VssHeaderProviderError::from)?;

		Ok(LnurlAuthToJwtProvider {
			engine,
			parent_key,
			url,
			default_headers,
			client,
			cached_jwt_token: RwLock::new(None),
		})
	}

	async fn fetch_jwt_token(&self) -> Result<JwtToken, VssHeaderProviderError> {
		// Fetch the LNURL.
		let lnurl_str = self
			.client
			.get(&self.url)
			.send()
			.await
			.map_err(VssHeaderProviderError::from)?
			.text()
			.await
			.map_err(VssHeaderProviderError::from)?;

		// Sign the LNURL and perform the request.
		let signed_lnurl = sign_lnurl(&self.engine, &self.parent_key, &lnurl_str)?;
		let lnurl_auth_response: LnurlAuthResponse = self
			.client
			.get(&signed_lnurl)
			.send()
			.await
			.map_err(VssHeaderProviderError::from)?
			.json()
			.await
			.map_err(VssHeaderProviderError::from)?;

		let untrusted_token = match lnurl_auth_response {
			LnurlAuthResponse { token: Some(token), .. } => token,
			LnurlAuthResponse { reason: Some(reason), .. } => {
				return Err(VssHeaderProviderError::AuthorizationError {
					error: format!("LNURL Auth failed, reason is: {}", reason.escape_debug()),
				});
			},
			_ => {
				return Err(VssHeaderProviderError::InvalidData {
					error: "LNURL Auth response did not contain a token nor an error".to_string(),
				});
			},
		};
		parse_jwt_token(untrusted_token)
	}

	async fn get_jwt_token(&self, force_refresh: bool) -> Result<String, VssHeaderProviderError> {
		let cached_token_str = if force_refresh {
			None
		} else {
			let jwt_token = self.cached_jwt_token.read().unwrap();
			jwt_token.as_ref().filter(|t| !t.is_expired()).map(|t| t.token_str.clone())
		};
		if let Some(token_str) = cached_token_str {
			Ok(token_str)
		} else {
			let jwt_token = self.fetch_jwt_token().await?;
			*self.cached_jwt_token.write().unwrap() = Some(jwt_token.clone());
			Ok(jwt_token.token_str)
		}
	}
}

#[async_trait]
impl VssHeaderProvider for LnurlAuthToJwtProvider {
	async fn get_headers(
		&self, _request: &[u8],
	) -> Result<HashMap<String, String>, VssHeaderProviderError> {
		let jwt_token = self.get_jwt_token(false).await?;
		let mut headers = self.default_headers.clone();
		headers.insert(AUTHORIZATION.to_string(), format!("Bearer {}", jwt_token));
		Ok(headers)
	}
}

fn hashing_key(
	engine: &Secp256k1<SignOnly>, parent_key: &Xpriv,
) -> Result<PrivateKey, VssHeaderProviderError> {
	let hashing_child_number = ChildNumber::from_normal_idx(HASHING_DERIVATION_INDEX)
		.map_err(VssHeaderProviderError::from)?;
	parent_key
		.derive_priv(engine, &vec![hashing_child_number])
		.map(|xpriv| xpriv.to_priv())
		.map_err(VssHeaderProviderError::from)
}

fn linking_key_path(
	hashing_key: &PrivateKey, domain_name: &str,
) -> Result<DerivationPath, VssHeaderProviderError> {
	let mut engine = HmacEngine::<sha256::Hash>::new(&hashing_key.inner[..]);
	engine.input(domain_name.as_bytes());
	let result = Hmac::<sha256::Hash>::from_engine(engine).to_byte_array();
	// unwrap safety: We take 4-byte chunks, so TryInto for [u8; 4] never fails.
	let children = result
		.chunks_exact(4)
		.take(4)
		.map(|i| u32::from_be_bytes(i.try_into().unwrap()))
		.map(ChildNumber::from);
	Ok(DerivationPath::from_iter(children))
}

fn sign_lnurl(
	engine: &Secp256k1<SignOnly>, parent_key: &Xpriv, lnurl_str: &str,
) -> Result<String, VssHeaderProviderError> {
	// Parse k1 parameter to sign.
	let invalid_lnurl = || VssHeaderProviderError::InvalidData {
		error: format!("invalid lnurl: {}", lnurl_str.escape_debug()),
	};
	let mut lnurl = Url::parse(lnurl_str).map_err(|_| invalid_lnurl())?;
	let domain = lnurl.domain().ok_or(invalid_lnurl())?;
	let k1_str = lnurl
		.query_pairs()
		.find(|(k, _)| k == K1_QUERY_PARAM)
		.ok_or(invalid_lnurl())?
		.1
		.to_string();
	let k1: [u8; 32] = FromHex::from_hex(&k1_str).map_err(|_| invalid_lnurl())?;

	// Sign k1 parameter with linking private key.
	let hashing_private_key = hashing_key(engine, parent_key)?;
	let linking_key_path = linking_key_path(&hashing_private_key, domain)?;
	let linking_private_key = parent_key
		.derive_priv(engine, &linking_key_path)
		.map_err(VssHeaderProviderError::from)?
		.to_priv();
	let linking_public_key = linking_private_key.public_key(engine);
	let message = Message::from_digest_slice(&k1).map_err(|_| {
		VssHeaderProviderError::InvalidData { error: format!("invalid k1: {:?}", k1) }
	})?;
	let sig = engine.sign_ecdsa(&message, &linking_private_key.inner);

	// Compose LNURL with signature and linking public key.
	lnurl
		.query_pairs_mut()
		.append_pair(SIG_QUERY_PARAM, &sig.serialize_der().to_string())
		.append_pair(KEY_QUERY_PARAM, &linking_public_key.to_string());
	Ok(lnurl.to_string())
}

#[derive(Deserialize, Debug, Clone)]
struct LnurlAuthResponse {
	reason: Option<String>,
	token: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct ExpiryClaim {
	#[serde(rename = "exp")]
	expiry_secs: Option<u64>,
}

fn parse_jwt_token(jwt_token: String) -> Result<JwtToken, VssHeaderProviderError> {
	let parts: Vec<&str> = jwt_token.split('.').collect();
	let invalid = || VssHeaderProviderError::InvalidData {
		error: format!("invalid JWT token: {}", jwt_token.escape_debug()),
	};
	if parts.len() != 3 {
		return Err(invalid());
	}
	let _ = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid())?;
	let bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?;
	let _ = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid())?;
	let claim: ExpiryClaim = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
	let expiry =
		claim.expiry_secs.and_then(|e| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(e)));
	Ok(JwtToken { token_str: jwt_token, expiry })
}

impl From<bitcoin::bip32::Error> for VssHeaderProviderError {
	fn from(e: bitcoin::bip32::Error) -> VssHeaderProviderError {
		VssHeaderProviderError::InternalError { error: e.to_string() }
	}
}

impl From<reqwest::Error> for VssHeaderProviderError {
	fn from(e: reqwest::Error) -> VssHeaderProviderError {
		VssHeaderProviderError::RequestError { error: e.to_string() }
	}
}

#[cfg(test)]
mod test {
	use crate::headers::lnurl_auth_jwt::{linking_key_path, sign_lnurl};
	use bitcoin::bip32::Xpriv;
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
			SecretKey::from_str("7d417a6a5e9a6a4a879aeaba11a11838764c8fa2b959c242d43dea682b3e409b")
				.unwrap(),
			Network::Testnet, // The network only matters for serialization.
		);
		let path = linking_key_path(&hashing_key, "site.com").unwrap();
		let numbers: Vec<u32> = path.into_iter().map(|c| u32::from(c.clone())).collect();
		assert_eq!(numbers, vec![1588488367, 2659270754, 38110259, 4136336762]);
	}

	#[test]
	fn test_sign_lnurl() {
		let engine = Secp256k1::signing_only();
		let seed: [u8; 32] =
			FromHex::from_hex("abababababababababababababababababababababababababababababababab")
				.unwrap();
		let master = Xpriv::new_master(Network::Testnet, &seed).unwrap();
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
