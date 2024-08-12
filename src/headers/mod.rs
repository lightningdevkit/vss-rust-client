use async_trait::async_trait;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

#[cfg(feature = "lnurl-auth")]
mod lnurl_auth_jwt;

#[cfg(feature = "lnurl-auth")]
pub use lnurl_auth_jwt::LnurlAuthToJwtProvider;

/// Defines a trait around how headers are provided for each VSS request.
#[async_trait]
pub trait VssHeaderProvider {
	/// Returns the HTTP headers to be used for a VSS request.
	/// This method is called on each request, and should likely perform some form of caching.
	///
	/// A reference to the serialized request body is given as `request`.
	/// It can be used to perform operations such as request signing.
	async fn get_headers(
		&self, request: &[u8],
	) -> Result<HashMap<String, String>, VssHeaderProviderError>;
}

/// Errors around providing headers for each VSS request.
#[derive(Debug)]
pub enum VssHeaderProviderError {
	/// Invalid data was encountered.
	InvalidData {
		/// The error message.
		error: String,
	},
	/// An external request failed.
	RequestError {
		/// The error message.
		error: String,
	},
	/// Authorization was refused.
	AuthorizationError {
		/// The error message.
		error: String,
	},
	/// An application-level error occurred specific to the header provider functionality.
	InternalError {
		/// The error message.
		error: String,
	},
}

impl Display for VssHeaderProviderError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidData { error } => {
				write!(f, "invalid data: {}", error)
			},
			Self::RequestError { error } => {
				write!(f, "error performing external request: {}", error)
			},
			Self::AuthorizationError { error } => {
				write!(f, "authorization was refused: {}", error)
			},
			Self::InternalError { error } => {
				write!(f, "internal error: {}", error)
			},
		}
	}
}

impl Error for VssHeaderProviderError {}

/// A header provider returning an given, fixed set of headers.
pub struct FixedHeaders {
	headers: HashMap<String, String>,
}

impl FixedHeaders {
	/// Creates a new header provider returning the given, fixed set of headers.
	pub fn new(headers: HashMap<String, String>) -> FixedHeaders {
		FixedHeaders { headers }
	}
}

#[async_trait]
impl VssHeaderProvider for FixedHeaders {
	async fn get_headers(
		&self, _request: &[u8],
	) -> Result<HashMap<String, String>, VssHeaderProviderError> {
		Ok(self.headers.clone())
	}
}

pub(crate) fn get_headermap(
	headers: &HashMap<String, String>,
) -> Result<HeaderMap, VssHeaderProviderError> {
	let mut headermap = HeaderMap::new();
	for (name, value) in headers {
		headermap.insert(
			reqwest::header::HeaderName::from_str(&name)
				.map_err(|e| VssHeaderProviderError::InvalidData { error: e.to_string() })?,
			reqwest::header::HeaderValue::from_str(&value)
				.map_err(|e| VssHeaderProviderError::InvalidData { error: e.to_string() })?,
		);
	}
	Ok(headermap)
}
