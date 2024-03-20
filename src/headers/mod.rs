use async_trait::async_trait;
use reqwest::header::HeaderMap;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

mod lnurl_auth_jwt;
pub use lnurl_auth_jwt::LnurlAuthJwt;

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
	/// An application-level error occurred specific to the header provider functionality.
	ApplicationError {
		/// The error message.
		error: String,
	},
}

impl Display for VssHeaderProviderError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidData { error } => {
				write!(f, "invalid data: {}", error)
			}
			Self::RequestError { error } => {
				write!(f, "error making request: {}", error)
			}
			Self::ApplicationError { error } => {
				write!(f, "application error providing headers: {}", error)
			}
		}
	}
}

impl Error for VssHeaderProviderError {}

/// Defines a trait around how headers are provided for each VSS request.
#[async_trait]
pub trait VssHeaderProvider {
	/// Returns the HTTP headers to be used for a VSS request.
	/// This method is called on each request, and should likely perform some form of caching.
	async fn get_headers(&self) -> Result<Vec<(String, String)>, VssHeaderProviderError>;
}

/// A header provider returning an given, fixed set of headers.
pub struct FixedHeaders {
	headers: Vec<(String, String)>,
}

impl FixedHeaders {
	/// Creates a new header provider returning the given, fixed set of headers.
	pub fn new(headers: Vec<(String, String)>) -> FixedHeaders {
		FixedHeaders { headers }
	}
}

#[async_trait]
impl VssHeaderProvider for FixedHeaders {
	async fn get_headers(&self) -> Result<Vec<(String, String)>, VssHeaderProviderError> {
		Ok(self.headers.clone())
	}
}

pub(crate) fn get_headermap(headers: &Vec<(String, String)>) -> Result<HeaderMap, String> {
	let mut headermap = HeaderMap::new();
	for (name, value) in headers {
		headermap.insert(
			reqwest::header::HeaderName::from_str(&name).map_err(|e| e.to_string())?,
			reqwest::header::HeaderValue::from_str(&value).map_err(|e| e.to_string())?,
		);
	}
	Ok(headermap)
}
