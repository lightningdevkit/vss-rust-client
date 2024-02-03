use async_trait::async_trait;
use reqwest::header::HeaderMap;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;

mod lnurl_auth_jwt;
pub use lnurl_auth_jwt::LnurlAuthJwt;

/// Errors around providing headers for each VSS request.
#[derive(Debug)]
pub enum HeaderProviderError {
	/// Invalid data was encountered.
	InvalidData(String),
	/// An external request failed.
	RequestError(String),
	/// An application-level error occurred specific to the header provider functionality.
	ApplicationError(String),
}

impl Display for HeaderProviderError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidData(e) => {
				write!(f, "invalid data: {}", e)
			}
			Self::RequestError(e) => {
				write!(f, "error making request: {}", e)
			}
			Self::ApplicationError(e) => {
				write!(f, "application error providing headers: {}", e)
			}
		}
	}
}

impl Error for HeaderProviderError {}

/// Defines a trait around how headers are provided for each VSS request.
#[async_trait]
pub trait HeaderProvider {
	/// Returns the HTTP headers to be used for a VSS request.
	/// This method is called on each request, and should likely perform some form of caching.
	async fn get_headers(&self) -> Result<HeaderMap, HeaderProviderError>;
}

/// A header provider returning an given, fixed set of headers.
pub struct FixedHeaders {
	headers: HeaderMap,
}

impl FixedHeaders {
	/// Creates a new header provider returning the given, fixed set of headers.
	pub fn new(headers: HeaderMap) -> FixedHeaders {
		FixedHeaders { headers }
	}
}

#[async_trait]
impl HeaderProvider for FixedHeaders {
	async fn get_headers(&self) -> Result<HeaderMap, HeaderProviderError> {
		Ok(self.headers.clone())
	}
}
