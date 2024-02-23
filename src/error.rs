use crate::types::{ErrorCode, ErrorResponse};
use prost::bytes::Bytes;
use prost::{DecodeError, Message};
use reqwest::StatusCode;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// When there is an error while writing to VSS storage, the response contains a relevant error code.
/// A mapping from a VSS server error codes. Refer to [`ErrorResponse`] docs for more
/// information regarding each error code and corresponding use-cases.
#[derive(Debug)]
pub enum VssError {
	/// Please refer to [`ErrorCode::NoSuchKeyException`].
	NoSuchKeyError(String),

	/// Please refer to [`ErrorCode::InvalidRequestException`].
	InvalidRequestError(String),

	/// Please refer to [`ErrorCode::ConflictException`].
	ConflictError(String),

	/// Please refer to [`ErrorCode::AuthException`].
	AuthError(String),

	/// Please refer to [`ErrorCode::InternalServerException`].
	InternalServerError(String),

	/// There is an unknown error, it could be a client-side bug, unrecognized error-code, network error
	/// or something else.
	InternalError(String),
}

impl VssError {
	/// Create new instance of `VssError`
	pub fn new(status: StatusCode, payload: Bytes) -> VssError {
		match ErrorResponse::decode(&payload[..]) {
			Ok(error_response) => VssError::from(error_response),
			Err(e) => {
				let message = format!(
					"Unable to decode ErrorResponse from server, HttpStatusCode: {}, DecodeErr: {}",
					status, e
				);
				VssError::InternalError(message)
			},
		}
	}
}

impl Display for VssError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			VssError::NoSuchKeyError(message) => {
				write!(f, "Requested key does not exist: {}", message)
			},
			VssError::InvalidRequestError(message) => {
				write!(f, "Request sent to VSS Storage was invalid: {}", message)
			},
			VssError::ConflictError(message) => {
				write!(f, "Potential version conflict in write operation: {}", message)
			},
			VssError::AuthError(message) => {
				write!(f, "Authentication or Authorization failure: {}", message)
			},
			VssError::InternalServerError(message) => {
				write!(f, "InternalServerError: {}", message)
			},
			VssError::InternalError(message) => {
				write!(f, "InternalError: {}", message)
			},
		}
	}
}

impl Error for VssError {}

impl From<ErrorResponse> for VssError {
	fn from(error_response: ErrorResponse) -> Self {
		match error_response.error_code() {
			ErrorCode::NoSuchKeyException => VssError::NoSuchKeyError(error_response.message),
			ErrorCode::InvalidRequestException => {
				VssError::InvalidRequestError(error_response.message)
			},
			ErrorCode::ConflictException => VssError::ConflictError(error_response.message),
			ErrorCode::AuthException => VssError::AuthError(error_response.message),
			ErrorCode::InternalServerException => {
				VssError::InternalServerError(error_response.message)
			},
			_ => VssError::InternalError(format!(
				"VSS responded with an unknown error code: {}, message: {}",
				error_response.error_code, error_response.message
			)),
		}
	}
}

impl From<DecodeError> for VssError {
	fn from(err: DecodeError) -> Self {
		VssError::InternalError(err.to_string())
	}
}

impl From<reqwest::Error> for VssError {
	fn from(err: reqwest::Error) -> Self {
		VssError::InternalError(err.to_string())
	}
}
