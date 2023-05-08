use crate::vss::{ErrorCode, ErrorResponse};
use prost::bytes::Bytes;
use prost::{DecodeError, Message};
use reqwest::StatusCode;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum VssError {
	InvalidRequestError(ErrorResponse),
	ConflictError(ErrorResponse),
	InternalServerError(ErrorResponse),
	InternalError(String),
}

impl VssError {
	pub fn new(status: StatusCode, payload: Bytes) -> VssError {
		match ErrorResponse::decode(&payload[..]) {
			Ok(error_response) => VssError::from(error_response),
			Err(e) => {
				let message =
					format!("Unable to decode ErrorResponse from server, HttpStatusCode: {}, DecodeErr: {}", status, e);
				VssError::InternalError(message)
			}
		}
	}
}

impl Display for VssError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			VssError::InvalidRequestError(error_response) => {
				write!(f, "Request sent to VSS Server was invalid : {}", error_response.message)
			}
			VssError::ConflictError(error_response) => {
				write!(f, "Potential version conflict in write operation : {}", error_response.message)
			}
			VssError::InternalServerError(error_response) => {
				write!(f, "InternalServerError : {}", error_response.message)
			}
			VssError::InternalError(message) => {
				write!(f, "InternalError : {}", message)
			}
		}
	}
}

impl Error for VssError {}

impl From<ErrorResponse> for VssError {
	fn from(error_response: ErrorResponse) -> Self {
		return match error_response.error_code() {
			ErrorCode::InvalidRequestException => VssError::InvalidRequestError(error_response),
			ErrorCode::ConflictException => VssError::ConflictError(error_response),
			ErrorCode::InternalServerException => VssError::InternalServerError(error_response),
			_ => VssError::InternalError(format!(
				"Server responded with an unknown error code: {}, \
             message: {}",
				error_response.error_code, error_response.message
			)),
		};
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
