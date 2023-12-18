use std::error::Error;
use std::future::Future;
use std::time::Duration;

/// A function that performs and retries the given operation according to a retry policy.
pub async fn retry<R, F, Fut, T, E>(mut operation: F, retry_policy: &R) -> Result<T, E>
where
	R: RetryPolicy<E = E>,
	F: FnMut() -> Fut,
	Fut: Future<Output = Result<T, E>>,
	E: Error,
{
	let mut attempts_made = 0;
	let mut accumulated_delay = Duration::ZERO;
	loop {
		match operation().await {
			Ok(result) => return Ok(result),
			Err(err) => {
				attempts_made += 1;
				if let Some(delay) =
					retry_policy.next_delay(&RetryContext { attempts_made, accumulated_delay, error: &err })
				{
					tokio::time::sleep(delay).await;
					accumulated_delay += delay;
				} else {
					return Err(err);
				}
			}
		}
	}
}

/// Provides the logic for how and when to perform retries.
pub trait RetryPolicy: Sized {
	/// The error type returned by the `operation` in `retry`.
	type E: Error;

	/// Returns the duration to wait before trying the next attempt.
	/// `context` represents the context of a retry operation.
	///
	/// If `None` is returned then no further retry attempt is made.
	fn next_delay(&self, context: &RetryContext<Self::E>) -> Option<Duration>;
}

/// Represents the context of a retry operation.
///
/// The context holds key information about the retry operation
/// such as how many attempts have been made until now, the accumulated
/// delay between retries, and the error that triggered the retry.
pub struct RetryContext<'a, E: Error> {
	/// The number attempts made until now, before attempting the next retry.
	attempts_made: u32,

	/// The amount of artificial delay we have already waited in between previous
	/// attempts. Does not include the time taken to execute the operation.
	accumulated_delay: Duration,

	/// The error encountered in the previous attempt.
	error: &'a E,
}
