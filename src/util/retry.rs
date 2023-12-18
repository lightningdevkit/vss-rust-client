use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

/// A function that performs and retries the given operation according to a retry policy.
///
/// **Example**
/// ```rust
/// # use std::time::Duration;
/// # use vss_client::error::VssError;
/// # use vss_client::util::retry::{ExponentialBackoffRetryPolicy, retry, RetryPolicy};
/// #
/// # async fn operation() -> Result<i32, VssError>  {
/// # 	tokio::time::sleep(Duration::from_millis(10)).await;
/// # 	Ok(42)
/// # }
/// #
/// let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100));
///
/// let result = retry(operation, &retry_policy);
///```
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

/// The exponential backoff strategy is a retry approach that doubles the delay between retries.
/// A combined exponential backoff and jitter strategy is recommended that is ["Exponential Backoff and Jitter"](https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/).
/// This is helpful to avoid [Thundering Herd Problem](https://en.wikipedia.org/wiki/Thundering_herd_problem).
pub struct ExponentialBackoffRetryPolicy<E> {
	/// The base delay duration for the backoff algorithm. First retry is `base_delay` after first attempt.
	base_delay: Duration,
	phantom: PhantomData<E>,
}

impl<E: Error> ExponentialBackoffRetryPolicy<E> {
	/// Constructs a new instance using `base_delay`.
	///
	/// `base_delay` is the base delay duration for the backoff algorithm. First retry is `base_delay`
	/// after first attempt.
	pub fn new(base_delay: Duration) -> ExponentialBackoffRetryPolicy<E> {
		Self { base_delay, phantom: PhantomData }
	}
}

impl<E: Error> RetryPolicy for ExponentialBackoffRetryPolicy<E> {
	type E = E;
	fn next_delay(&self, context: &RetryContext<Self::E>) -> Option<Duration> {
		let backoff_factor = 2_u32.pow(context.attempts_made) - 1;
		let delay = self.base_delay * backoff_factor;
		Some(delay)
	}
}
