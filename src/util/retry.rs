use rand::Rng;
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

/// A function that performs and retries the given operation according to a retry policy.
///
/// **Caution**: A retry policy without the number of attempts capped by [`MaxAttemptsRetryPolicy`]
/// decorator will result in infinite retries.
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
/// let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
/// 	.with_max_attempts(5)
/// 	.with_max_total_delay(Duration::from_secs(2))
/// 	.with_max_jitter(Duration::from_millis(30));
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

	/// Returns a new `RetryPolicy` that respects the given maximum attempts.
	fn with_max_attempts(self, max_attempts: u32) -> MaxAttemptsRetryPolicy<Self> {
		MaxAttemptsRetryPolicy { inner_policy: self, max_attempts }
	}

	/// Returns a new `RetryPolicy` that respects the given total delay.
	fn with_max_total_delay(self, max_total_delay: Duration) -> MaxTotalDelayRetryPolicy<Self> {
		MaxTotalDelayRetryPolicy { inner_policy: self, max_total_delay }
	}

	/// Returns a new `RetryPolicy` that adds jitter(random delay) to underlying policy.
	fn with_max_jitter(self, max_jitter: Duration) -> JitteredRetryPolicy<Self> {
		JitteredRetryPolicy { inner_policy: self, max_jitter }
	}
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

/// Decorates the given `RetryPolicy` to respect the given maximum attempts.
pub struct MaxAttemptsRetryPolicy<T: RetryPolicy> {
	/// The underlying retry policy to use.
	inner_policy: T,
	/// The maximum number of attempts to retry.
	max_attempts: u32,
}

impl<T: RetryPolicy> RetryPolicy for MaxAttemptsRetryPolicy<T> {
	type E = T::E;
	fn next_delay(&self, context: &RetryContext<Self::E>) -> Option<Duration> {
		if self.max_attempts == context.attempts_made {
			None
		} else {
			self.inner_policy.next_delay(context)
		}
	}
}

/// Decorates the given `RetryPolicy` to respect the given maximum total delay.
pub struct MaxTotalDelayRetryPolicy<T: RetryPolicy> {
	/// The underlying retry policy to use.
	inner_policy: T,
	/// The maximum accumulated delay that will be allowed over all attempts.
	max_total_delay: Duration,
}

impl<T: RetryPolicy> RetryPolicy for MaxTotalDelayRetryPolicy<T> {
	type E = T::E;
	fn next_delay(&self, context: &RetryContext<Self::E>) -> Option<Duration> {
		let next_delay = self.inner_policy.next_delay(context);
		if let Some(next_delay) = next_delay {
			if self.max_total_delay < context.accumulated_delay + next_delay {
				return None;
			}
		}
		next_delay
	}
}

/// Decorates the given `RetryPolicy` and adds jitter (random delay) to it. This can make retries
/// more spread out and less likely to all fail at once.
pub struct JitteredRetryPolicy<T: RetryPolicy> {
	/// The underlying retry policy to use.
	inner_policy: T,
	/// The maximum amount of random jitter to apply to the delay.
	max_jitter: Duration,
}

impl<T: RetryPolicy> RetryPolicy for JitteredRetryPolicy<T> {
	type E = T::E;
	fn next_delay(&self, context: &RetryContext<Self::E>) -> Option<Duration> {
		if let Some(base_delay) = self.inner_policy.next_delay(context) {
			let mut rng = rand::thread_rng();
			let jitter = Duration::from_micros(rng.gen_range(0..self.max_jitter.as_micros() as u64));
			Some(base_delay + jitter)
		} else {
			None
		}
	}
}
