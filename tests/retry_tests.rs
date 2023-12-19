#[cfg(test)]
mod retry_tests {
	use std::io;
	use std::sync::atomic::{AtomicU32, Ordering};
	use std::sync::Arc;
	use std::time::Duration;

	use vss_client::error::VssError;
	use vss_client::util::retry::{retry, ExponentialBackoffRetryPolicy, RetryPolicy};

	#[tokio::test]
	async fn test_async_retry() {
		let base_delay = Duration::from_millis(10);
		let max_attempts = 3;
		let max_total_delay = Duration::from_secs(60);
		let max_jitter = Duration::from_millis(5);

		let exponential_backoff_jitter_policy = ExponentialBackoffRetryPolicy::new(base_delay)
			.skip_retry_on_error(|e| matches!(e, VssError::InvalidRequestError(..)))
			.with_max_attempts(max_attempts)
			.with_max_total_delay(max_total_delay)
			.with_max_jitter(max_jitter);

		let mut call_count = Arc::new(AtomicU32::new(0));
		let count = call_count.clone();
		let async_function = move || {
			let count = count.clone();
			async move {
				let attempts_made = count.fetch_add(1, Ordering::SeqCst);
				if attempts_made < max_attempts - 1 {
					return Err(VssError::InternalServerError("Failure".to_string()));
				}
				tokio::time::sleep(Duration::from_millis(100)).await;
				Ok(42)
			}
		};

		let result = retry(async_function, &exponential_backoff_jitter_policy).await;
		assert_eq!(result.ok(), Some(42));
		assert_eq!(call_count.load(Ordering::SeqCst), max_attempts);

		call_count = Arc::new(AtomicU32::new(0));
		let count = call_count.clone();
		let failing_async_function = move || {
			let count = count.clone();
			async move {
				count.fetch_add(1, Ordering::SeqCst);
				tokio::time::sleep(Duration::from_millis(100)).await;
				Err::<(), VssError>(VssError::InternalServerError("Failed".to_string()))
			}
		};

		let failed_result = retry(failing_async_function, &exponential_backoff_jitter_policy).await;
		assert!(failed_result.is_err());
		assert_eq!(call_count.load(Ordering::SeqCst), 3);
	}

	#[tokio::test]
	async fn test_retry_on_all_errors() {
		let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(10)).with_max_attempts(3);

		let call_count = Arc::new(AtomicU32::new(0));
		let count = call_count.clone();
		let failing_async_function = move || {
			let count = count.clone();
			async move {
				count.fetch_add(1, Ordering::SeqCst);
				tokio::time::sleep(Duration::from_millis(100)).await;
				Err::<(), io::Error>(io::Error::new(io::ErrorKind::InvalidData, "Failure"))
			}
		};

		let failed_result = retry(failing_async_function, &retry_policy).await;
		assert!(failed_result.is_err());
		assert_eq!(call_count.load(Ordering::SeqCst), 3);
	}

	#[tokio::test]
	async fn test_retry_capped_by_max_total_delay() {
		let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
			.with_max_total_delay(Duration::from_millis(350));

		let call_count = Arc::new(AtomicU32::new(0));
		let count = call_count.clone();
		let failing_async_function = move || {
			let count = count.clone();
			async move {
				count.fetch_add(1, Ordering::SeqCst);
				tokio::time::sleep(Duration::from_millis(100)).await;
				Err::<(), VssError>(VssError::InternalServerError("Failed".to_string()))
			}
		};

		let failed_result = retry(failing_async_function, &retry_policy).await;
		assert!(failed_result.is_err());
		assert_eq!(call_count.load(Ordering::SeqCst), 2);
	}
}
