use serde::Deserialize;
use serde::Deserializer;
use std::fmt;
use std::ops::Deref;

/// An untrusted String that will override the Display implementation to escape control characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct UntrustedString(String);

impl UntrustedString {
	/// Wraps a String as an untrusted String.
	pub fn new(s: String) -> Self {
		UntrustedString(s)
	}

	/// Unwraps an untrusted String after the user performs validation.
	pub fn into_inner(self) -> String {
		self.0
	}
}

impl Deref for UntrustedString {
	type Target = String;

	fn deref(&self) -> &String {
		&self.0
	}
}

impl fmt::Display for UntrustedString {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl<'de> Deserialize<'de> for UntrustedString {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s: Result<String, D::Error> = Deserialize::deserialize(deserializer);
		s.map(UntrustedString)
	}
}
