//! Client-side library to interact with Versioned Storage Service (VSS).
//!
//! VSS is an open-source project designed to offer a server-side cloud storage solution specifically
//! tailored for noncustodial Lightning supporting mobile wallets. Its primary objective is to
//! simplify the development process for Lightning wallets by providing a secure means to store
//! and manage the essential state required for Lightning Network (LN) operations.
//!
//! Learn more [here](https://github.com/lightningdevkit/vss-server/blob/main/README.md).

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]

// Crate re-exports
pub use reqwest;

/// Implements a thin-client ([`client::VssClient`]) to access a hosted instance of Versioned Storage Service (VSS).
pub mod client;

/// Implements the error type ([`error::VssError`]) returned on interacting with [`client::VssClient`]
pub mod error;

/// Contains request/response types generated from the API definition of VSS.
pub mod types;

/// Contains utils for encryption, requests-retries etc.
pub mod util;

/// A collection of header providers.
pub mod headers;
