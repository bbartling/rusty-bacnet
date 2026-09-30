//! Shared helpers for the Criterion suites, the `stress-test` binary and the Docker
//! cross-network test binaries.

// Benchmark and stress-test plumbing, not a published API: the user opted this
// crate out of the missing_docs policy (#902).
#![allow(missing_docs)]

pub mod helpers;
pub mod sc_helpers;
pub mod stress;
