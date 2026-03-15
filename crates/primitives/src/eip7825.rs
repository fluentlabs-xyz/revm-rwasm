//! EIP-7825: Transaction Gas Limit Cap
//!
//! Introduces a protocol-level cap on the maximum gas used by a transaction.

/// Transaction gas limit cap.
///
/// # Rationale from EIP
///
/// The proposed cap of 16,777,216 gas (2^24) provides a clean power-of-two boundary that simplifies implementation while still
/// being large enough to accommodate most complex transactions, including contract deployments and advanced DeFi interactions.
/// This value represents approximately half of typical block sizes (30-40 million gas), ensuring multiple transactions can fit within each block.
///
/// We disable this check, because for Fluent we can have more than 16mil, for example, if we need
/// to deploy big Wasm binary (~1 MiB)
pub const TX_GAS_LIMIT_CAP: u64 = u64::MAX; // 16_777_216;
