use std::vec;
use primitives::{keccak256, Bytes, B256};

mod bytecode;
pub use bytecode::{AnalyzedBytecode, LegacyBytecode};

/// Ethereum metadata
#[derive(Debug)]
pub enum EthereumMetadata {
    /// Legacy EVM bytecode
    Legacy(LegacyBytecode),
    /// Analyzed EVM bytecode
    Analyzed(AnalyzedBytecode),
}

/// A prefix indicating analyzed bytecode
pub const ETHEREUM_METADATA_VERSION_ANALYZED: B256 = B256::with_last_byte(0x01);

impl EthereumMetadata {
    /// Create new analyzed EVM bytecode metadata
    pub fn new_analyzed(bytecode: Bytes) -> Self {
        let code_hash = keccak256(bytecode.as_ref());
        Self::Analyzed(AnalyzedBytecode::new(bytecode, code_hash))
    }

    /// Create new legacy EVM bytecode metadata
    pub fn new_legacy(bytecode: Bytes) -> Self {
        let hash = keccak256(bytecode.as_ref());
        Self::Legacy(LegacyBytecode { hash, bytecode })
    }

    /// Read metadata from bytes
    pub fn read_from_bytes(metadata: &Bytes) -> Option<Self> {
        if metadata.len() < 32 {
            return None;
        }
        Some(match B256::from_slice(&metadata[0..32]) {
            ETHEREUM_METADATA_VERSION_ANALYZED => Self::Analyzed(
                AnalyzedBytecode::deserialize(&metadata[32..])
                    .unwrap_or_else(|_| unreachable!("failed to deserialize analyzed bytecode")),
            ),
            hash => {
                let bytecode = metadata.slice(32..);
                Self::Legacy(LegacyBytecode { hash, bytecode })
            }
        })
    }

    /// Write metadata into bytes
    pub fn write_to_bytes(&self) -> Bytes {
        match self {
            EthereumMetadata::Legacy(legacy_bytecode) => {
                let mut result = vec![];
                result.extend_from_slice(&legacy_bytecode.hash[..]);
                result.extend_from_slice(&legacy_bytecode.bytecode[..]);
                result.into()
            }
            EthereumMetadata::Analyzed(analyzed_bytecode) => {
                let hint_size = analyzed_bytecode.hint_size();
                let mut result = vec![0u8; B256::len_bytes() + hint_size];
                result[0..B256::len_bytes()]
                    .copy_from_slice(&ETHEREUM_METADATA_VERSION_ANALYZED[..]);
                analyzed_bytecode
                    .serialize(&mut result[B256::len_bytes()..])
                    .unwrap_or_else(|_| unreachable!("evm: failed to serialize analyzed bytecode"));
                result.into()
            }
        }
    }

    /// Get the code size
    pub fn code_size(&self) -> usize {
        match self {
            EthereumMetadata::Legacy(bytecode) => bytecode.bytecode.len(),
            EthereumMetadata::Analyzed(bytecode) => bytecode.len(),
        }
    }

    /// Get the code hash
    pub fn code_hash(&self) -> B256 {
        match self {
            EthereumMetadata::Legacy(bytecode) => bytecode.hash,
            EthereumMetadata::Analyzed(bytecode) => bytecode.hash,
        }
    }

    /// Copy EVM bytecode into bytes
    pub fn code_copy(&self) -> Bytes {
        match self {
            EthereumMetadata::Legacy(bytecode) => bytecode.bytecode.clone(),
            EthereumMetadata::Analyzed(bytecode) => bytecode.bytecode.slice(0..bytecode.len()),
        }
    }
}