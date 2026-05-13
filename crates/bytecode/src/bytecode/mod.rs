//! Module that contains the bytecode struct with all variants supported by Ethereum mainnet.
//!
//! Those are:
//! - Legacy bytecode with jump table analysis
//! - EIP-7702 bytecode, introduced in Prague and contains address to delegated account

#[cfg(feature = "serde")]
mod serde_impl;

use crate::{
    eip7702::{Eip7702DecodeError, EIP7702_MAGIC_BYTES, EIP7702_VERSION},
    legacy::analyze_legacy,
    opcode,
    ownable_account::{OwnableAccountBytecode, OWNABLE_ACCOUNT_MAGIC_BYTES},
    rwasm::{RwasmBytecode, RWASM_MAGIC_BYTES},
    BytecodeDecodeError, JumpTable,
};
use primitives::{
    alloy_primitives::Sealable, keccak256, Address, Bytes, OnceLock, B256, KECCAK_EMPTY,
};
use std::sync::Arc;

/// Ethereum EVM bytecode.
#[derive(Clone, Debug)]
pub enum Bytecode {
    /// A default legacy bytecode (we keep it here mostly for e2e testing suite, Fluent doesn't use it).
    BytecodeInner(Arc<BytecodeInner>),
    /// A based Rwasm bytecode, used for system precompiles and user smart contracts.
    Rwasm(Arc<RwasmBytecode>),
    /// An ownable account bytecode.
    OwnableAccount(Arc<OwnableAccountBytecode>),
}

/// Inner bytecode representation.
///
/// This struct is flattened to avoid nested allocations. The `kind` field determines
/// how the bytecode should be interpreted.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BytecodeInner {
    /// The kind of bytecode (Legacy or EIP-7702).
    kind: BytecodeKind,
    /// The bytecode bytes.
    ///
    /// For legacy bytecode, this may be padded with zeros at the end.
    /// For EIP-7702 bytecode, this is exactly 23 bytes.
    bytecode: Bytes,
    /// The original length of the bytecode before padding.
    ///
    /// For EIP-7702 bytecode, this is always 23.
    original_len: usize,
    /// The jump table for legacy bytecode. Empty for EIP-7702.
    jump_table: JumpTable,
    /// Cached hash of the original bytecode.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    hash: OnceLock<B256>,
}

/// The kind of bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BytecodeKind {
    /// Legacy analyzed bytecode with jump table.
    #[default]
    LegacyAnalyzed,
    /// EIP-7702 delegated bytecode.
    Eip7702,
    /// Rwasm bytecode.
    Rwasm,
    /// Delegated bytecode metadata.
    OwnableAccount,
}

impl Default for Bytecode {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Bytecode {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.original_byte_slice() == other.original_byte_slice()
    }
}

impl Eq for Bytecode {}

impl core::hash::Hash for Bytecode {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.original_byte_slice().hash(state);
    }
}

impl PartialOrd for Bytecode {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bytecode {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.original_byte_slice().cmp(other.original_byte_slice())
    }
}

impl Sealable for Bytecode {
    #[inline]
    fn hash_slow(&self) -> B256 {
        self.hash_slow()
    }
}

impl Bytecode {
    /// Creates a new legacy analyzed [`Bytecode`] with exactly one STOP opcode.
    #[inline]
    pub fn new() -> Self {
        static DEFAULT_BYTECODE: OnceLock<Bytecode> = OnceLock::new();
        DEFAULT_BYTECODE
            .get_or_init(|| {
                Self::BytecodeInner(Arc::new(BytecodeInner {
                    kind: BytecodeKind::LegacyAnalyzed,
                    bytecode: Bytes::from_static(&[opcode::STOP]),
                    original_len: 0,
                    jump_table: JumpTable::default(),
                    hash: {
                        let hash = OnceLock::new();
                        let _ = hash.set(KECCAK_EMPTY);
                        hash
                    },
                }))
            })
            .clone()
    }

    /// Creates a new legacy [`Bytecode`] by analyzing raw bytes.
    #[inline]
    pub fn new_legacy(raw: Bytes) -> Self {
        if raw.is_empty() {
            return Self::new();
        }

        let original_len = raw.len();
        let (jump_table, bytecode) = analyze_legacy(raw);
        Self::BytecodeInner(Arc::new(BytecodeInner {
            kind: BytecodeKind::LegacyAnalyzed,
            original_len,
            bytecode,
            jump_table,
            hash: OnceLock::new(),
        }))
    }

    /// Creates a new raw [`Bytecode`].
    ///
    /// # Panics
    ///
    /// Panics if bytecode is in incorrect format. If you want to handle errors use [`Self::new_raw_checked`].
    #[inline]
    pub fn new_raw(bytecode: Bytes) -> Self {
        Self::new_raw_checked(bytecode).expect("Expect correct bytecode")
    }

    /// Creates a new EIP-7702 [`Bytecode`] from [`Address`].
    #[inline]
    pub fn new_eip7702(address: Address) -> Self {
        let raw: Bytes = [EIP7702_MAGIC_BYTES, &[EIP7702_VERSION], &address[..]]
            .concat()
            .into();
        Self::BytecodeInner(Arc::new(BytecodeInner {
            kind: BytecodeKind::Eip7702,
            original_len: raw.len(),
            bytecode: raw,
            jump_table: JumpTable::default(),
            hash: OnceLock::new(),
        }))
    }

    /// Creates new Rwasm [`Bytecode`]
    #[inline]
    pub fn new_rwasm(raw: Bytes) -> Self {
        Self::Rwasm(Arc::new(RwasmBytecode::new(raw).unwrap()))
    }

    /// Creates new ownable account [`Bytecode`]
    #[inline]
    pub fn new_ownable_account(owner_address: Address, metadata: Bytes) -> Self {
        Self::OwnableAccount(Arc::new(OwnableAccountBytecode::new(
            owner_address,
            metadata,
        )))
    }

    /// Creates a new raw [`Bytecode`].
    ///
    /// Returns an error on incorrect bytecode format.
    #[inline]
    pub fn new_raw_checked(bytes: Bytes) -> Result<Self, BytecodeDecodeError> {
        // Additional bytecode types for Fluent (rWasm + Ownable Bytecode)
        if bytes.starts_with(&RWASM_MAGIC_BYTES) {
            return Ok(Self::Rwasm(Arc::new(RwasmBytecode::new(bytes)?)));
        } else if bytes.starts_with(&OWNABLE_ACCOUNT_MAGIC_BYTES) {
            return Ok(Self::OwnableAccount(Arc::new(
                OwnableAccountBytecode::new_raw(bytes)?,
            )));
        }
        if bytes.starts_with(EIP7702_MAGIC_BYTES) {
            Self::new_eip7702_raw(bytes).map_err(Into::into)
        } else {
            Ok(Self::new_legacy(bytes))
        }
    }

    /// Creates a new EIP-7702 [`Bytecode`] from raw bytes.
    ///
    /// Returns an error if the bytes are not valid EIP-7702 bytecode.
    #[inline]
    pub fn new_eip7702_raw(bytes: Bytes) -> Result<Self, Eip7702DecodeError> {
        if bytes.len() != 23 {
            return Err(Eip7702DecodeError::InvalidLength);
        }
        if !bytes.starts_with(EIP7702_MAGIC_BYTES) {
            return Err(Eip7702DecodeError::InvalidMagic);
        }
        if bytes[2] != EIP7702_VERSION {
            return Err(Eip7702DecodeError::UnsupportedVersion);
        }
        Ok(Self::BytecodeInner(Arc::new(BytecodeInner {
            kind: BytecodeKind::Eip7702,
            original_len: bytes.len(),
            bytecode: bytes,
            jump_table: JumpTable::default(),
            hash: OnceLock::new(),
        })))
    }

    /// Create new checked bytecode from pre-analyzed components.
    ///
    /// # Panics
    ///
    /// * If `original_len` is greater than `bytecode.len()`
    /// * If jump table length is less than `original_len`
    /// * If bytecode is empty
    #[inline]
    pub fn new_analyzed(bytecode: Bytes, original_len: usize, jump_table: JumpTable) -> Self {
        assert!(
            original_len <= bytecode.len(),
            "original_len is greater than bytecode length"
        );
        assert!(
            original_len <= jump_table.len(),
            "jump table length is less than original length"
        );
        assert!(!bytecode.is_empty(), "bytecode cannot be empty");
        Self::BytecodeInner(Arc::new(BytecodeInner {
            kind: BytecodeKind::LegacyAnalyzed,
            bytecode,
            original_len,
            jump_table,
            hash: OnceLock::new(),
        }))
    }

    /// Returns the kind of bytecode.
    #[inline]
    pub fn kind(&self) -> BytecodeKind {
        match self {
            Bytecode::BytecodeInner(inner) => inner.kind,
            Bytecode::Rwasm(_) => BytecodeKind::Rwasm,
            Bytecode::OwnableAccount(_) => BytecodeKind::OwnableAccount,
        }
    }

    /// Returns `true` if bytecode is legacy.
    #[inline]
    pub fn is_legacy(&self) -> bool {
        self.kind() == BytecodeKind::LegacyAnalyzed
    }

    /// Returns `true` if bytecode is rwasm.
    #[inline]
    pub fn is_rwasm(&self) -> bool {
        self.kind() == BytecodeKind::Rwasm
    }

    /// Returns `true` if bytecode is an ownable account.
    #[inline]
    pub fn is_ownable_account(&self) -> bool {
        self.kind() == BytecodeKind::OwnableAccount
    }

    /// Returns `true` if bytecode is EIP-7702.
    #[inline]
    pub fn is_eip7702(&self) -> bool {
        self.kind() == BytecodeKind::Eip7702
    }

    /// Returns the EIP-7702 delegated address if this is EIP-7702 bytecode.
    #[inline]
    pub fn eip7702_address(&self) -> Option<Address> {
        match self {
            Bytecode::BytecodeInner(inner) if self.is_eip7702() => {
                Some(Address::from_slice(&inner.bytecode[3..23]))
            }
            _ => None,
        }
    }

    /// Returns jump table if bytecode is legacy analyzed.
    #[inline]
    pub fn legacy_jump_table(&self) -> Option<&JumpTable> {
        match self {
            Bytecode::BytecodeInner(inner) if self.is_legacy() => Some(&inner.jump_table),
            _ => None,
        }
    }

    /// Calculates or returns cached hash of the bytecode.
    #[inline]
    pub fn hash_slow(&self) -> B256 {
        match self {
            Bytecode::BytecodeInner(inner) => *inner
                .hash
                .get_or_init(|| keccak256(&inner.bytecode[..inner.original_len])),
            Bytecode::Rwasm(inner) => *inner.hash.get_or_init(|| keccak256(&*inner.raw)),
            Bytecode::OwnableAccount(inner) => *inner.hash.get_or_init(|| keccak256(&*inner.raw)),
        }
    }

    /// Returns a reference to the bytecode bytes.
    ///
    /// For legacy bytecode, this includes padding. For EIP-7702, this is the raw bytes.
    #[inline]
    pub fn bytecode(&self) -> &Bytes {
        match self {
            Bytecode::BytecodeInner(inner) => &inner.bytecode,
            Bytecode::Rwasm(inner) => &inner.raw,
            Bytecode::OwnableAccount(inner) => &inner.raw,
        }
    }

    /// Pointer to the bytecode bytes.
    #[inline]
    pub fn bytecode_ptr(&self) -> *const u8 {
        match self {
            Bytecode::BytecodeInner(inner) => inner.bytecode.as_ptr(),
            Bytecode::Rwasm(inner) => inner.raw.as_ptr(),
            Bytecode::OwnableAccount(inner) => inner.raw.as_ptr(),
        }
    }

    /// Returns a clone of the bytecode bytes.
    #[inline]
    pub fn bytes(&self) -> Bytes {
        match self {
            Bytecode::BytecodeInner(inner) => inner.bytecode.clone(),
            Bytecode::Rwasm(inner) => inner.raw.clone(),
            Bytecode::OwnableAccount(inner) => inner.raw.clone(),
        }
    }

    /// Returns a reference to the bytecode bytes.
    #[inline]
    pub fn bytes_ref(&self) -> &Bytes {
        match self {
            Bytecode::BytecodeInner(inner) => &inner.bytecode,
            Bytecode::Rwasm(inner) => &inner.raw,
            Bytecode::OwnableAccount(inner) => &inner.raw,
        }
    }

    /// Returns the bytecode as a slice.
    #[inline]
    pub fn bytes_slice(&self) -> &[u8] {
        match self {
            Bytecode::BytecodeInner(inner) => &inner.bytecode,
            Bytecode::Rwasm(inner) => &inner.raw,
            Bytecode::OwnableAccount(inner) => &inner.raw,
        }
    }

    /// Returns the original bytecode without padding.
    #[inline]
    pub fn original_bytes(&self) -> Bytes {
        match self {
            Bytecode::BytecodeInner(inner) => inner.bytecode.slice(..inner.original_len),
            Bytecode::Rwasm(inner) => inner.raw.clone(),
            Bytecode::OwnableAccount(inner) => inner.raw.clone(),
        }
    }

    /// Returns the original bytecode as a byte slice without padding.
    #[inline]
    pub fn original_byte_slice(&self) -> &[u8] {
        match self {
            Bytecode::BytecodeInner(inner) => &inner.bytecode[..inner.original_len],
            Bytecode::Rwasm(inner) => &inner.raw,
            Bytecode::OwnableAccount(inner) => &inner.raw,
        }
    }

    /// Returns the length of the original bytes (without padding).
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Bytecode::BytecodeInner(inner) => inner.original_len,
            Bytecode::Rwasm(inner) => inner.raw.len(),
            Bytecode::OwnableAccount(inner) => inner.raw.len(),
        }
    }

    /// Returns whether the bytecode is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Bytecode::BytecodeInner(inner) => inner.original_len == 0,
            Bytecode::Rwasm(inner) => inner.raw.len() == 0,
            Bytecode::OwnableAccount(inner) => inner.raw.len() == 0,
        }
    }

    /// Returns an iterator over the opcodes in this bytecode, skipping immediates.
    #[inline]
    pub fn iter_opcodes(&self) -> crate::BytecodeIterator<'_> {
        crate::BytecodeIterator::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{eip7702::Eip7702DecodeError, opcode};
    use bitvec::{bitvec, order::Lsb0};
    use primitives::bytes;

    #[test]
    fn test_new_empty() {
        for bytecode in [
            Bytecode::default(),
            Bytecode::new(),
            Bytecode::new().clone(),
            Bytecode::new_legacy(Bytes::new()),
        ] {
            assert_eq!(bytecode.kind(), BytecodeKind::LegacyAnalyzed);
            assert_eq!(bytecode.len(), 0);
            assert_eq!(bytecode.bytes_slice(), [opcode::STOP]);
        }
    }

    #[test]
    fn test_new_analyzed() {
        let raw = Bytes::from_static(&[opcode::PUSH1, 0x01]);
        let bytecode = Bytecode::new_legacy(raw);
        let _ = Bytecode::new_analyzed(
            bytecode.bytecode().clone(),
            bytecode.len(),
            bytecode.legacy_jump_table().unwrap().clone(),
        );
    }

    #[test]
    #[should_panic(expected = "original_len is greater than bytecode length")]
    fn test_panic_on_large_original_len() {
        let bytecode = Bytecode::new_legacy(Bytes::from_static(&[opcode::PUSH1, 0x01]));
        let _ = Bytecode::new_analyzed(
            bytecode.bytecode().clone(),
            100,
            bytecode.legacy_jump_table().unwrap().clone(),
        );
    }

    #[test]
    #[should_panic(expected = "jump table length is less than original length")]
    fn test_panic_on_short_jump_table() {
        let bytecode = Bytecode::new_legacy(Bytes::from_static(&[opcode::PUSH1, 0x01]));
        let jump_table = JumpTable::new(bitvec![u8, Lsb0; 0; 1]);
        let _ = Bytecode::new_analyzed(bytecode.bytecode().clone(), bytecode.len(), jump_table);
    }

    #[test]
    #[should_panic(expected = "bytecode cannot be empty")]
    fn test_panic_on_empty_bytecode() {
        let bytecode = Bytes::from_static(&[]);
        let jump_table = JumpTable::new(bitvec![u8, Lsb0; 0; 0]);
        let _ = Bytecode::new_analyzed(bytecode, 0, jump_table);
    }

    #[test]
    fn eip7702_sanity_decode() {
        let raw = bytes!("ef01deadbeef");
        assert_eq!(
            Bytecode::new_eip7702_raw(raw),
            Err(Eip7702DecodeError::InvalidLength)
        );

        let raw = bytes!("ef0101deadbeef00000000000000000000000000000000");
        assert_eq!(
            Bytecode::new_eip7702_raw(raw),
            Err(Eip7702DecodeError::UnsupportedVersion)
        );

        let raw = bytes!("ef0100deadbeef00000000000000000000000000000000");
        let bytecode = Bytecode::new_eip7702_raw(raw.clone()).unwrap();
        assert!(bytecode.is_eip7702());
        assert_eq!(
            bytecode.eip7702_address(),
            Some(Address::from_slice(&raw[3..]))
        );
        assert_eq!(bytecode.original_bytes(), raw);
    }

    #[test]
    fn eip7702_from_address() {
        let address = Address::new([0x01; 20]);
        let bytecode = Bytecode::new_eip7702(address);
        assert_eq!(bytecode.eip7702_address(), Some(address));
        assert_eq!(
            bytecode.original_bytes(),
            bytes!("ef01000101010101010101010101010101010101010101")
        );
    }
}
