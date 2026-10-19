use crate::{eip7702::Eip7702DecodeError, ownable_account::OwnableAccountDecodeError};
use core::fmt;

/// Bytecode decode errors
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BytecodeDecodeError {
    /// EIP-7702 decode error
    Eip7702(Eip7702DecodeError),
    /// Metadata decode error
    OwnableAccount(OwnableAccountDecodeError),
    /// Rwasm decode error
    MalformedRwasmBinary,
}

impl From<Eip7702DecodeError> for BytecodeDecodeError {
    fn from(error: Eip7702DecodeError) -> Self {
        Self::Eip7702(error)
    }
}

impl From<OwnableAccountDecodeError> for BytecodeDecodeError {
    fn from(error: OwnableAccountDecodeError) -> Self {
        Self::OwnableAccount(error)
    }
}

impl core::error::Error for BytecodeDecodeError {}

impl fmt::Display for BytecodeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eip7702(e) => fmt::Display::fmt(e, f),
            Self::OwnableAccount(e) => fmt::Display::fmt(e, f),
            Self::MalformedRwasmBinary => fmt::Display::fmt("malformed rwasm binary", f),
        }
    }
}
