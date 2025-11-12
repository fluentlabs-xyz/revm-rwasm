use crate::interpreter::ReturnData;
use helpers::reusable_pool::global::VecU8;
use primitives::Bytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::vec::Vec;

/// Default implementation of return data storage for the interpreter.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default)]
pub struct ReturnDataImpl(
    #[cfg(feature = "std")] pub Bytes,
    #[cfg(not(feature = "std"))] pub VecU8,
);

impl ReturnData for ReturnDataImpl {
    #[cfg(feature = "std")]
    fn buffer(&self) -> &Bytes {
        &self.0
    }
    #[cfg(not(feature = "std"))]
    fn buffer(&self) -> &Vec<u8> {
        &self.0
    }

    #[cfg(feature = "std")]
    fn set_buffer(&mut self, bytes: Bytes) {
        self.0 = bytes;
    }
    #[cfg(not(feature = "std"))]
    fn set_buffer(&mut self, bytes: VecU8) {
        self.0 = bytes;
    }
}
