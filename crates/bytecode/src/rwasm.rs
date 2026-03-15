use crate::BytecodeDecodeError;
use primitives::Bytes;
use rwasm::RwasmModule;

/// Rwasm magic number in array form.
pub static RWASM_MAGIC_BYTES: Bytes = primitives::bytes!("ef52");
/// Wasm magic number in array form.
pub static WASM_MAGIC_BYTES: Bytes = primitives::bytes!("0061736d");

/// rWasm bytecode wrapper.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RwasmBytecode {
    /// A parsed rWasm bytecode (with code & data sections).
    pub module: RwasmModule,
    /// Raw rWasm bytes.
    pub raw: Bytes,
}

impl RwasmBytecode {
    /// Create new rWasm module from bytes.
    pub fn new(raw: Bytes) -> Result<Self, BytecodeDecodeError> {
        let (module, _) = RwasmModule::new_checked(raw.as_ref()).map_err(|_| BytecodeDecodeError::Rwasm)?;
        Ok(Self { module, raw })
    }

    /// Return raw rWasm bytes
    #[inline]
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}
