use crate::BytecodeDecodeError;
use primitives::{Bytes, OnceLock, B256};
use rwasm::RwasmModule;

/// Rwasm magic number in array form.
pub static RWASM_MAGIC_BYTES: Bytes = primitives::bytes!("ef52");
/// Wasm magic number in array form.
pub static WASM_MAGIC_BYTES: Bytes = primitives::bytes!("0061736d");

/// rWasm bytecode wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RwasmBytecode {
    /// A parsed rWasm bytecode (with code & data sections).
    pub module: RwasmModule,
    /// Raw rWasm bytes.
    pub raw: Bytes,
    /// Cached hash of the original bytecode.
    #[cfg_attr(feature = "serde", serde(skip, default))]
    pub(crate) hash: OnceLock<B256>,
}

impl RwasmBytecode {
    /// Create a new rWasm module from bytes.
    pub fn new(raw: Bytes) -> Result<Self, BytecodeDecodeError> {
        let (module, _) = RwasmModule::new_checked(raw.as_ref())
            .map_err(|_| BytecodeDecodeError::MalformedRwasmBinary)?;
        Ok(Self {
            module,
            raw,
            hash: OnceLock::new(),
        })
    }

    /// Return raw rWasm bytes
    #[inline]
    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}
