use crate::{interpreter_types::InputsTr, CallInput};
use primitives::{Address, U256};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Inputs for the interpreter that are used for execution of the call.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InputsImpl {
    /// Storage of this account address is being used.
    pub target_address: Address,
    /// Address of the bytecode that is being executed. This field is not used inside Interpreter but it is used
    /// by dependent projects that would need to know the address of the bytecode.
    pub bytecode_address: Option<Address>,
    /// Address of the caller of the call.
    pub caller_address: Address,
    /// Input data for the call.
    pub input: CallInput,
    /// Value of the call.
    pub call_value: U256,
    /// Call depth of the frame this interpreter executes (0 for the first frame).
    pub depth: usize,
    /// Owner of this account when executing a system runtime.
    pub account_owner: Option<Address>,
}

impl InputsImpl {
    /// Returns the effective bytecode address, including a system runtime owner.
    pub fn effective_bytecode_address(&self) -> Address {
        self.account_owner
            .or(self.bytecode_address)
            .unwrap_or(self.target_address)
    }
}

impl InputsTr for InputsImpl {
    fn target_address(&self) -> Address {
        self.target_address
    }

    fn depth(&self) -> usize {
        self.depth
    }

    fn bytecode_address(&self) -> Option<&Address> {
        self.bytecode_address.as_ref()
    }

    fn caller_address(&self) -> Address {
        self.caller_address
    }

    fn input(&self) -> &CallInput {
        &self.input
    }

    fn call_value(&self) -> U256 {
        self.call_value
    }

    fn account_owner_address(&self) -> Option<Address> {
        self.account_owner
    }
}
