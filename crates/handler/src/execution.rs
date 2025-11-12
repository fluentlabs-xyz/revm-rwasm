use context_interface::Transaction;
use helpers::reusable_pool::global::VecU8;
use interpreter::{
    CallInput, CallInputs, CallScheme, CallValue, CreateInputs, CreateScheme, FrameInput,
};
use primitives::TxKind;
use std::boxed::Box;

/// Creates the first [`FrameInput`] from the transaction, spec and gas limit.
pub fn create_init_frame(tx: &impl Transaction, gas_limit: u64) -> FrameInput {
    let input = tx.input().clone();

    match tx.kind() {
        TxKind::Call(target_address) => FrameInput::Call(Box::new(CallInputs {
            #[cfg(feature = "std")]
            input: CallInput::Bytes(input),
            #[cfg(not(feature = "std"))]
            input: CallInput::Bytes(VecU8::try_from_slice(input).expect("enough cap")),
            gas_limit,
            target_address,
            bytecode_address: target_address,
            caller: tx.caller(),
            value: CallValue::Transfer(tx.value()),
            scheme: CallScheme::Call,
            is_static: false,
            return_memory_offset: 0..0,
        })),
        TxKind::Create => FrameInput::Create(Box::new(CreateInputs {
            caller: tx.caller(),
            scheme: CreateScheme::Create,
            value: tx.value(),
            init_code: input,
            gas_limit,
        })),
    }
}
