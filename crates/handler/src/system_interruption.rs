use interpreter::{Gas, InterpreterResult};
use primitives::{B256, U256};
use std::ops::Range;

/// A system interruption input params
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInterruptionInputs {
    /// The call identifier (used for recover).
    pub call_id: u32,
    /// Interruptions params (code hash, inputs, gas limits, etc.).
    pub code_hash: B256,
    /// Input range (start, end) for the frame.
    pub input: Range<usize>,
    /// Fuel limit for the frame.
    pub fuel_limit: u64,
    /// The state of the frame (STATE_MAIN or STATE_DEPLOY).
    pub state: u32,
    /// A pointer where fuel params are located.
    pub fuel16_ptr: u32,
    /// A gas snapshot assigned before the interruption.
    /// We need this to calculate the final amount of gas charged for the entire interruption.
    pub gas: Gas,
    /// Precharged system-runtime storage slots (slot, gas_cost) from frame preloading.
    /// Used to return gas for slots that were preloaded but never touched.
    pub preloaded_slot_costs: Option<Vec<(U256, u64)>>,
}

/// An interruption outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemInterruptionOutcome {
    /// Original inputs.
    pub inputs: SystemInterruptionInputs,
    /// An interruption execution result.
    /// It can be empty for frame creation,
    /// where we don't know the result until the frame is executed.
    pub result: Option<InterpreterResult>,
    /// Indicates was the frame halted before execution.
    /// When we do CALL-like op we can halt execution during the frame creation, we
    /// should handle this to forward inside the system runtime to make sure all frames
    /// are terminated gracefully.
    pub halted_frame: bool,
}
