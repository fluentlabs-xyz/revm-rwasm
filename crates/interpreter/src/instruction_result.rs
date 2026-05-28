use context_interface::{
    journaled_state::TransferError,
    result::{HaltReason, OutOfGasError, SuccessReason},
};
use core::fmt::Debug;

/// Result of executing an EVM instruction.
///
/// This enum represents all possible outcomes when executing an instruction,
/// including successful execution, reverts, and various error conditions.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InstructionResult {
    /// Encountered a `STOP` opcode
    #[default]
    Stop = 1, // Start at 1 so that `Result<(), _>::Ok(())` is 0.
    /// Return from the current call.
    Return,
    /// Self-destruct the current contract.
    SelfDestruct,

    // Revert Codes
    /// Revert the transaction.
    Revert = 0x10,
    /// Exceeded maximum call depth.
    CallTooDeep,
    /// Insufficient funds for transfer.
    OutOfFunds,
    /// Revert if `CREATE`/`CREATE2` starts with `0xEF00`.
    CreateInitCodeStartingEF00,
    /// Invalid EVM Object Format (EOF) init code.
    InvalidEOFInitCode,
    /// `ExtDelegateCall` calling a non EOF contract.
    InvalidExtDelegateCallTarget,

    // Error Codes
    /// Out of gas error.
    OutOfGas = 0x20,
    /// Out of gas error encountered during memory expansion.
    MemoryOOG,
    /// The memory limit of the EVM has been exceeded.
    MemoryLimitOOG,
    /// Out of gas error encountered during the execution of a precompiled contract.
    PrecompileOOG,
    /// Out of gas error encountered while calling an invalid operand.
    InvalidOperandOOG,
    /// Out of gas error encountered while checking for reentrancy sentry.
    ReentrancySentryOOG,
    /// Unknown or invalid opcode.
    OpcodeNotFound,
    /// Invalid `CALL` with value transfer in static context.
    CallNotAllowedInsideStatic,
    /// Invalid state modification in static call.
    StateChangeDuringStaticCall,
    /// An undefined bytecode value encountered during execution.
    InvalidFEOpcode,
    /// Invalid jump destination. Dynamic jumps points to invalid not jumpdest opcode.
    InvalidJump,
    /// The feature or opcode is not activated in this version of the EVM.
    NotActivated,
    /// Attempting to pop a value from an empty stack.
    StackUnderflow,
    /// Attempting to push a value onto a full stack.
    StackOverflow,
    /// Invalid memory or storage offset.
    OutOfOffset,
    /// Address collision during contract creation.
    CreateCollision,
    /// Payment amount overflow.
    OverflowPayment,
    /// Error in precompiled contract execution.
    PrecompileError,
    /// Nonce overflow.
    NonceOverflow,
    /// Exceeded contract size limit during creation.
    CreateContractSizeLimit,
    /// Created contract starts with invalid bytes (`0xEF`).
    CreateContractStartingWithEF,
    /// Exceeded init code size limit (EIP-3860:  Limit and meter initcode).
    CreateInitCodeSizeLimit,
    /// Fatal external error. Returned by database.
    FatalExternalError,
    /// Invalid encoding of an instruction's immediate operand.
    InvalidImmediateEncoding,

    // Fluentbase Error Codes
    /// Function can only be invoked as the root entry call
    RootCallOnly = 0x80,
    /// Builtin function received malformed or invalid parameters
    MalformedBuiltinParams,
    /// Exceeded maximum allowed call stack depth
    CallDepthOverflow,
    /// Exit code must be non-negative, but a negative value was used
    NonNegativeExitCode,
    /// Generic catch-all error for unknown failures
    UnknownError,
    /// I/O operation tried to read/write outside allowed buffer bounds
    InputOutputOutOfBounds,

    // rWasm Trap Codes
    /// Execution reached a code path marked as unreachable
    UnreachableCodeReached = 0x90,
    /// Memory access outside the allocated memory range
    MemoryOutOfBounds,
    /// Table index access outside the allocated table range
    TableOutOfBounds,
    /// Indirect function call attempted with a null function reference
    IndirectCallToNull,
    /// Division or remainder by zero occurred
    IntegerDivisionByZero,
    /// Integer arithmetic operation overflowed the allowed range
    IntegerOverflow,
    /// Invalid conversion to integer (e.g., from NaN or out-of-range value)
    BadConversionToInteger,
    /// Function signature mismatch in a call
    BadSignature,
    /// Execution ran out of allocated fuel/gas
    OutOfFuel,
    /// Call an undefined or unregistered external function
    UnknownExternalFunction,
}

impl From<TransferError> for InstructionResult {
    fn from(e: TransferError) -> Self {
        match e {
            TransferError::OutOfFunds => InstructionResult::OutOfFunds,
            TransferError::OverflowPayment => InstructionResult::OverflowPayment,
            TransferError::CreateCollision => InstructionResult::CreateCollision,
        }
    }
}

impl From<SuccessReason> for InstructionResult {
    fn from(value: SuccessReason) -> Self {
        match value {
            SuccessReason::Return => InstructionResult::Return,
            SuccessReason::Stop => InstructionResult::Stop,
            SuccessReason::SelfDestruct => InstructionResult::SelfDestruct,
        }
    }
}

impl From<HaltReason> for InstructionResult {
    fn from(value: HaltReason) -> Self {
        match value {
            HaltReason::OutOfGas(error) => match error {
                OutOfGasError::Basic => Self::OutOfGas,
                OutOfGasError::InvalidOperand => Self::InvalidOperandOOG,
                OutOfGasError::Memory => Self::MemoryOOG,
                OutOfGasError::MemoryLimit => Self::MemoryLimitOOG,
                OutOfGasError::Precompile => Self::PrecompileOOG,
                OutOfGasError::ReentrancySentry => Self::ReentrancySentryOOG,
            },
            HaltReason::OpcodeNotFound => Self::OpcodeNotFound,
            HaltReason::InvalidFEOpcode => Self::InvalidFEOpcode,
            HaltReason::InvalidJump => Self::InvalidJump,
            HaltReason::NotActivated => Self::NotActivated,
            HaltReason::StackOverflow => Self::StackOverflow,
            HaltReason::StackUnderflow => Self::StackUnderflow,
            HaltReason::OutOfOffset => Self::OutOfOffset,
            HaltReason::CreateCollision => Self::CreateCollision,
            HaltReason::PrecompileError => Self::PrecompileError,
            HaltReason::PrecompileErrorWithContext(_) => Self::PrecompileError,
            HaltReason::NonceOverflow => Self::NonceOverflow,
            HaltReason::CreateContractSizeLimit => Self::CreateContractSizeLimit,
            HaltReason::CreateContractStartingWithEF => Self::CreateContractStartingWithEF,
            HaltReason::CreateInitCodeSizeLimit => Self::CreateInitCodeSizeLimit,
            HaltReason::OverflowPayment => Self::OverflowPayment,
            HaltReason::StateChangeDuringStaticCall => Self::StateChangeDuringStaticCall,
            HaltReason::CallNotAllowedInsideStatic => Self::CallNotAllowedInsideStatic,
            HaltReason::OutOfFunds => Self::OutOfFunds,
            HaltReason::CallTooDeep => Self::CallTooDeep,
        }
    }
}

fn instruction_result_to_halt_reason(value: InstructionResult) -> HaltReason {
    match value {
        InstructionResult::CallTooDeep => HaltReason::CallTooDeep,
        InstructionResult::OutOfFunds => HaltReason::OutOfFunds,
        InstructionResult::OutOfGas => HaltReason::OutOfGas(OutOfGasError::Basic),
        InstructionResult::MemoryLimitOOG => HaltReason::OutOfGas(OutOfGasError::MemoryLimit),
        InstructionResult::MemoryOOG => HaltReason::OutOfGas(OutOfGasError::Memory),
        InstructionResult::PrecompileOOG => HaltReason::OutOfGas(OutOfGasError::Precompile),
        InstructionResult::InvalidOperandOOG => HaltReason::OutOfGas(OutOfGasError::InvalidOperand),
        InstructionResult::ReentrancySentryOOG => {
            HaltReason::OutOfGas(OutOfGasError::ReentrancySentry)
        }
        InstructionResult::OpcodeNotFound | InstructionResult::InvalidImmediateEncoding => {
            HaltReason::OpcodeNotFound
        }
        InstructionResult::CallNotAllowedInsideStatic => HaltReason::CallNotAllowedInsideStatic,
        InstructionResult::StateChangeDuringStaticCall => HaltReason::StateChangeDuringStaticCall,
        InstructionResult::InvalidFEOpcode => HaltReason::InvalidFEOpcode,
        InstructionResult::InvalidJump => HaltReason::InvalidJump,
        InstructionResult::NotActivated => HaltReason::NotActivated,
        InstructionResult::StackUnderflow => HaltReason::StackUnderflow,
        InstructionResult::StackOverflow => HaltReason::StackOverflow,
        InstructionResult::OutOfOffset | InstructionResult::InputOutputOutOfBounds => {
            HaltReason::OutOfOffset
        }
        InstructionResult::CreateCollision => HaltReason::CreateCollision,
        InstructionResult::OverflowPayment | InstructionResult::IntegerOverflow => {
            HaltReason::OverflowPayment
        }
        InstructionResult::PrecompileError => HaltReason::PrecompileError,
        InstructionResult::NonceOverflow => HaltReason::NonceOverflow,
        InstructionResult::CreateContractSizeLimit => HaltReason::CreateContractSizeLimit,
        InstructionResult::CreateContractStartingWithEF => HaltReason::CreateContractStartingWithEF,
        InstructionResult::CreateInitCodeSizeLimit => HaltReason::CreateInitCodeSizeLimit,
        InstructionResult::RootCallOnly => {
            HaltReason::PrecompileErrorWithContext("RootCallOnly".into())
        }
        InstructionResult::MalformedBuiltinParams => {
            HaltReason::PrecompileErrorWithContext("MalformedBuiltinParams".into())
        }
        InstructionResult::CallDepthOverflow => HaltReason::CallTooDeep,
        InstructionResult::NonNegativeExitCode => {
            HaltReason::PrecompileErrorWithContext("NonNegativeExitCode".into())
        }
        InstructionResult::UnknownError => {
            HaltReason::PrecompileErrorWithContext("UnknownError".into())
        }
        InstructionResult::UnreachableCodeReached => {
            HaltReason::PrecompileErrorWithContext("UnreachableCodeReached".into())
        }
        InstructionResult::MemoryOutOfBounds => {
            HaltReason::PrecompileErrorWithContext("MemoryOutOfBounds".into())
        }
        InstructionResult::TableOutOfBounds => {
            HaltReason::PrecompileErrorWithContext("TableOutOfBounds".into())
        }
        InstructionResult::IndirectCallToNull => {
            HaltReason::PrecompileErrorWithContext("IndirectCallToNull".into())
        }
        InstructionResult::IntegerDivisionByZero => {
            HaltReason::PrecompileErrorWithContext("IntegerDivisionByZero".into())
        }
        InstructionResult::BadConversionToInteger => {
            HaltReason::PrecompileErrorWithContext("BadConversionToInteger".into())
        }
        InstructionResult::BadSignature => {
            HaltReason::PrecompileErrorWithContext("BadSignature".into())
        }
        InstructionResult::OutOfFuel => HaltReason::OutOfGas(OutOfGasError::Basic),
        InstructionResult::UnknownExternalFunction => {
            HaltReason::PrecompileErrorWithContext("UnknownExternalFunction".into())
        }
        InstructionResult::Stop
        | InstructionResult::Return
        | InstructionResult::SelfDestruct
        | InstructionResult::Revert
        | InstructionResult::CreateInitCodeStartingEF00
        | InstructionResult::InvalidEOFInitCode
        | InstructionResult::FatalExternalError
        | InstructionResult::InvalidExtDelegateCallTarget => HaltReason::PrecompileError,
    }
}

/// Macro that matches all successful instruction results.
/// Used in pattern matching to handle all successful execution outcomes.
#[macro_export]
macro_rules! return_ok {
    () => {
        $crate::InstructionResult::Stop
            | $crate::InstructionResult::Return
            | $crate::InstructionResult::SelfDestruct
    };
}

/// Macro that matches all revert instruction results.
/// Used in pattern matching to handle all revert outcomes.
#[macro_export]
macro_rules! return_revert {
    () => {
        $crate::InstructionResult::Revert
            | $crate::InstructionResult::CallTooDeep
            | $crate::InstructionResult::OutOfFunds
            | $crate::InstructionResult::InvalidEOFInitCode
            | $crate::InstructionResult::CreateInitCodeStartingEF00
            | $crate::InstructionResult::InvalidExtDelegateCallTarget
    };
}

/// Macro that matches all error instruction results.
/// Used in pattern matching to handle all error outcomes.
#[macro_export]
macro_rules! return_error {
    () => {
        $crate::InstructionResult::OutOfGas
            | $crate::InstructionResult::MemoryOOG
            | $crate::InstructionResult::MemoryLimitOOG
            | $crate::InstructionResult::PrecompileOOG
            | $crate::InstructionResult::InvalidOperandOOG
            | $crate::InstructionResult::ReentrancySentryOOG
            | $crate::InstructionResult::OpcodeNotFound
            | $crate::InstructionResult::CallNotAllowedInsideStatic
            | $crate::InstructionResult::StateChangeDuringStaticCall
            | $crate::InstructionResult::InvalidFEOpcode
            | $crate::InstructionResult::InvalidJump
            | $crate::InstructionResult::NotActivated
            | $crate::InstructionResult::StackUnderflow
            | $crate::InstructionResult::StackOverflow
            | $crate::InstructionResult::OutOfOffset
            | $crate::InstructionResult::CreateCollision
            | $crate::InstructionResult::OverflowPayment
            | $crate::InstructionResult::PrecompileError
            | $crate::InstructionResult::NonceOverflow
            | $crate::InstructionResult::CreateContractSizeLimit
            | $crate::InstructionResult::CreateContractStartingWithEF
            | $crate::InstructionResult::CreateInitCodeSizeLimit
            | $crate::InstructionResult::FatalExternalError
            | $crate::InstructionResult::InvalidImmediateEncoding
            | $crate::InstructionResult::RootCallOnly
            | $crate::InstructionResult::MalformedBuiltinParams
            | $crate::InstructionResult::CallDepthOverflow
            | $crate::InstructionResult::NonNegativeExitCode
            | $crate::InstructionResult::UnknownError
            | $crate::InstructionResult::InputOutputOutOfBounds
            | $crate::InstructionResult::UnreachableCodeReached
            | $crate::InstructionResult::MemoryOutOfBounds
            | $crate::InstructionResult::TableOutOfBounds
            | $crate::InstructionResult::IndirectCallToNull
            | $crate::InstructionResult::IntegerDivisionByZero
            | $crate::InstructionResult::IntegerOverflow
            | $crate::InstructionResult::BadConversionToInteger
            | $crate::InstructionResult::BadSignature
            | $crate::InstructionResult::OutOfFuel
            | $crate::InstructionResult::UnknownExternalFunction
    };
}

impl InstructionResult {
    /// Returns whether the result is a success.
    #[inline]
    pub const fn is_ok(self) -> bool {
        matches!(self, return_ok!())
    }

    #[inline]
    /// Returns whether the result is a success or revert (not an error).
    pub const fn is_ok_or_revert(self) -> bool {
        matches!(self, return_ok!() | return_revert!())
    }

    /// Returns whether the result is a revert.
    #[inline]
    pub const fn is_revert(self) -> bool {
        matches!(self, return_revert!())
    }

    /// Returns whether the result is an error.
    #[inline]
    pub const fn is_error(self) -> bool {
        matches!(self, return_error!())
    }
}

/// Internal results that are not exposed externally
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum InternalResult {
    /// Internal CREATE/CREATE starts with 0xEF00
    CreateInitCodeStartingEF00,
    /// Internal to ExtDelegateCall
    InvalidExtDelegateCallTarget,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
/// Represents the outcome of instruction execution, distinguishing between
/// success, revert, halt (error), fatal external errors, and internal results.
pub enum SuccessOrHalt<HaltReasonTr> {
    /// Successful execution with the specific success reason.
    Success(SuccessReason),
    /// Execution reverted.
    Revert,
    /// Execution halted due to an error.
    Halt(HaltReasonTr),
    /// Fatal external error occurred.
    FatalExternalError,
    /// Internal execution result not exposed externally.
    Internal(InternalResult),
}

impl<HaltReasonTr> SuccessOrHalt<HaltReasonTr> {
    /// Returns true if the transaction returned successfully without halts.
    #[inline]
    pub fn is_success(self) -> bool {
        matches!(self, SuccessOrHalt::Success(_))
    }

    /// Returns the [SuccessReason] value if this a successful result
    #[inline]
    pub fn to_success(self) -> Option<SuccessReason> {
        match self {
            SuccessOrHalt::Success(reason) => Some(reason),
            _ => None,
        }
    }

    /// Returns true if the transaction reverted.
    #[inline]
    pub fn is_revert(self) -> bool {
        matches!(self, SuccessOrHalt::Revert)
    }

    /// Returns true if the EVM has experienced an exceptional halt
    #[inline]
    pub fn is_halt(self) -> bool {
        matches!(self, SuccessOrHalt::Halt(_))
    }

    /// Returns the [HaltReason] value the EVM has experienced an exceptional halt
    #[inline]
    pub fn to_halt(self) -> Option<HaltReasonTr> {
        match self {
            SuccessOrHalt::Halt(reason) => Some(reason),
            _ => None,
        }
    }
}

impl<HALT: From<HaltReason>> From<HaltReason> for SuccessOrHalt<HALT> {
    fn from(reason: HaltReason) -> Self {
        SuccessOrHalt::Halt(reason.into())
    }
}

impl<HALT: From<HaltReason>> From<InstructionResult> for SuccessOrHalt<HALT> {
    fn from(result: InstructionResult) -> Self {
        match result {
            InstructionResult::Stop => Self::Success(SuccessReason::Stop),
            InstructionResult::Return => Self::Success(SuccessReason::Return),
            InstructionResult::SelfDestruct => Self::Success(SuccessReason::SelfDestruct),
            InstructionResult::Revert => Self::Revert,
            InstructionResult::CreateInitCodeStartingEF00 => Self::Revert,
            InstructionResult::CallTooDeep
            | InstructionResult::OutOfFunds
            | InstructionResult::OutOfGas
            | InstructionResult::MemoryLimitOOG
            | InstructionResult::MemoryOOG
            | InstructionResult::PrecompileOOG
            | InstructionResult::InvalidOperandOOG
            | InstructionResult::ReentrancySentryOOG
            | InstructionResult::OpcodeNotFound
            | InstructionResult::CallNotAllowedInsideStatic
            | InstructionResult::StateChangeDuringStaticCall
            | InstructionResult::InvalidFEOpcode
            | InstructionResult::InvalidJump
            | InstructionResult::NotActivated
            | InstructionResult::StackUnderflow
            | InstructionResult::StackOverflow
            | InstructionResult::OutOfOffset
            | InstructionResult::CreateCollision
            | InstructionResult::OverflowPayment
            | InstructionResult::PrecompileError
            | InstructionResult::NonceOverflow
            | InstructionResult::CreateContractSizeLimit
            | InstructionResult::CreateContractStartingWithEF
            | InstructionResult::CreateInitCodeSizeLimit => {
                Self::Halt(instruction_result_to_halt_reason(result).into())
            }
            // TODO : (EOF) Add proper Revert subtype.
            InstructionResult::InvalidEOFInitCode => Self::Revert,
            InstructionResult::FatalExternalError => Self::FatalExternalError,
            InstructionResult::InvalidExtDelegateCallTarget => {
                Self::Internal(InternalResult::InvalidExtDelegateCallTarget)
            }
            InstructionResult::InvalidImmediateEncoding
            | InstructionResult::RootCallOnly
            | InstructionResult::MalformedBuiltinParams
            | InstructionResult::CallDepthOverflow
            | InstructionResult::NonNegativeExitCode
            | InstructionResult::UnknownError
            | InstructionResult::InputOutputOutOfBounds
            | InstructionResult::UnreachableCodeReached
            | InstructionResult::MemoryOutOfBounds
            | InstructionResult::TableOutOfBounds
            | InstructionResult::IndirectCallToNull
            | InstructionResult::IntegerDivisionByZero
            | InstructionResult::IntegerOverflow
            | InstructionResult::BadConversionToInteger
            | InstructionResult::BadSignature
            | InstructionResult::OutOfFuel
            | InstructionResult::UnknownExternalFunction => {
                Self::Halt(instruction_result_to_halt_reason(result).into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{InstructionResult, SuccessOrHalt};
    use context_interface::result::{HaltReason, OutOfGasError};

    #[test]
    fn exhaustiveness() {
        match InstructionResult::Stop {
            return_error!() => {}
            return_revert!() => {}
            return_ok!() => {}
        }
    }

    #[test]
    fn test_results() {
        let ok_results = [
            InstructionResult::Stop,
            InstructionResult::Return,
            InstructionResult::SelfDestruct,
        ];
        for result in ok_results {
            assert!(result.is_ok());
            assert!(!result.is_revert());
            assert!(!result.is_error());
        }

        let revert_results = [
            InstructionResult::Revert,
            InstructionResult::CallTooDeep,
            InstructionResult::OutOfFunds,
        ];
        for result in revert_results {
            assert!(!result.is_ok());
            assert!(result.is_revert());
            assert!(!result.is_error());
        }

        let error_results = [
            InstructionResult::OutOfGas,
            InstructionResult::MemoryOOG,
            InstructionResult::MemoryLimitOOG,
            InstructionResult::PrecompileOOG,
            InstructionResult::InvalidOperandOOG,
            InstructionResult::OpcodeNotFound,
            InstructionResult::CallNotAllowedInsideStatic,
            InstructionResult::StateChangeDuringStaticCall,
            InstructionResult::InvalidFEOpcode,
            InstructionResult::InvalidJump,
            InstructionResult::NotActivated,
            InstructionResult::StackUnderflow,
            InstructionResult::StackOverflow,
            InstructionResult::OutOfOffset,
            InstructionResult::CreateCollision,
            InstructionResult::OverflowPayment,
            InstructionResult::PrecompileError,
            InstructionResult::NonceOverflow,
            InstructionResult::CreateContractSizeLimit,
            InstructionResult::CreateContractStartingWithEF,
            InstructionResult::CreateInitCodeSizeLimit,
            InstructionResult::FatalExternalError,
        ];
        for result in error_results {
            assert!(!result.is_ok());
            assert!(!result.is_revert());
            assert!(result.is_error());
        }
    }

    #[test]
    fn base_halt_reason_collapses_runtime_halts() {
        assert_eq!(
            SuccessOrHalt::<HaltReason>::from(InstructionResult::RootCallOnly),
            SuccessOrHalt::Halt(HaltReason::PrecompileErrorWithContext(
                "RootCallOnly".into()
            ))
        );
        assert_eq!(
            SuccessOrHalt::<HaltReason>::from(InstructionResult::OutOfFuel),
            SuccessOrHalt::Halt(HaltReason::OutOfGas(OutOfGasError::Basic))
        );
    }
}
