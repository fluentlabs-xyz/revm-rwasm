//! Revm is a Rust EVM implementation.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
#[cfg(not(feature = "std"))]
extern crate alloc as std;

mod builder;
mod context;

pub mod db;
mod evm;
mod frame;
pub mod handler;
mod inspector;
mod journaled_state;
#[cfg(feature = "optimism")]
pub mod optimism;
pub mod rwasm;

// Export items.
#[cfg(feature = "rwasm")]
pub use builder::RwasmBuilder as EvmBuilder;
#[cfg(not(feature = "rwasm"))]
pub use builder::{EvmBuilder, RwasmBuilder};
pub use context::{
    Context,
    ContextPrecompile,
    ContextPrecompiles,
    ContextStatefulPrecompile,
    ContextStatefulPrecompileArc,
    ContextStatefulPrecompileBox,
    ContextStatefulPrecompileMut,
    ContextWithHandlerCfg,
    EvmContext,
    InnerEvmContext,
};
pub use db::{
    CacheState,
    DBBox,
    Database,
    DatabaseCommit,
    DatabaseRef,
    InMemoryDB,
    State,
    StateBuilder,
    StateDBBox,
    TransitionAccount,
    TransitionState,
};
#[cfg(not(feature = "rwasm"))]
pub use evm::Evm;
pub use evm::CALL_STACK_LIMIT;
pub use frame::{CallFrame, CreateFrame, Frame, FrameData, FrameOrResult, FrameResult};
pub use handler::Handler;
pub use inspector::{inspector_handle_register, inspectors, GetInspector, Inspector};
pub use journaled_state::{JournalCheckpoint, JournalEntry, JournaledState};
// export Optimism types, helpers, and constants
#[cfg(feature = "optimism")]
pub use optimism::{L1BlockInfo, BASE_FEE_RECIPIENT, L1_BLOCK_CONTRACT, L1_FEE_RECIPIENT};
// Reexport libraries
#[doc(inline)]
pub use revm_interpreter as interpreter;
#[doc(inline)]
pub use revm_interpreter::primitives;
#[doc(inline)]
pub use revm_precompile as precompile;
#[cfg(feature = "rwasm")]
pub use rwasm::Rwasm as Evm;
pub use rwasm::Rwasm;
