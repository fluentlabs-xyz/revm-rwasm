use revm::handler::evm::{ContextDbError, FrameInitResult};
use revm::handler::instructions::InstructionProvider;
use revm::inspector::handler::{frame_end, frame_start};
use revm::inspector::{inspect_instructions, InspectorFrame};
use revm::{
    context::{ContextError, ContextSetters, ContextTr, Evm, FrameStack},
    handler::{
        evm::FrameTr, instructions::EthInstructions, EthFrame, EthPrecompiles, EvmTr,
        FrameInitOrResult, ItemOrResult,
    },
    inspector::{InspectorEvmTr, JournalExt},
    interpreter::interpreter::EthInterpreter,
    Database, Inspector,
};

/// MyEvm variant of the EVM.
///
/// This struct demonstrates how to create a custom EVM implementation by wrapping
/// the standard REVM components. It combines a context (CTX), an inspector (INSP),
/// and the standard Ethereum instructions, precompiles, and frame execution logic.
///
/// The generic parameters allow for flexibility in the underlying database and
/// inspection capabilities while maintaining the standard Ethereum execution semantics.
#[derive(Debug)]
pub struct MyEvm<CTX, INSP>(
    pub  Evm<
        CTX,
        INSP,
        EthInstructions<EthInterpreter, CTX>,
        EthPrecompiles,
        EthFrame<EthInterpreter>,
    >,
);

impl<CTX: ContextTr, INSP> MyEvm<CTX, INSP> {
    /// Creates a new instance of MyEvm with the provided context and inspector.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The execution context that manages state, environment, and journaling
    /// * `inspector` - The inspector for debugging and tracing execution
    ///
    /// # Returns
    ///
    /// A new MyEvm instance configured with:
    /// - The provided context and inspector
    /// - Mainnet instruction set
    /// - Default Ethereum precompiles
    /// - A fresh frame stack for execution
    pub fn new(ctx: CTX, inspector: INSP) -> Self {
        Self(Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new(),
        })
    }
}

impl<CTX: ContextTr, INSP> EvmTr for MyEvm<CTX, INSP>
where
    CTX: ContextTr,
{
    type Context = CTX;
    type Instructions = EthInstructions<EthInterpreter, CTX>;
    type Precompiles = EthPrecompiles;
    type Frame = EthFrame<EthInterpreter>;
    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        self.0.ctx_ref()
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        self.0.ctx_instructions()
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        self.0.ctx_precompiles()
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        self.0.frame_stack()
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_init(frame_input)
    }

    fn frame_run(
        &mut self,
    ) -> Result<
        FrameInitOrResult<Self::Frame>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_run()
    }

    fn frame_return_result(
        &mut self,
        frame_result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<
        Option<<Self::Frame as FrameTr>::FrameResult>,
        ContextError<<<Self::Context as ContextTr>::Db as Database>::Error>,
    > {
        self.0.frame_return_result(frame_result)
    }
}

impl<CTX: ContextTr, INSP> InspectorEvmTr for MyEvm<CTX, INSP>
where
    CTX: ContextSetters<Journal: JournalExt>,
    INSP: Inspector<CTX, EthInterpreter>,
{
    type Inspector = INSP;

    fn inspector(&mut self) -> &mut Self::Inspector {
        self.0.inspector()
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        self.0.ctx_inspector()
    }

    fn ctx_inspector_frame(
        &mut self,
    ) -> (&mut Self::Context, &mut Self::Inspector, &mut Self::Frame) {
        self.0.ctx_inspector_frame()
    }

    fn ctx_inspector_frame_instructions(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Inspector,
        &mut Self::Frame,
        &mut Self::Instructions,
    ) {
        self.0.ctx_inspector_frame_instructions()
    }

    #[inline]
    fn inspect_frame_init(
        &mut self,
        mut frame_init: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<FrameInitResult<'_, Self::Frame>, ContextDbError<Self::Context>> {
        let (ctx, inspector) = self.ctx_inspector();
        if let Some(mut output) = frame_start(ctx, inspector, &mut frame_init.frame_input) {
            frame_end(ctx, inspector, &frame_init.frame_input, &mut output);
            return Ok(ItemOrResult::Result(output));
        }

        let frame_input = frame_init.frame_input.clone();
        if let ItemOrResult::Result(mut output) = self.frame_init(frame_init)? {
            let (ctx, inspector) = self.ctx_inspector();
            frame_end(ctx, inspector, &frame_input, &mut output);
            return Ok(ItemOrResult::Result(output));
        }

        // if it is new frame, initialize the interpreter.
        let (ctx, inspector, frame) = self.ctx_inspector_frame();
        let interp = frame.interpreter();
        inspector.initialize_interp(interp, ctx);
        Ok(ItemOrResult::Item(frame))
    }

    #[inline]
    fn inspect_frame_run(
        &mut self,
    ) -> Result<FrameInitOrResult<Self::Frame>, ContextDbError<Self::Context>> {
        let (ctx, inspector, frame, instructions) = self.ctx_inspector_frame_instructions();

        let next_action = inspect_instructions(
            ctx,
            frame.interpreter(),
            inspector,
            instructions.instruction_table(),
        );
        let mut result = frame.process_next_action(ctx, next_action);

        if let Ok(ItemOrResult::Result(frame_result)) = &mut result {
            let (ctx, inspector, frame) = self.ctx_inspector_frame();
            frame_end(ctx, inspector, frame.frame_input(), frame_result);
            frame.set_finished(true);
        };
        result
    }
}
