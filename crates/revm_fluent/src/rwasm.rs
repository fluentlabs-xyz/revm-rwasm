use crate::{
    primitives::{Address, Bytecode, Bytes, Log, LogData, B256, U256},
    Database,
    EvmContext,
    JournalEntry,
};
use core::cell::RefCell;
use fluentbase_core::helpers::exit_code_from_evm_error;
use fluentbase_sdk::{
    Account,
    AccountCheckpoint,
    AccountStatus,
    SovereignAPI,
    JZKT_ACCOUNT_RWASM_CODE_HASH_FIELD,
    JZKT_ACCOUNT_SOURCE_CODE_HASH_FIELD,
};
use fluentbase_types::{EmptyJournalTrie, ExitCode, Fuel, SharedAPI, F254};
use revm_interpreter::{Gas, InstructionResult};

pub(crate) struct RwasmDbWrapper<'a, SDK: SharedAPI, DB: Database> {
    ctx: RefCell<&'a mut EvmContext<DB>>,
    sdk: SDK,
}

impl<'a, SDK: SharedAPI, DB: Database> RwasmDbWrapper<'a, SDK, DB> {
    pub(crate) fn new(
        ctx: RefCell<&'a mut EvmContext<DB>>,
        sdk: SDK,
    ) -> RwasmDbWrapper<'a, SDK, DB> {
        RwasmDbWrapper { ctx, sdk }
    }
}

impl<'a, SDK: SharedAPI, DB: Database> SharedAPI for RwasmDbWrapper<'a, SDK, DB> {
    fn keccak256(data: &[u8]) -> B256 {
        SDK::keccak256(data)
    }

    fn poseidon(data: &[u8]) -> F254 {
        SDK::poseidon(data)
    }

    fn poseidon_hash(fa: &F254, fb: &F254, fd: &F254) -> F254 {
        SDK::poseidon_hash(fa, fb, fd)
    }

    fn ec_recover(digest: &B256, sig: &[u8; 64], rec_id: u8) -> [u8; 65] {
        SDK::ec_recover(digest, sig, rec_id)
    }

    fn read(&self, target: &mut [u8], offset: u32) {
        self.sdk.read(target, offset)
    }

    fn input_size(&self) -> u32 {
        self.sdk.input_size()
    }

    fn write(&self, value: &[u8]) {
        self.sdk.write(value)
    }

    fn forward_output(&self, offset: u32, len: u32) {
        self.sdk.forward_output(offset, len)
    }

    fn exit(&self, exit_code: i32) -> ! {
        self.sdk.exit(exit_code)
    }

    fn output_size(&self) -> u32 {
        self.sdk.output_size()
    }

    fn read_output(&self, target: &mut [u8], offset: u32) {
        self.sdk.read_output(target, offset)
    }

    fn state(&self) -> u32 {
        self.sdk.state()
    }

    fn read_context(&self, target: &mut [u8], offset: u32) {
        self.sdk.read_context(target, offset)
    }

    fn charge_fuel(&self, fuel: &mut Fuel) {
        self.sdk.charge_fuel(fuel)
    }

    fn account(&self, address: &Address) -> (Account, bool) {
        let mut ctx = self.ctx.borrow_mut();
        let (account, is_cold) = ctx
            .load_account(*address)
            .map_err(|_| panic!("database error"))
            .unwrap();
        let mut account = Account::from(account.info.clone());
        account.address = *address;
        (account, is_cold)
    }

    fn preimage_size(&self, hash: &B256) -> u32 {
        self.ctx
            .borrow_mut()
            .db
            .code_by_hash(*hash)
            .map(|b| b.bytecode().len() as u32)
            .unwrap_or_default()
    }

    fn preimage_copy(&self, target: &mut [u8], hash: &B256) {
        let mut ctx = self.ctx.borrow_mut();
        let code = ctx
            .code_by_hash(*hash)
            .map_err(|_| panic!("failed to get bytecode by hash"))
            .unwrap();
        target.copy_from_slice(code.as_ref());
    }

    fn preimage(&self, hash: &B256) -> Bytes {
        let mut ctx = self.ctx.borrow_mut();
        ctx.code_by_hash(*hash)
            .map_err(|_| panic!("failed to get bytecode by hash"))
            .unwrap()
    }

    fn log(&self, address: &Address, data: Bytes, topics: &[B256]) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.journaled_state.log(Log {
            address: *address,
            data: LogData::new_unchecked(topics.into(), data),
        });
    }

    fn system_call(&self, address: &Address, input: &[u8], fuel: &mut Fuel) -> (Bytes, ExitCode) {
        self.sdk.system_call(address, input, fuel)
    }

    fn debug(&self, msg: &[u8]) {
        self.sdk.debug(msg)
    }
}

impl<'a, SDK: SharedAPI, DB: Database> SovereignAPI for RwasmDbWrapper<'a, SDK, DB> {
    fn checkpoint(&self) -> AccountCheckpoint {
        let mut ctx = self.ctx.borrow_mut();
        let (a, b) = ctx.journaled_state.checkpoint().into();
        fluentbase_types::JournalCheckpoint::from((a, b)).to_u64()
    }

    fn commit(&self) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.journaled_state.checkpoint_commit();
    }

    fn rollback(&self, checkpoint: AccountCheckpoint) {
        let checkpoint = fluentbase_types::JournalCheckpoint::from_u64(checkpoint);
        let mut ctx = self.ctx.borrow_mut();
        ctx.journaled_state
            .checkpoint_revert((checkpoint.0, checkpoint.1).into());
    }

    fn write_account(&self, account: &Account, status: AccountStatus) {
        let mut ctx = self.ctx.borrow_mut();
        // load account with this address from journaled state
        let (db_account, _) = ctx
            .load_account_with_code(account.address)
            .map_err(|_| panic!("database error"))
            .unwrap();
        let old_nonce = db_account.info.nonce;
        // copy all account info fields
        db_account.info.balance = account.balance;
        db_account.info.nonce = account.nonce;
        db_account.info.code_hash = account.source_code_hash;
        db_account.info.rwasm_code_hash = account.rwasm_code_hash;
        // if this is an account deployment, then mark is as created (needed for SELFDESTRUCT)
        if status == AccountStatus::NewlyCreated {
            db_account.mark_created();
            let last_journal = ctx.journaled_state.journal.last_mut().unwrap();
            last_journal.push(JournalEntry::AccountCreated {
                address: account.address,
            });
        } else if status == AccountStatus::SelfDestroyed {
        }
        // if nonce has changed, then inc nonce as well
        if account.nonce - old_nonce == 1 {
            let last_journal = ctx.journaled_state.journal.last_mut().unwrap();
            last_journal.push(JournalEntry::NonceChange {
                address: account.address,
            });
        }
        // mark an account as touched
        ctx.journaled_state.touch(&account.address);
    }

    fn update_preimage(&self, key: &[u8; 32], field: u32, preimage: &[u8]) {
        let mut ctx = self.ctx.borrow_mut();
        let address = Address::from_slice(&key[12..]);
        // debug_log!("am: update_preimage for address {}", address);
        if field == JZKT_ACCOUNT_SOURCE_CODE_HASH_FIELD && !preimage.is_empty() {
            ctx.journaled_state.set_code(
                address,
                Bytecode::new_raw(Bytes::copy_from_slice(preimage)),
                None,
            );
        } else if field == JZKT_ACCOUNT_RWASM_CODE_HASH_FIELD && !preimage.is_empty() {
            ctx.journaled_state.set_rwasm_code(
                address,
                Bytecode::new_raw(Bytes::copy_from_slice(preimage)),
                None,
            );
        }
    }

    fn context_call(
        &self,
        address: &Address,
        input: &[u8],
        context: &[u8],
        fuel: &mut Fuel,
        state: u32,
    ) -> (Bytes, ExitCode) {
        let (callee, _) = self.account(address);
        let rwasm_bytecode = self.preimage(&callee.rwasm_code_hash);
        if rwasm_bytecode.is_empty() {
            return (Bytes::default(), ExitCode::Ok);
        }
        let result = {
            #[cfg(feature = "std")]
            {
                use fluentbase_runtime::{Runtime, RuntimeContext};
                let ctx = RuntimeContext::new(rwasm_bytecode)
                    .with_input(input.into())
                    .with_context(context.into())
                    .with_fuel_limit(fuel.0)
                    .with_jzkt(EmptyJournalTrie::default())
                    .with_state(state);
                let mut runtime = Runtime::new(ctx);
                let result = match runtime.call() {
                    Ok(result) => result,
                    Err(err) => {
                        let exit_code = Runtime::catch_trap(&err);
                        return (Bytes::default(), ExitCode::from(exit_code));
                    }
                };
                fuel.0 -= result.fuel_consumed;
                (Bytes::from(result.output.clone()), result.exit_code.into())
            }
            #[cfg(not(feature = "std"))]
            {
                unreachable!("not supported yet");
                // let gam = GuestAccountManager::default();
                // let result = gam.exec_hash(hash32_offset, context, input, fuel_offset, state);
                // unsafe {
                //     *fuel_offset -= result.1 as u32;
                // }
                // (result.0, result.1)
            }
        };
        result
    }

    fn storage(&self, address: &Address, slot: &U256, committed: bool) -> (U256, bool) {
        let mut ctx = self.ctx.borrow_mut();
        // let (address, slot) = if address != EVM_STORAGE_ADDRESS {
        //     // let storage_key = calc_storage_key(&address, slot.as_le_slice().as_ptr());
        //     // (EVM_STORAGE_ADDRESS, U256::from_le_bytes(storage_key))
        //     (address, slot)
        // } else {
        //     (address, slot)
        // };
        if committed {
            let (account, _) = ctx
                .load_account(*address)
                .map_err(|_| panic!("failed to load account"))
                .unwrap();
            if account.is_created() {
                return (U256::ZERO, true);
            }
            let value = ctx
                .db
                .storage(*address, *slot)
                .ok()
                .expect("failed to read storage slot");
            (value, true)
        } else {
            ctx.sload(*address, *slot)
                .ok()
                .expect("failed to read storage slot")
        }
    }

    fn write_storage(&self, address: &Address, slot: &U256, value: &U256) -> bool {
        let mut ctx = self.ctx.borrow_mut();
        // let (address, slot) = if address != EVM_STORAGE_ADDRESS {
        //     // let storage_key = calc_storage_key(&address, slot.as_le_slice().as_ptr());
        //     // (EVM_STORAGE_ADDRESS, U256::from_le_bytes(storage_key))
        //     (address, slot)
        // } else {
        //     (address, slot)
        // };
        // println!(
        //     "write_storage: address {} slot {} value {}",
        //     &address, &slot, &value
        // );
        let result = ctx
            .sstore(*address, *slot, *value)
            .map_err(|_| panic!("failed to update storage slot"))
            .unwrap();
        result.is_cold
    }

    fn write_log(&self, address: &Address, data: &Bytes, topics: &[B256]) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.journaled_state.log(Log {
            address: *address,
            data: LogData::new_unchecked(topics.into(), data.clone()),
        });
    }

    fn precompile(
        &self,
        address: &Address,
        input: &Bytes,
        gas: u64,
    ) -> Option<(Bytes, ExitCode, u64, i64)> {
        let mut ctx = self.ctx.borrow_mut();
        let result = ctx
            .call_precompile(&address, input, Gas::new(gas))
            .unwrap_or(None)?;
        Some((
            result.output,
            exit_code_from_evm_error(result.result),
            result.gas.remaining(),
            result.gas.refunded(),
        ))
    }

    fn is_precompile(&self, address: &Address) -> bool {
        let ctx = self.ctx.borrow_mut();
        ctx.journaled_state
            .warm_preloaded_addresses
            .contains(address)
    }

    fn transfer(&self, from: &mut Account, to: &mut Account, value: U256) -> Result<(), ExitCode> {
        Account::transfer(from, to, value)?;
        let mut ctx = self.ctx.borrow_mut();
        ctx.transfer(&from.address, &to.address, value)
            .map_err(|_| panic!("unexpected EVM transfer error"))
            .unwrap()
            .and_then(|err| -> Option<InstructionResult> {
                panic!(
                    "it seems there is an account balance mismatch between ECL and REVM: {:?}",
                    err
                );
            });
        Ok(())
    }

    fn self_destruct(&self, address: Address, target: Address) -> [bool; 4] {
        let mut ctx = self.ctx.borrow_mut();
        let result = ctx
            .selfdestruct(address, target)
            .map_err(|_| "unexpected EVM self destruct error")
            .unwrap();
        [
            result.had_value,
            result.target_exists,
            result.is_cold,
            result.previously_destroyed,
        ]
    }

    fn block_hash(&self, number: U256) -> B256 {
        let mut ctx = self.ctx.borrow_mut();
        ctx.block_hash(number)
            .map_err(|_| "unexpected EVM error")
            .unwrap()
    }

    fn write_transient_storage(&self, address: Address, index: U256, value: U256) {
        let mut ctx = self.ctx.borrow_mut();
        ctx.tstore(address, index, value)
    }

    fn transient_storage(&self, address: Address, index: U256) -> U256 {
        let mut ctx = self.ctx.borrow_mut();
        ctx.tload(address, index)
    }
}
