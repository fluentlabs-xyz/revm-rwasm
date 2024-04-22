use super::{
    merkle_trie::{log_rlp_hash, state_merkle_trie_root},
    models::{SpecName, Test, TestSuite},
    utils::recover_address,
};
use indicatif::{ProgressBar, ProgressDrawTarget};
use revm::{
    db::EmptyDB,
    inspector_handle_register,
    inspectors::TracerEip3155,
    interpreter::CreateScheme,
    primitives::{
        calc_excess_blob_gas,
        keccak256,
        Bytecode,
        Bytes,
        Env,
        ExecutionResult,
        SpecId,
        TransactTo,
        B256,
        U256,
    },
    Evm,
    State,
};
use serde_json::json;
use std::{
    io::{stderr, stdout},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
        Mutex,
    },
    time::{Duration, Instant},
};
use std::convert::Infallible;
use std::mem::transmute;
use fluentbase_types::{Address, ExitCode};
use revm::primitives::EVMError;
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};
use revm_original as ro;
use ro::primitives as rop;
use revm::primitives::EVMResultGeneric;

#[derive(Debug, Error)]
#[error("Test {name} failed: {kind}")]
pub struct TestError {
    pub name: String,
    pub kind: TestErrorKind,
}

#[derive(Debug, Error)]
pub enum TestErrorKind {
    #[error("logs root mismatch (spec_name={spec_name:?}): expected {expected:?}, got {got:?}")]
    LogsRootMismatch {
        spec_name: SpecName,
        got: B256,
        expected: B256,
    },
    #[error("state root mismatch (spec_name={spec_name:?}): expected {expected:?}, got {got:?}")]
    StateRootMismatch {
        spec_name: SpecName,
        got: B256,
        expected: B256,
    },
    #[error("Unknown private key: {0:?}")]
    UnknownPrivateKey(B256),
    #[error("Unexpected exception (spec_name={spec_name:?}): {got_exception:?} but test expects:{expected_exception:?}")]
    UnexpectedException {
        spec_name: SpecName,
        expected_exception: Option<String>,
        got_exception: Option<String>,
    },
    #[error("Unexpected output (spec_name={spec_name:?}): {got_output:?} but test expects:{expected_output:?}")]
    UnexpectedOutput {
        spec_name: SpecName,
        expected_output: Option<Bytes>,
        got_output: Option<Bytes>,
    },
    #[error(transparent)]
    SerdeDeserialize(#[from] serde_json::Error),
}

pub fn find_all_json_tests(path: &Path) -> Vec<PathBuf> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .map(DirEntry::into_path)
        .collect::<Vec<PathBuf>>()
}

fn skip_test(path: &Path) -> bool {
    let path_str = path.to_str().expect("Path is not valid UTF-8");
    let name = path.file_name().unwrap().to_str().unwrap();

    matches!(
        name,
        // funky test with `bigint 0x00` value in json :) not possible to happen on mainnet and
        // require custom json parser. https://github.com/ethereum/tests/issues/971
        |"ValueOverflow.json"| "ValueOverflowParis.json"

        // precompiles having storage is not possible
        | "RevertPrecompiledTouch_storage.json"
        | "RevertPrecompiledTouch.json"

        // txbyte is of type 02 and we dont parse tx bytes for this test to fail.
        | "typeTwoBerlin.json"

        // Need to handle Test errors
        | "transactionIntinsicBug.json"

        // Test check if gas price overflows, we handle this correctly but does not match tests specific exception.
        | "HighGasPrice.json"
        | "CREATE_HighNonce.json"
        | "CREATE_HighNonceMinus1.json"
        | "CreateTransactionHighNonce.json"

        // Skip test where basefee/accesslist/difficulty is present but it shouldn't be supported in
        // London/Berlin/TheMerge. https://github.com/ethereum/tests/blob/5b7e1ab3ffaf026d99d20b17bb30f533a2c80c8b/GeneralStateTests/stExample/eip1559.json#L130
        // It is expected to not execute these tests.
        | "basefeeExample.json"
        | "eip1559.json"
        | "mergeTest.json"

        // These tests are passing, but they take a lot of time to execute so we are going to skip them.
        | "loopExp.json"
        | "Call50000_sha256.json"
        | "static_Call50000_sha256.json"
        | "loopMul.json"
        | "CALLBlake2f_MaxRounds.json"
    ) || path_str.contains("stEOF")
}

fn check_evm_execution<EXT1, EXT2>(
    test: &Test,
    spec_name: &SpecName,
    expected_output: Option<&Bytes>,
    test_name: &str,
    exec_result: &Result<ExecutionResult, EVMError<ExitCode>>,
    exec_result_original: &EVMResultGeneric<rop::ExecutionResult, Infallible>,
    evm: &Evm<'_, EXT1, &mut State<EmptyDB>>,
    evm_original: &ro::Evm<'_, EXT2, &mut ro::State<ro::db::EmptyDB>>,
    print_json_outcome: bool,
) -> Result<(), TestError> {
    // let logs_root = log_rlp_hash(exec_result.as_ref().map(|r| r.logs()).unwrap_or_default());
    let logs_root_original = log_rlp_hash(exec_result_original.as_ref().map(|r| unsafe { transmute(r.logs()) }).unwrap_or_default());
    let state_root = state_merkle_trie_root(evm.context.evm.db.cache.trie_account());
    let accounts = evm_original.context.evm.db.cache.trie_account().into_iter().map(|(addr, acc)| {
        (addr, &revm::db::PlainAccount { info: unsafe { transmute(acc.info.clone()) }, storage: acc.storage.clone() })
    });
    let state_root_original = state_merkle_trie_root(accounts);

    let print_json_output = |error: Option<String>| {
        if print_json_outcome {
            let json = json!({
                    "stateRoot": state_root_original,
                    "logsRoot": logs_root_original,
                    "output": exec_result_original.as_ref().ok().and_then(|r| r.output().cloned()).unwrap_or_default(),
                    "gasUsed": exec_result_original.as_ref().ok().map(|r| r.gas_used()).unwrap_or_default(),
                    "pass": error.is_none(),
                    "errorMsg": error.unwrap_or_default(),
                    "evmResult": exec_result_original.as_ref().err().map(|e| e.to_string()).unwrap_or("Ok".to_string()),
                    "postLogsHash": logs_root_original,
                    "fork": evm_original.handler.cfg().spec_id,
                    "test": test_name,
                    "d": test.indexes.data,
                    "g": test.indexes.gas,
                    "v": test.indexes.value,
            });
            eprintln!("{json}");
        }
    };

    // if we expect exception revm should return error from execution.
    // So we do not check logs and state root.
    //
    // Note that some tests that have exception and run tests from before state clear
    // would touch the caller account and make it appear in state root calculation.
    // This is not something that we would expect as invalid tx should not touch state.
    // but as this is a cleanup of invalid tx it is not properly defined and in the end
    // it does not matter.
    // Test where this happens: `tests/GeneralStateTests/stTransactionTest/NoSrcAccountCreate.json`
    // and you can check that we have only two "hash" values for before and after state clear.
    match (&test.expect_exception, exec_result_original) {
        // do nothing
        (None, Ok(result)) => {
            // check output
            let result_output = result.output();
            if let Some((expected_output, output)) = expected_output.zip(result_output) {
                let output: &Bytes = unsafe { transmute(output) };
                if expected_output != output {
                    let kind = TestErrorKind::UnexpectedOutput {
                        spec_name: spec_name.clone(),
                        expected_output: Some(expected_output.clone()),
                        got_output: unsafe { transmute(result.output().cloned()) },
                    };
                    print_json_output(Some(kind.to_string()));
                    return Err(TestError {
                        name: test_name.to_string(),
                        kind,
                    });
                }
            }
        }
        // return okay, exception is expected.
        (Some(_), Err(_)) => return Ok(()),
        _ => {
            let kind = TestErrorKind::UnexpectedException {
                spec_name: spec_name.clone(),
                expected_exception: test.expect_exception.clone(),
                got_exception: exec_result_original.clone().err().map(|e| e.to_string()),
            };
            print_json_output(Some(kind.to_string()));
            return Err(TestError {
                name: test_name.to_string(),
                kind,
            });
        }
    }

    if logs_root_original != test.logs {
        let kind = TestErrorKind::LogsRootMismatch {
            spec_name: spec_name.clone(),
            got: logs_root_original,
            expected: test.logs,
        };
        print_json_output(Some(kind.to_string()));
        return Err(TestError {
            name: test_name.to_string(),
            kind,
        });
    }

    if state_root_original.0 != test.hash.0 {
        let kind = TestErrorKind::StateRootMismatch {
            spec_name: spec_name.clone(),
            got: state_root_original.0.into(),
            expected: test.hash,
        };
        print_json_output(Some(kind.to_string()));
        return Err(TestError {
            name: test_name.to_string(),
            kind,
        });
    }

    print_json_output(None);

    Ok(())
}

pub fn execute_test_suite(
    path: &Path,
    elapsed: &Arc<Mutex<Duration>>,
    trace: bool,
    print_json_outcome: bool,
) -> Result<(), TestError> {
    if skip_test(path) {
        return Ok(());
    }

    let s = std::fs::read_to_string(path).unwrap();
    let suite: TestSuite = serde_json::from_str(&s).map_err(|e| TestError {
        name: path.to_string_lossy().into_owned(),
        kind: e.into(),
    })?;

    for (name, unit) in suite.0 {
        // Create database and insert cache
        let mut cache_state = revm::CacheState::new(false);
        let mut cache_state_original = ro::CacheState::new(false);
        for (address, info) in unit.pre {
            let acc_info = revm::primitives::AccountInfo {
                balance: info.balance,
                code_hash: keccak256(&info.code),
                rwasm_code_hash: Default::default(),
                code: Some(Bytecode::new_raw(info.code.clone())),
                nonce: info.nonce,
                rwasm_code: None,
            };
            let acc_info_original = ro::primitives::AccountInfo {
                balance: info.balance,
                code_hash: (keccak256(&info.code)),
                code: Some(ro::primitives::Bytecode::new_raw((info.code))),
                nonce: info.nonce,
                ..Default::default()
            };
            cache_state.insert_account_with_storage(address, acc_info, info.storage.clone());
            cache_state_original.insert_account_with_storage((address), acc_info_original, (info.storage));
        }

        let mut env = Box::<Env>::default();
        let mut env_original = Box::<rop::Env>::default();
        // for mainnet
        env.cfg.chain_id = 1;
        env_original.cfg.chain_id = 1;
        // env.cfg.spec_id is set down the road

        // block env
        env.block.number = unit.env.current_number;
        env_original.block.number = unit.env.current_number;

        env.block.coinbase = unit.env.current_coinbase;
        env_original.block.coinbase = (unit.env.current_coinbase);

        env.block.timestamp = unit.env.current_timestamp;
        env_original.block.timestamp = unit.env.current_timestamp;

        env.block.gas_limit = unit.env.current_gas_limit;
        env_original.block.gas_limit = unit.env.current_gas_limit;

        env.block.basefee = unit.env.current_base_fee.unwrap_or_default();
        env_original.block.basefee = unit.env.current_base_fee.unwrap_or_default();

        env.block.difficulty = unit.env.current_difficulty;
        env_original.block.difficulty = unit.env.current_difficulty;

        // after the Merge prevrandao replaces mix_hash field in block and replaced difficulty
        // opcode in EVM.
        env.block.prevrandao = unit.env.current_random;
        env_original.block.prevrandao = unit.env.current_random;
        // EIP-4844
        if let Some(current_excess_blob_gas) = unit.env.current_excess_blob_gas {
            env.block.set_blob_excess_gas_and_price(current_excess_blob_gas.to());
            env_original.block.set_blob_excess_gas_and_price(current_excess_blob_gas.to());
        } else if let (Some(parent_blob_gas_used), Some(parent_excess_blob_gas)) = (
            unit.env.parent_blob_gas_used,
            unit.env.parent_excess_blob_gas,
        ) {
            env.block
                .set_blob_excess_gas_and_price(calc_excess_blob_gas(
                    parent_blob_gas_used.to(),
                    parent_excess_blob_gas.to(),
                ));
            env_original.block
                .set_blob_excess_gas_and_price(calc_excess_blob_gas(
                    parent_blob_gas_used.to(),
                    parent_excess_blob_gas.to(),
                ));
        }

        // tx env
        let caller
            = if let Some(address) = unit.transaction.sender {
            address
        } else {
            recover_address(unit.transaction.secret_key.as_slice()).ok_or_else(|| TestError {
                name: name.clone(),
                kind: TestErrorKind::UnknownPrivateKey(unit.transaction.secret_key),
            })?
        };
        env.tx.caller = caller;
        env_original.tx.caller = (caller);

        let gas_price = unit
            .transaction
            .gas_price
            .or(unit.transaction.max_fee_per_gas)
            .unwrap_or_default();
        env.tx.gas_price = gas_price;
        env_original.tx.gas_price = gas_price;

        let gas_priority_fee = unit.transaction.max_priority_fee_per_gas;
        env.tx.gas_priority_fee = gas_priority_fee;
        env_original.tx.gas_priority_fee = gas_priority_fee;

        // EIP-4844
        let blob_hashes = unit.transaction.blob_versioned_hashes;
        env.tx.blob_hashes = blob_hashes.clone();
        env_original.tx.blob_hashes = blob_hashes;

        let max_fee_per_blob_gas = unit.transaction.max_fee_per_blob_gas;
        env.tx.max_fee_per_blob_gas = max_fee_per_blob_gas;
        env_original.tx.max_fee_per_blob_gas = max_fee_per_blob_gas;

        // post and execution
        for (spec_name, tests) in unit.post {
            if matches!(
                spec_name,
                SpecName::ByzantiumToConstantinopleAt5
                    | SpecName::Constantinople
                    | SpecName::Unknown
            ) {
                continue;
            }
            if spec_name.lt(&SpecName::Cancun) {
                continue
            }

            let spec_id = spec_name.to_spec_id();

            for (index, test) in tests.into_iter().enumerate() {
                env.tx.gas_limit = unit.transaction.gas_limit[test.indexes.gas].saturating_to();
                env_original.tx.gas_limit = unit.transaction.gas_limit[test.indexes.gas].saturating_to();

                let data = unit
                    .transaction
                    .data
                    .get(test.indexes.data)
                    .unwrap()
                    .clone();
                env.tx.data = data.clone();
                env_original.tx.data = (data);

                let value = unit.transaction.value[test.indexes.value];
                env.tx.value = value;
                env_original.tx.value = value;

                let access_list: Vec<(Address, Vec<U256>)> = unit
                    .transaction
                    .access_lists
                    .get(test.indexes.data)
                    .and_then(Option::as_deref)
                    .unwrap_or_default()
                    .iter()
                    .map(|item| {
                        (
                            item.address,
                            item.storage_keys
                                .iter()
                                .map(|key| U256::from_be_bytes(key.0))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect();
                env.tx.access_list = access_list.clone();
                env_original.tx.access_list = unsafe { transmute(access_list) };

                let to = match unit.transaction.to {
                    Some(add) => TransactTo::Call(add),
                    None => TransactTo::Create(CreateScheme::Create),
                };
                env.tx.transact_to = to.clone();
                env_original.tx.transact_to = unsafe { transmute(to) };

                let mut cache = cache_state.clone();
                cache.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let mut cache_original = cache_state_original.clone();
                cache_original.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let mut state = revm::db::State::builder()
                    .with_cached_prestate(cache)
                    .with_bundle_update()
                    .build();
                let mut state_original = ro::db::State::builder()
                    .with_cached_prestate(cache_original)
                    .with_bundle_update()
                    .build();
                let mut evm = Evm::builder()
                    .with_db(&mut state)
                    .modify_env(|e| *e = env.clone())
                    .with_spec_id(spec_id)
                    .build();
                let mut evm_original = ro::Evm::builder()
                    .with_db(&mut state_original)
                    .modify_env(|e| *e = env_original.clone())
                    .with_spec_id(unsafe { transmute(spec_id) })
                    .build();

                // do the deed
                let (e, exec_result) = if trace {
                    let mut evm = evm
                        .modify()
                        .reset_handler_with_external_context(TracerEip3155::new(
                            Box::new(stderr()),
                            false,
                        ))
                        // TODO do we need this?
                        // .append_handler_register(inspector_handle_register)
                        .build();
                    let mut evm_original = evm_original
                        .modify()
                        .reset_handler_with_external_context(TracerEip3155::new(
                            Box::new(stderr()),
                            false,
                        ))
                        // TODO do we need this?
                        // .append_handler_register(inspector_handle_register)
                        .build();

                    let timer = Instant::now();
                    let res = evm.transact_commit();
                    let res_original = evm_original.transact_commit();
                    *elapsed.lock().unwrap() += timer.elapsed();

                    let Err(e) = check_evm_execution(
                        &test,
                        &spec_name,
                        unit.out.as_ref(),
                        &name,
                        &res,
                        &res_original,
                        &evm,
                        &evm_original,
                        print_json_outcome,
                    ) else {
                        continue;
                    };
                    // reset external context
                    (e, res_original)
                } else {
                    let timer = Instant::now();
                    let res = evm.transact_commit();
                    let res_original = evm_original.transact_commit();
                    *elapsed.lock().unwrap() += timer.elapsed();

                    // dump state and traces if test failed
                    let output = check_evm_execution(
                        &test,
                        &spec_name,
                        unit.out.as_ref(),
                        &name,
                        &res,
                        &res_original,
                        &evm,
                        &evm_original,
                        print_json_outcome,
                    );
                    let Err(e) = output else {
                        continue;
                    };
                    (e, res_original)
                };

                // print only once or
                // if we are already in trace mode, just return error
                static FAILED: AtomicBool = AtomicBool::new(false);
                if FAILED.swap(true, Ordering::SeqCst) {
                    return Err(e);
                }

                // re build to run with tracing
                let mut cache = cache_state.clone();
                cache.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let mut cache_original = cache_state_original.clone();
                cache_original.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let state = revm::db::State::builder()
                    .with_cached_prestate(cache)
                    .with_bundle_update()
                    .build();
                let state_original = ro::db::State::builder()
                    .with_cached_prestate(cache_original)
                    .with_bundle_update()
                    .build();

                let path = path.display();
                println!("\nTraces:");
                let mut evm = Evm::builder()
                    .with_spec_id(unsafe { transmute(spec_id) })
                    .with_db(state)
                    .with_external_context(TracerEip3155::new(Box::new(stdout()), false))
                    // .append_handler_register(inspector_handle_register)
                    .build();
                let mut evm_original = ro::Evm::builder()
                    .with_spec_id(unsafe { transmute(spec_id) })
                    .with_db(state_original)
                    .with_external_context(TracerEip3155::new(Box::new(stdout()), false))
                    // .append_handler_register(inspector_handle_register)
                    .build();
                let _ = evm.transact_commit();

                println!("\nExecution result: {exec_result:#?}");
                println!("\nExpected exception: {:?}", test.expect_exception);
                println!("\nState before: {cache_state:#?}");
                println!("\nState after: {:#?}", evm.context.evm.db.cache);
                println!("\nSpecification: {spec_id:?}");
                println!("\nEnvironment: {env_original:#?}");
                println!("\nTest name: {name:?} (index: {index}, path: {path}) failed:\n{e}");

                return Err(e);
            }
        }
    }
    Ok(())
}

pub fn run(
    test_files: Vec<PathBuf>,
    mut single_thread: bool,
    trace: bool,
    mut print_outcome: bool,
) -> Result<(), TestError> {
    // trace implies print_outcome
    if trace {
        print_outcome = true;
    }
    // print_outcome or trace implies single_thread
    if print_outcome {
        single_thread = true;
    }
    let n_files = test_files.len();

    let endjob = Arc::new(AtomicBool::new(false));
    let console_bar = Arc::new(ProgressBar::with_draw_target(
        Some(n_files as u64),
        ProgressDrawTarget::stdout(),
    ));
    let queue = Arc::new(Mutex::new((0usize, test_files)));
    let elapsed = Arc::new(Mutex::new(std::time::Duration::ZERO));

    let num_threads = match (single_thread, std::thread::available_parallelism()) {
        (true, _) | (false, Err(_)) => 1,
        (false, Ok(n)) => n.get(),
    };
    let num_threads = num_threads.min(n_files);
    let mut handles = Vec::with_capacity(num_threads);
    for i in 0..num_threads {
        let queue = queue.clone();
        let endjob = endjob.clone();
        let console_bar = console_bar.clone();
        let elapsed = elapsed.clone();

        let thread = std::thread::Builder::new().name(format!("runner-{i}"));

        let f = move || loop {
            if endjob.load(Ordering::SeqCst) {
                return Ok(());
            }

            let (_index, test_path) = {
                let (current_idx, queue) = &mut *queue.lock().unwrap();
                let prev_idx = *current_idx;
                let Some(test_path) = queue.get(prev_idx).cloned() else {
                    return Ok(());
                };
                *current_idx = prev_idx + 1;
                (prev_idx, test_path)
            };

            if let Err(err) = execute_test_suite(&test_path, &elapsed, trace, print_outcome) {
                endjob.store(true, Ordering::SeqCst);
                return Err(err);
            }
            console_bar.inc(1);
        };
        handles.push(thread.spawn(f).unwrap());
    }

    // join all threads before returning an error
    let mut errors = Vec::new();
    for handle in handles {
        if let Err(e) = handle.join().unwrap() {
            errors.push(e);
        }
    }
    console_bar.finish();

    println!(
        "Finished execution. Total CPU time: {:.6}s",
        elapsed.lock().unwrap().as_secs_f64()
    );
    if errors.is_empty() {
        println!("All tests passed!");
        Ok(())
    } else {
        let n = errors.len();
        if n > 1 {
            println!("{n} threads returned an error, out of {num_threads} total:");
            for error in &errors {
                println!("{error}");
            }
        }
        Err(errors.swap_remove(0))
    }
}
