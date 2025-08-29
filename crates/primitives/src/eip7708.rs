//! EIP-7708: ETH transfers emit a log
//!
//! https://eips.ethereum.org/EIPS/eip-7708
use alloy_primitives::{address, b256, Address, Log, LogData, B256, U256};
use std::vec;

/// keccak256 of "Transfer(address,address,uint256)" that notifies
/// about native transfer of eth
///
/// EIP-7708 is a draft, but we need native events for efficient call trace extraction
pub const NATIVE_TRANSFER_KECCAK: B256 =
    b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// A system address that is used to identify system contracts
///
/// It's used in EIP-2935
pub const NATIVE_TRANSFER_ADDRESS: Address = address!("0xfffffffffffffffffffffffffffffffffffffffe");

/// Creates a log entry conforming to the EIP-7708 standard that represents
/// a native token transfer between two addresses.
pub fn create_eip7708_log(caller: Address, callee: Address, transfer_value: U256) -> Log {
    let transfer_value: B256 = transfer_value.into();
    Log {
        address: NATIVE_TRANSFER_ADDRESS,
        data: LogData::new_unchecked(
            vec![
                NATIVE_TRANSFER_KECCAK,
                caller.into_word(),
                callee.into_word(),
            ],
            transfer_value.into(),
        ),
    }
}
