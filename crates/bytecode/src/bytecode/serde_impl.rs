use super::{Arc, Bytecode, BytecodeInner, BytecodeKind, JumpTable, OnceLock};
use primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
enum BytecodeSerde {
    LegacyAnalyzed {
        bytecode: Bytes,
        original_len: usize,
        jump_table: JumpTable,
    },
    Eip7702 {
        delegated_address: Address,
    },
    Rwasm {
        rwasm_bytecode: Bytes,
    },
    OwnableAccount {
        owner_address: Address,
        metadata: Bytes,
    },
}

impl Serialize for Bytecode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Bytecode::BytecodeInner(inner) => {
                let repr = match self.kind() {
                    BytecodeKind::LegacyAnalyzed => BytecodeSerde::LegacyAnalyzed {
                        bytecode: inner.bytecode.clone(),
                        original_len: inner.original_len,
                        jump_table: inner.jump_table.clone(),
                    },
                    BytecodeKind::Eip7702 => BytecodeSerde::Eip7702 {
                        delegated_address: self.eip7702_address().unwrap(),
                    },
                    _ => unreachable!(),
                };
                repr.serialize(serializer)
            }
            Bytecode::Rwasm(inner) => BytecodeSerde::Rwasm {
                rwasm_bytecode: inner.raw.clone(),
            }
            .serialize(serializer),
            Bytecode::OwnableAccount(inner) => BytecodeSerde::OwnableAccount {
                owner_address: inner.owner_address,
                metadata: inner.metadata.clone(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Bytecode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match BytecodeSerde::deserialize(deserializer)? {
            BytecodeSerde::LegacyAnalyzed {
                bytecode,
                original_len,
                jump_table,
            } => Ok(Self::BytecodeInner(Arc::new(BytecodeInner {
                kind: BytecodeKind::LegacyAnalyzed,
                bytecode,
                original_len,
                jump_table,
                hash: OnceLock::new(),
            }))),
            BytecodeSerde::Eip7702 { delegated_address } => {
                Ok(Self::new_eip7702(delegated_address))
            }
            BytecodeSerde::Rwasm { rwasm_bytecode } => Ok(Self::new_rwasm(rwasm_bytecode)),
            BytecodeSerde::OwnableAccount {
                owner_address,
                metadata,
            } => Ok(Self::new_ownable_account(owner_address, metadata)),
        }
    }
}
