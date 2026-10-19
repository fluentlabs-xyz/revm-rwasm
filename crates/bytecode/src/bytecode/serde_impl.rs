use super::{Bytecode, BytecodeKind, JumpTable};
use primitives::{Address, Bytes};
use rwasm::RwasmModule;
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
        rwasm_module: RwasmModule,
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
                rwasm_module: inner.module.clone(),
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
                ..
            } => {
                if original_len > bytecode.len() {
                    return Err(serde::de::Error::custom(
                        "original_len is greater than bytecode length",
                    ));
                }
                // Re-analyze from original bytes to ensure padding invariants
                // are satisfied, rather than trusting the serialized form.
                Ok(Self::new_legacy(bytecode.slice(..original_len)))
            }
            BytecodeSerde::Eip7702 { delegated_address } => {
                Ok(Self::new_eip7702(delegated_address))
            }
            BytecodeSerde::Rwasm { rwasm_module } => Ok(Self::new_rwasm(rwasm_module, None)),
            BytecodeSerde::OwnableAccount {
                owner_address,
                metadata,
            } => Ok(Self::new_ownable_account(owner_address, metadata)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_deserialization_rebuilds_padding_and_jump_table() {
        let original = Bytes::from_static(&[0x5b, 0x7f]);
        let untrusted = BytecodeSerde::LegacyAnalyzed {
            bytecode: original.clone(),
            original_len: original.len(),
            jump_table: JumpTable::default(),
        };
        let encoded = serde_json::to_vec(&untrusted).unwrap();
        let decoded: Bytecode = serde_json::from_slice(&encoded).unwrap();
        let expected = Bytecode::new_legacy(original);
        assert_eq!(decoded.bytecode(), expected.bytecode());
        assert_eq!(decoded.legacy_jump_table(), expected.legacy_jump_table());
        assert!(decoded.legacy_jump_table().unwrap().is_valid(0));
        assert!(decoded.bytecode().len() > 33);
    }

    #[test]
    fn legacy_deserialization_rejects_original_length_outside_buffer() {
        let untrusted = BytecodeSerde::LegacyAnalyzed {
            bytecode: Bytes::from_static(&[0x00]),
            original_len: 2,
            jump_table: JumpTable::default(),
        };
        let encoded = serde_json::to_vec(&untrusted).unwrap();
        assert!(serde_json::from_slice::<Bytecode>(&encoded).is_err());
    }
}
