use fluentbase_types::{Address, B256, Bytes, U256};
use hashbrown::HashMap;
use revm_oiginal as ro;
use ro::primitives as rop;

// impl From<B256> for ro::precompile::B256 {
//     fn from(value: B256) -> Self {
//         todo!()
//     }
// }
pub(crate) fn convert_bytes(v: &Bytes) -> ro::primitives::Bytes {
    ro::primitives::Bytes::from(v.to_vec())
}

pub(crate) fn convert_b256(v: &B256) -> ro::primitives::B256 {
    ro::primitives::B256::from_slice(v.as_slice())
}

pub(crate) fn convert_address(v: &Address) -> ro::primitives::Address {
    ro::primitives::Address::from_slice(v.as_slice())
}

pub(crate) fn convert_hashmap(v: &HashMap<U256, U256>) -> ro::primitives::HashMap<U256, U256> {
    let mut hm: std::collections::HashMap<U256, U256> = ro::primitives::HashMap::new();
    v.iter().for_each(|(k, v)| {
        assert!(hm.insert(k.clone(), v.clone()).is_none())
    });
    hm
}